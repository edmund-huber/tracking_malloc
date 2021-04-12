#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "printf.h"

#define ASSERT(cond) \
    { \
        if (!(cond)) { \
            printf("ASSERT(" #cond ") failed at %s L%i\n", __FILE__, __LINE__); \
            exit(1); \
        } \
    }
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

char *align(char *p, int alignment) {
    uintptr_t off = ((uintptr_t)p) % alignment;
    if (off == 0) {
        return p;
    } else {
        return p + alignment - off;
    }
}

#define ALLOC_ENTRY_MAGIC 0xdeadbeef
typedef struct alloc_entry {
    void *allocation_begin;
    size_t size;
    uint64_t when_allocated;
    struct alloc_entry *prev, *next;
    // Rationale for putting the magic at the end: it seems more likely that a
    // poorly behaving program would corrupt those areas closest to the
    // malloc'ed region.
    uint32_t magic;
} alloc_entry_t;

__thread int this_thread_has_init_mutex = 0;

typedef enum {
    COLD_AND_DARK,
    INITIALIZING,
    ACTIVE,
    PASSTHROUGH
} context_mode_t;

#define N_PREALLOCATIONS 8
#define PREALLOCATION_SIZE 1024
struct {
    pthread_mutex_t mutex_for_init;
    context_mode_t mode;
    struct {
        int is_free;
        char allocation[PREALLOCATION_SIZE];
    } preallocations[N_PREALLOCATIONS];
    void *(*system_malloc)(size_t);
    void (*system_free)(void *);
    // Why separate mutexes: separate threads could race to init(), so we must
    // have a statically-initialized mutex to resolve that. However, the
    // pthreads mutex static initializer, PTHREAD_MUTEX_INITIALIZER, specifies
    // a default (not errorchecking, not recursive) mutex, which isn't what we
    // want for actual operation. There exists
    // PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP in glibc, but that isn't
    // portable..
    pthread_mutex_t mutex;
    uint64_t when_started;
    uint64_t lifetime_allocations;
    alloc_entry_t *head;
    int use_printf_fd;
    int printf_fd;
    size_t printf_written;
} context = {
    .mutex_for_init = PTHREAD_MUTEX_INITIALIZER,
    .use_printf_fd = 0,
    .printf_written = 0,
    .mode = COLD_AND_DARK
};

static void *get_system_fp(char *name) {
    dlerror();
    void *fp = dlsym(RTLD_NEXT, name);
    char *error = dlerror();
    ASSERT(error == NULL);
    ASSERT(fp != NULL);
    return fp;
}

static uint64_t time_in_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * (int64_t)1000000000) + ts.tv_nsec;
}

typedef struct {
    uint64_t lower;
    uint64_t upper;
    uint64_t count;
} stats_bin_t;

#define STATS_N_SIZE_BINS 12
#define STATS_N_AGE_BINS 4
struct {
    stats_bin_t size_bins[STATS_N_SIZE_BINS];
    stats_bin_t age_bins[STATS_N_AGE_BINS];
} stats;

static stats_bin_t *find_bin(stats_bin_t *bins, int bin_count, uint64_t value) {
    for (int i = 0; i < bin_count; i++) {
        if ((value >= bins[i].lower) && ((value < bins[i].upper) || (i == bin_count - 1))) {
            return &bins[i];
        }
    }
    return NULL;
}

static void print_binned_stats(char *type, char *unit, stats_bin_t *bins, int n_bins) {
    uint64_t biggest_bin = 0;
    for (int i = 0; i < n_bins; i++) {
        biggest_bin = MAX(biggest_bin, bins[i].count);
    }
    int total_width = 50;
    double one_hash = biggest_bin / (double)total_width;
    if (one_hash > 1) {
        printf("Current allocations by %s: (# = %i current allocations)\n", type, one_hash);
        for (int i = 0; i < n_bins; i++) {
            stats_bin_t *bin = &bins[i];
            int width = floor(bin->count / (double)one_hash);
            int j = 0;
            for (; j < width; j++) {
                printf("#");
            }
            for (; j < total_width; j++) {
                printf(" ");
            }
            if (i < n_bins - 1) {
                printf(" %i - %i %s, %i allocs\n", bin->lower, bin->upper, unit, bin->count);
            } else {
                printf(" %i + %s, %i allocs\n", bin->lower, unit, bin->count);
            }
        }
    }
    printf("\n");
}

static void *reporting_thread(void *);

static void maybe_init(void) {
    // We need to know if we are INITIALIZING already, because if we are, we
    // don't want to enter the initialization code (below), which we are
    // already executing! I don't see a way to check if we already hold the
    // mutex, except this thread-local variable.
    if (this_thread_has_init_mutex) {
        ASSERT((context.mode == INITIALIZING) || (context.mode == PASSTHROUGH));
    } else {
        ASSERT(pthread_mutex_lock(&context.mutex_for_init) == 0);
        if (context.mode == COLD_AND_DARK) {
            // Establish that we are initializing, so that the following
            // reentrant calls to/from dlsym() know to use the crutch logic for
            // allocation functions.
            context.mode = INITIALIZING;
            this_thread_has_init_mutex = 1;
            for (int i = 0; i < N_PREALLOCATIONS; i++) {
                context.preallocations[i].is_free = 1;
            }

            // NB: gcc's `-pedantic` doesn't allow assignments from "data
            // pointers" to "function pointers":
            // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83584
            // These pointer manipulations are a workaround documented in this
            // POSIX manpage:
            // https://pubs.opengroup.org/onlinepubs/009695399/functions/dlsym.html
            *(void **)(&context.system_malloc) = get_system_fp("malloc");
            *(void **)(&context.system_free) = get_system_fp("free");

            // We should be able to use PASSTHROUGH mode for the rest of
            // initialization.
            context.mode = PASSTHROUGH;
            pthread_mutexattr_t attr;
            ASSERT(pthread_mutexattr_init(&attr) == 0);
            ASSERT(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
            ASSERT(pthread_mutex_init(&context.mutex, &attr) == 0);
            context.when_started = time_in_ns();
            context.lifetime_allocations = 0;
            context.head = NULL;
            char *fn = getenv("TRACKING_MALLOC_FILENAME");
            ASSERT(fn != NULL);
            context.printf_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0666);
            if (context.printf_fd == -1) {
                printf("TRACKING_MALLOC_FILENAME can't be opened\n");
                ASSERT(0);
            }
            context.use_printf_fd = 1;
            context.printf_written = 0;

            // Start up the reporting thread.
            pthread_t thread;
            ASSERT(pthread_create(&thread, NULL, reporting_thread, NULL) == 0);

            // We're done!
            context.mode = ACTIVE;
            this_thread_has_init_mutex = 0;
        }
        ASSERT(pthread_mutex_unlock(&context.mutex_for_init) == 0);
    }
}

static void *reporting_thread(void *_) {
    while (1) {
        unsigned int to_sleep = 5;
        while ((to_sleep = sleep(to_sleep)) != 0);

        maybe_init();
        ASSERT(pthread_mutex_lock(&context.mutex) == 0);

        // Any allocations we do here (asctime, gmtime definitely mallocs at
        // least once) shouldn't count.
        ASSERT(context.mode == ACTIVE);
        context.mode = PASSTHROUGH;

        // Print the stats header with the current UTC datetime.
        time_t t = time(NULL);
        struct tm gmt;
        gmtime_r(&t, &gmt);
        char s[64];
        asctime_r(&gmt, s);
        s[strlen(s) - 1] = '\0';
        printf(">>>>>>>>>>>>>>>> %s <<<<<<<<<<<<<<<<\n", s);

        // Set up the bins.
        uint64_t prev_size_bin_upper = 0;
        for (int i = 0; i < STATS_N_SIZE_BINS; i++) {
            stats.size_bins[i].lower = prev_size_bin_upper;
            stats.size_bins[i].upper = prev_size_bin_upper = pow(2, 2 + i);
            stats.size_bins[i].count = 0;
        }
        prev_size_bin_upper = 0;
        for (int i = 0; i < STATS_N_AGE_BINS; i++) {
            stats.age_bins[i].lower = prev_size_bin_upper;
            stats.age_bins[i].upper = prev_size_bin_upper = pow(10, i);
            stats.age_bins[i].count = 0;
        }

        // Walk through all alloc_entry_t to get stats.
        uint64_t now = time_in_ns();
        uint64_t current_allocations = 0;
        uint64_t currently_allocated_bytes = 0;
        for (alloc_entry_t *p = context.head; p != NULL; p = p->next) {
            current_allocations++;
            currently_allocated_bytes += p->size;

            // Size bins.
            stats_bin_t *bin = find_bin(stats.size_bins, STATS_N_SIZE_BINS, p->size);
            ASSERT(bin != NULL);
            bin->count++;

            // Age bins.
            uint64_t age_in_s = (now - p->when_allocated) / 1e9;
            bin = find_bin(stats.age_bins, STATS_N_AGE_BINS, age_in_s);
            ASSERT(bin != NULL);
            bin->count++;
        }

        printf("Overall stats:\n");
        printf("%i Current allocations\n", current_allocations);
        printf("%i Overall allocations since start\n", context.lifetime_allocations);
        printf("%.2fMiB Current total allocated size\n\n", currently_allocated_bytes / pow(1024, 2));
        print_binned_stats("size", "bytes", stats.size_bins, STATS_N_SIZE_BINS);
        print_binned_stats("age", "sec", stats.age_bins, STATS_N_AGE_BINS);

        // Go back to normal operation now that there's no more danger of malloc.
        context.mode = ACTIVE;

        ASSERT(pthread_mutex_unlock(&context.mutex) == 0);
    }

    ASSERT(0);
    return NULL;
}

// printf needs an implementation of _putchar: we'll print to a file, and
// truncate it when it gets too big.
void _putchar(char c) {
    maybe_init();
    ASSERT(pthread_mutex_lock(&context.mutex) == 0);
    int fd = context.use_printf_fd ? context.printf_fd : STDERR_FILENO;
    while (write(fd, &c, 1) != 1);
    if (++context.printf_written > 1024) {
        ASSERT(ftruncate(context.printf_fd, 0) == 0);
        context.printf_written = 0;
    }
    ASSERT(pthread_mutex_unlock(&context.mutex) == 0);
}

void *malloc_inner(size_t requested_size, int alignment) {
    maybe_init();
    ASSERT(pthread_mutex_lock(&context.mutex) == 0);
    char *p = NULL;
    switch (context.mode) {
    case COLD_AND_DARK:
        ASSERT(0);
        break;

    case INITIALIZING:
        // If we're initializing, we'll return a "preallocated" block.
        for (int i = 0; i < N_PREALLOCATIONS; i++) {
            if (context.preallocations[i].is_free) {
                ASSERT(requested_size <= sizeof(context.preallocations[i].allocation));
                context.preallocations[i].is_free = 0;
                p = context.preallocations[i].allocation;
                break;
            }
        }
        if (p == NULL) {
            printf("no free preallocated block\n");
            ASSERT(0);
        }
        break;

    case ACTIVE:
    case PASSTHROUGH:
        {
            // Use system malloc() to make an allocation big enough to fit the
            // alloc_entry_t plus the requested allocation, at the requested
            // alignment.
            char *allocation = context.system_malloc(alignment - 1 + sizeof(alloc_entry_t) + requested_size);
            p = align(allocation + sizeof(alloc_entry_t), alignment);
            alloc_entry_t *alloc_entry = (alloc_entry_t *)(p - sizeof(alloc_entry_t));

            // Populate this alloc_entry_t ..
            alloc_entry->allocation_begin = allocation;
            alloc_entry->size = requested_size;
            context_mode_t old_mode = context.mode;
            context.mode = PASSTHROUGH;
            alloc_entry->when_allocated = time_in_ns();
            context.mode = old_mode;
            alloc_entry->magic = ALLOC_ENTRY_MAGIC;

            // If we're in PASSTHROUGH mode, we skip accounting.
            alloc_entry->prev = NULL;
            if (context.mode == PASSTHROUGH) {
                alloc_entry->next = NULL;
            } else {
                if (context.head != NULL) {
                    alloc_entry->next = context.head;
                    alloc_entry->next->prev = alloc_entry;
                } else {
                    alloc_entry->next = NULL;
                }
                context.head = alloc_entry;
                context.lifetime_allocations++;
            }
        }
        break;
    }
    ASSERT(pthread_mutex_unlock(&context.mutex) == 0);
    return p;
}

void *malloc(size_t requested_size) {
    return malloc_inner(requested_size, 1);
}

static void check_if_preallocation_or_true_allocation(void *p, int *preallocation_i, alloc_entry_t **alloc_entry) {
    // Check if the region is one of the "preallocated" regions.
    ASSERT(preallocation_i != NULL);
    *preallocation_i = -1;
    for (int i = 0; i < N_PREALLOCATIONS; i++) {
        if (p == context.preallocations[i].allocation) {
            *preallocation_i = i;
            return;
        }
    }

    // Find the alloc_entry_t that we stashed before the malloc'ed region.
    ASSERT(alloc_entry != NULL);
    *alloc_entry = (alloc_entry_t *)((char *)p - sizeof(alloc_entry_t));
    ASSERT((*alloc_entry)->magic == ALLOC_ENTRY_MAGIC);
}

void free(void *p) {
    if (p == NULL) {
        return;
    }

    maybe_init();
    ASSERT(pthread_mutex_lock(&context.mutex) == 0);
    switch (context.mode) {
    case COLD_AND_DARK:
        ASSERT(0);
        break;

    case INITIALIZING:
        // It's not possible to write a correct free() without having
        // context.mutex set up, which isn't the case yet because we are
        // INITIALIZING. So just leak the memory.
        break;

    case ACTIVE:
    case PASSTHROUGH:
        {
            int preallocation_i;
            alloc_entry_t *alloc_entry;
            check_if_preallocation_or_true_allocation(p, &preallocation_i, &alloc_entry);
            if (preallocation_i != -1) {
                // If it's a "preallocated" region, we just mark it free.
                context.preallocations[preallocation_i].is_free = 1;
            } else {
                // Otherwise it was malloc'ed by us, so start by removing its
                // alloc_entry_t from the list of alloc_entry_t.
                if (context.head == alloc_entry) {
                    context.head = alloc_entry->next;
                }
                if (alloc_entry->prev != NULL) {
                    alloc_entry->prev->next = alloc_entry->next;
                }
                if (alloc_entry->next != NULL) {
                    alloc_entry->next->prev = alloc_entry->prev;
                }

                // Run system free() on the entire allocation.
                context.system_free(alloc_entry->allocation_begin);
            }
        }
        break;
    }
    ASSERT(pthread_mutex_unlock(&context.mutex) == 0);
}

void *calloc(size_t n, size_t size) {
    if ((n == 0) || (size == 0)) {
        return NULL;
    }
    void *p = malloc(n * size);
    memset(p, 0, n * size);
    return p;
}

void *realloc(void *p, size_t requested_size) {
    maybe_init();
    ASSERT(pthread_mutex_lock(&context.mutex) == 0);

    void *p2 = NULL;
    if (p != NULL) {
        if (requested_size != 0) {
            // Allocate the new region.
            p2 = malloc(requested_size);

            // Figure out the size of the current allocation.
            int preallocation_i;
            alloc_entry_t *alloc_entry;
            check_if_preallocation_or_true_allocation(p, &preallocation_i, &alloc_entry);
            size_t current_size;
            if (preallocation_i != -1) {
                // If it's a "preallocation", we know the (static) size.
                current_size = PREALLOCATION_SIZE;
            } else {
                current_size = alloc_entry->size;
            }

            // Copy what we can from the old to the new allocation.
            size_t min_size = MIN(current_size, requested_size);
            memcpy(p2, p, min_size);

            free(p);
        } else {
            free(p);
            p2 = NULL;
        }
    } else {
        p2 = malloc(requested_size);
    }

    ASSERT(pthread_mutex_unlock(&context.mutex) == 0);

    return p2;
}

void *reallocarray(void *p, size_t n, size_t size) {
    // Haven't needed to implement this yet!
    ASSERT(0);
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    *memptr = malloc_inner(size, alignment);
    return 0;
}

void *aligned_alloc(size_t alignment, size_t size) {
    // Haven't needed to implement this yet!
    ASSERT(0);
    return NULL;
}

void *valloc(size_t size) {
    // Haven't needed to implement this yet!
    ASSERT(0);
    return NULL;
}

void *memalign(size_t alignment, size_t size) {
    void *p;
    ASSERT(posix_memalign(&p, alignment, size) == 0);
    return p;
}

void *pvalloc(size_t size) {
    // Haven't needed to implement this yet!
    ASSERT(0);
    return NULL;
}
