#define _GNU_SOURCE
#include <dlfcn.h>
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

void _putchar(char c) {
    write(STDERR_FILENO, &c, 1);
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

// The pthreads API doesn't give you a way to figure out if you are the holder
// of a lock.
__thread int this_thread_has_init_mutex = 0;

#define N_PREALLOCATIONS 8
#define PREALLOCATION_SIZE 1024
struct {
    // Why separate mutexes: separate threads could race to init(), so we must
    // have a statically-initialized mutex to resolve that. However, pthreads
    // do not provide an initializer for a recursive mutex, which is what we
    // will want for actual operation.
    pthread_mutex_t mutex_for_init;
    pthread_mutex_t mutex;
    enum {
        COLD_AND_DARK,
        INITIALIZING,
        ACTIVE,
        PASSTHROUGH
    } mode;
    struct {
        int is_free;
        char allocation[PREALLOCATION_SIZE];
    } preallocations[N_PREALLOCATIONS];
    void *(*system_malloc)(size_t);
    void (*system_free)(void *);
    uint64_t when_started;
    uint64_t lifetime_allocations;
    alloc_entry_t *head;
} context = {
    .mutex_for_init = PTHREAD_MUTEX_INITIALIZER,
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

static void maybe_init(void) {
    if (!this_thread_has_init_mutex) {
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

            // We're done!
            context.mode = ACTIVE;
            this_thread_has_init_mutex = 0;
        }
        ASSERT(pthread_mutex_unlock(&context.mutex_for_init) == 0);
    }
}

typedef struct {
    uint64_t lower;
    uint64_t upper;
    uint64_t count;
} stats_bin_t;

#define STATS_N_SIZE_BINS 12
#define STATS_N_AGE_BINS 4
struct {
    uint64_t when_last_printed;
    stats_bin_t size_bins[STATS_N_SIZE_BINS];
    stats_bin_t age_bins[STATS_N_AGE_BINS];
} stats = {
    .when_last_printed = 0
};

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

static void maybe_print_stats(void) {
    ASSERT(pthread_mutex_lock(&context.mutex) == 0);

    // It only makes sense to print stats while ACTIVE.
    if (context.mode != ACTIVE) {
        ASSERT(pthread_mutex_unlock(&context.mutex) == 0);
        return;
    }

    // Any allocations we do here (asctime, gmtime definitely malloc at least
    // once) shouldn't count.
    context.mode = PASSTHROUGH;

    // Only print stats at most every 5 seconds.
    uint64_t now = time_in_ns();
    if (now - stats.when_last_printed < 5e9) {
        ASSERT(pthread_mutex_unlock(&context.mutex) == 0);
        return;
    }
    stats.when_last_printed = now;

    // Print the stats header with the current UTC datetime.
    time_t t = time(NULL);
    char *s = asctime(gmtime(&t));
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
        maybe_print_stats();
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
            context.mode = PASSTHROUGH;
            alloc_entry->when_allocated = time_in_ns();
            context.mode = ACTIVE;
            alloc_entry->magic = ALLOC_ENTRY_MAGIC;

            // .. and if we aren't in PASSTHROUGH mode, insert it in the list
            // of alloc_entry_t.
            alloc_entry->prev = NULL;
            if (context.mode != PASSTHROUGH) {
                if (context.head != NULL) {
                    alloc_entry->next = context.head;
                    alloc_entry->next->prev = alloc_entry;
                } else {
                    alloc_entry->next = NULL;
                }
                context.head = alloc_entry;
            } else {
                alloc_entry->next = NULL;
            }

            context.lifetime_allocations++;
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
    maybe_init();

    if (p == NULL) {
        return;
    }

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
        maybe_print_stats();
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
