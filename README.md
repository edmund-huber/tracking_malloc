This library provides `malloc`/`free`/`calloc`/`realloc` (and `posix_memalign`
and and and..)  functions which track how many allocations there are, their
sizes, their age, etc. The library prints out statistics about extant
allocations every 5 seconds.

# Background

Hooking `malloc` through LD_PRELOAD is very tricky.

Every approach I've seen involves calling `dlsym` from your `malloc`:
<https://stackoverflow.com/a/6083624>. Unfortunately, this code won't work as
written on all systems because `dlsym` can itself call `malloc` -- on my
system, it always does.

**Requirement 1:** you must provide a crutch `malloc`.

Another aspect to consider is when to do your library initialization (including
calling `dlsym`).

Some approaches suggest installing a library init function (either using the
`-init` ld option, or gcc's `__attribute__((constructor))`. Since it runs
first, you can do all your initialization there, before any thread in the
executable starts! .. Unfortunately, there is nothing guaranteeing that your
library's init will be called before the init of any other dependency of the
executable: <https://bugzilla.redhat.com/show_bug.cgi?id=954113>. So this
approach won't work all of the time. On my system, running `irssi` reliably
breaks this approach.

**Requirement 2:** in the absence of a guaranteed way to run your
initialization code before any other code that could run `malloc`, you must
instead attempt initialization from every function you hook (which may be
called from any thread).

# Some design notes

This library spends its time in one of four states:

It starts in **COLD_AND_DARK**. When any of the hooked functions is called, the
library will call maybe_init(). If the library hasn't been initialized yet, the
state will become INITIALIZING.

While **INITIALIZING**, all allocations will be served out of a finite pool of
statically defined allocations. The size of the pool is tuned to be "enough"
for the initialization phase. This is the "crutch" allocator as discussed in
Requirement 1.

When initialization is done the library enters **ACTIVE** mode. It will spend
most of its time in this mode. In this mode, the hooked functions ultimately
resolve to calls to system `malloc`/`free`, and stats about active allocations
are kept.

When the library needs to call `malloc` (either directly or through
a function that itself calls `malloc`), then it will put itself in **PASSTHROUGH**
mode. In this mode, allocation operations go directly to the underlying
`malloc`/`free`/etc. This is done for two reasons:
1) We only want to be tracking the allocation activity of the target program.
2) We want to avoid potential issues of infinite recursion.

This library uses <https://github.com/mpaland/printf>, which provides
allocation-free `printf`.

# How it's tested

All tests have been done on this machine (`uname -a` output): `Linux thripper
4.19.0-6-amd64 #1 SMP Debian 4.19.67-2 (2019-08-28) x86_64 GNU/Linux`.

The following programs work fine:
* python (2.7.16, 3.7.3)
* tree
* mplayer

So for example to try out python, do:
```
make && TRACKING_MALLOC_FILENAME=log LD_PRELOAD=./bin/alloc_tracker.so python
```

In another terminal, follow the log (it'll truncate every so often, no need to
log-rotate it):
```
tail -f log
```
