.DEFAULT_GOAL=bin/alloc_tracker.so

CFLAGS=-std=c99 -pedantic -Wall -Werror

bin:
	mkdir bin

bin/alloc_tracker.so: obj/alloc_tracker.opic obj/printf.opic | bin
	$(CC) -shared -ldl -lm -pthread $^ -o $@

obj:
	mkdir obj
	mkdir obj/programs

obj/%.opic: %.c | obj
	$(CC) -c $(CFLAGS) -fPIC $^ -o $@

obj/%.o: %.c | obj
	$(CC) -c $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -r bin/ obj/ || true
