#include <mymalloc.h>

spinlock_t big_lock;

// We don't need this malloc_count. You can remove it.
long malloc_count;

void *mymalloc(size_t size) {
    spin_lock(&big_lock);
    malloc_count++;
    spin_unlock(&big_lock);

    return NULL;
}

void myfree(void *ptr) {
}
