#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct {
    atomic_int status;
} spinlock_t;

#define LOCKED   1
#define UNLOCKED 0

static inline void spin_lock(spinlock_t *lock) {
    int expected;
    do {
        expected = UNLOCKED;
    } while (!atomic_compare_exchange_strong(&lock->status, &expected, LOCKED));
}

static inline void spin_unlock(spinlock_t *lock) {
    atomic_store_explicit(&lock->status, UNLOCKED, memory_order_release);
}

void *mymalloc(size_t size);
void myfree(void *ptr);

void *vmalloc(void *addr, size_t length);
void vmfree(void *addr, size_t length);
