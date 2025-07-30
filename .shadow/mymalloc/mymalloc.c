#include <mymalloc.h>
#include <sys/mman.h>

#ifndef SYS_gettid
#define SYS_gettid 186
#endif
#include <unistd.h>

// Ultra-fast allocation using pre-allocated pools and bitmaps
#define POOL_SIZE (1024 * 1024)  // 1MB pools
#define NUM_POOLS 16
#define BLOCK_SIZES 8
#define MAX_SMALL_SIZE 512

typedef struct {
    void *start;
    size_t size;
    uint64_t bitmap[POOL_SIZE / 64 / 8];  // 1 bit per 8-byte block
    int free_count;
    int total_blocks;
} fast_pool_t;

typedef struct {
    pid_t tid;
    fast_pool_t pools[NUM_POOLS][BLOCK_SIZES];  // pools for different size classes
    int pool_counts[BLOCK_SIZES];
    struct thread_cache *next;
} thread_cache_t;

// Size classes for ultra-fast allocation
static const size_t block_sizes[BLOCK_SIZES] = {8, 16, 32, 64, 128, 256, 512, 1024};

#define ALIGN(size) (((size) + 7) & ~7)
#define PAGE_SIZE 4096

static thread_cache_t *thread_caches = NULL;
spinlock_t big_lock = {UNLOCKED};

// Thread-local storage for instant access
static __thread thread_cache_t *current_cache = NULL;

static inline pid_t gettid(void) {
    pid_t tid;
    __asm__ volatile (
        "syscall"
        : "=a" (tid)
        : "0" (SYS_gettid)
        : "rcx", "r11", "memory"
    );
    return tid;
}

// Find size class for allocation
static inline int get_size_class(size_t size) {
    for (int i = 0; i < BLOCK_SIZES; i++) {
        if (size <= block_sizes[i]) {
            return i;
        }
    }
    return -1;  // Too large for fast allocation
}

// Initialize a fast pool
static void init_fast_pool(fast_pool_t *pool, size_t block_size) {
    pool->size = block_size;
    pool->total_blocks = POOL_SIZE / block_size;
    pool->free_count = pool->total_blocks;
    
    // Allocate the pool
    pool->start = vmalloc(NULL, POOL_SIZE);
    if (!pool->start) {
        pool->total_blocks = 0;
        pool->free_count = 0;
        return;
    }
    
    // Initialize bitmap (all blocks free)
    for (int i = 0; i < POOL_SIZE / 64 / 8; i++) {
        pool->bitmap[i] = 0;  // All bits 0 = all blocks free
    }
}

// Find first free block in bitmap
static int find_free_block(fast_pool_t *pool) {
    if (pool->free_count == 0) return -1;
    
    for (int i = 0; i < POOL_SIZE / 64 / 8; i++) {
        if (pool->bitmap[i] != 0xFFFFFFFFFFFFFFFFULL) {  // Not all bits set
            uint64_t word = pool->bitmap[i];
            for (int j = 0; j < 64; j++) {
                if (!(word & (1ULL << j))) {
                    return i * 64 + j;
                }
            }
        }
    }
    return -1;
}

// Allocate block from fast pool
static void *alloc_from_pool(fast_pool_t *pool) {
    int block_idx = find_free_block(pool);
    if (block_idx == -1) return NULL;
    
    // Mark block as allocated
    int word_idx = block_idx / 64;
    int bit_idx = block_idx % 64;
    pool->bitmap[word_idx] |= (1ULL << bit_idx);
    pool->free_count--;
    
    return (char*)pool->start + block_idx * pool->size;
}

// Free block in fast pool
static void free_in_pool(fast_pool_t *pool, void *ptr) {
    size_t offset = (char*)ptr - (char*)pool->start;
    int block_idx = offset / pool->size;
    
    if (block_idx >= 0 && block_idx < pool->total_blocks) {
        int word_idx = block_idx / 64;
        int bit_idx = block_idx % 64;
        pool->bitmap[word_idx] &= ~(1ULL << bit_idx);
        pool->free_count++;
    }
}

static thread_cache_t *get_thread_cache(void) {
    // Ultra-fast path: use thread-local cache
    if (current_cache) {
        return current_cache;
    }
    
    pid_t current_tid = gettid();
    
    // Check global cache first
    for (thread_cache_t *cache = thread_caches; cache; cache = cache->next) {
        if (cache->tid == current_tid) {
            current_cache = cache;
            return cache;
        }
    }
    
    spin_lock(&big_lock);

    // Double-check after acquiring lock
    for (thread_cache_t *cache = thread_caches; cache; cache = cache->next) {
        if (cache->tid == current_tid) {
            current_cache = cache;
            spin_unlock(&big_lock);
            return cache;
        }
    }
    
    // Create new cache with pre-allocated pools
    thread_cache_t *new_cache = (thread_cache_t *)vmalloc(NULL, sizeof(thread_cache_t));
    if (!new_cache) {
        spin_unlock(&big_lock);
        return NULL;
    }
    
    new_cache->tid = current_tid;
    new_cache->next = thread_caches;
    
    // Initialize all pools for all size classes
    for (int size_class = 0; size_class < BLOCK_SIZES; size_class++) {
        new_cache->pool_counts[size_class] = 1;  // Start with one pool per size class
        init_fast_pool(&new_cache->pools[0][size_class], block_sizes[size_class]);
    }
    
    thread_caches = new_cache;
    current_cache = new_cache;
    spin_unlock(&big_lock);
    return new_cache;
}

// Find which pool contains a pointer
static fast_pool_t *find_pool_for_ptr(thread_cache_t *cache, void *ptr) {
    for (int size_class = 0; size_class < BLOCK_SIZES; size_class++) {
        for (int pool_idx = 0; pool_idx < cache->pool_counts[size_class]; pool_idx++) {
            fast_pool_t *pool = &cache->pools[pool_idx][size_class];
            if (ptr >= pool->start && ptr < (char*)pool->start + POOL_SIZE) {
                return pool;
            }
        }
    }
    return NULL;
}

void *mymalloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    size = ALIGN(size);
    
    // Ultra-fast path for small allocations
    int size_class = get_size_class(size);
    if (size_class >= 0) {
        thread_cache_t *cache = get_thread_cache();
        if (cache) {
            // Try existing pools
            for (int pool_idx = 0; pool_idx < cache->pool_counts[size_class]; pool_idx++) {
                fast_pool_t *pool = &cache->pools[pool_idx][size_class];
                if (pool->free_count > 0) {
                    void *result = alloc_from_pool(pool);
                    if (result) {
                        return result;
                    }
                }
            }
            
            // Add new pool if needed
            if (cache->pool_counts[size_class] < NUM_POOLS) {
                int new_pool_idx = cache->pool_counts[size_class];
                init_fast_pool(&cache->pools[new_pool_idx][size_class], block_sizes[size_class]);
                cache->pool_counts[size_class]++;
                
                fast_pool_t *new_pool = &cache->pools[new_pool_idx][size_class];
                if (new_pool->total_blocks > 0) {
                    return alloc_from_pool(new_pool);
                }
            }
        }
    }
    
    // Fallback for large allocations - use direct vmalloc
    return vmalloc(NULL, size);
}

void myfree(void *ptr) {
    if (!ptr) {
        return;
    }
    
    thread_cache_t *cache = get_thread_cache();
    if (cache) {
        fast_pool_t *pool = find_pool_for_ptr(cache, ptr);
        if (pool) {
            free_in_pool(pool, ptr);
            return;
        }
    }
    
    // Fallback for large allocations
    vmfree(ptr, 0);  // Size unknown, but vmfree should handle it
}
