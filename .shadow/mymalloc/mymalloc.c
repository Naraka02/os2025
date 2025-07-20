#include <mymalloc.h>
#include <sys/mman.h>

#ifndef SYS_gettid
#define SYS_gettid 186
#endif
#include <unistd.h>

typedef struct block {
    size_t size;
    struct block *next;
    int is_free;
} block_t;

typedef struct pool {
    void* start;
    size_t total_size;
    block_t *free_list;
    struct pool *next;
} pool_t;

typedef struct thread_cache {
    pid_t tid;
    pool_t *pools;
    struct thread_cache *next;
} thread_cache_t;

#define ALIGN(size) (((size) + 7) & ~7)
#define MIN_BLOCK_SIZE (sizeof(block_t))
#define PAGE_SIZE 4096
#define MAX_THREAD_CACHE_SIZE (PAGE_SIZE * 16)

static thread_cache_t *thread_caches = NULL;
static pool_t *global_pools = NULL;
spinlock_t big_lock = {UNLOCKED};

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

static thread_cache_t *get_thread_cache(void) {
    pid_t current_tid = gettid();
    
    for (thread_cache_t *cache = thread_caches; cache; cache = cache->next) {
        if (cache->tid == current_tid) {
            return cache;
        }
    }
    
    spin_lock(&big_lock);

    for (thread_cache_t *cache = thread_caches; cache; cache = cache->next) {
        if (cache->tid == current_tid) {
            spin_unlock(&big_lock);
            return cache;
        }
    }
    
    thread_cache_t *new_cache = (thread_cache_t *)vmalloc(NULL, PAGE_SIZE);
    if (!new_cache) {
        spin_unlock(&big_lock);
        return NULL;
    }
    
    new_cache->tid = current_tid;
    new_cache->pools = NULL;
    new_cache->next = thread_caches;
    thread_caches = new_cache;
    
    spin_unlock(&big_lock);
    return new_cache;
}

static pool_t *find_pool_in_cache(thread_cache_t *cache, void *ptr) {
    for (pool_t *pool = cache->pools; pool; pool = pool->next) {
        if ((char *)ptr >= (char *)pool->start && (char *)ptr < (char *)pool->start + pool->total_size) {
            return pool;
        }
    }
    return NULL;
}

static pool_t *find_pool_global(void *ptr) {
    for (pool_t *pool = global_pools; pool; pool = pool->next) {
        if ((char *)ptr >= (char *)pool->start && (char *)ptr < (char *)pool->start + pool->total_size) {
            return pool;
        }
    }
    return NULL;
}

static int add_pool_to_cache(thread_cache_t *cache, size_t size) {
    size_t total_size = ((size + sizeof(pool_t) + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    void *mem = vmalloc(NULL, total_size);
    if (!mem) {
        return 0;
    }

    pool_t *pool = (pool_t *)mem;
    pool->start = (char *)mem + ALIGN(sizeof(pool_t));
    pool->total_size = total_size - ALIGN(sizeof(pool_t));
    pool->next = cache->pools;
    cache->pools = pool;

    block_t *block = (block_t *)pool->start;
    block->size = pool->total_size;
    block->next = NULL;
    block->is_free = 1;
    pool->free_list = block;

    return 1;
}

static int add_pool_global(size_t size) {
    size_t total_size = ((size + sizeof(pool_t) + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    void *mem = vmalloc(NULL, total_size);
    if (!mem) {
        return 0;
    }

    pool_t *pool = (pool_t *)mem;
    pool->start = (char *)mem + ALIGN(sizeof(pool_t));
    pool->total_size = total_size - ALIGN(sizeof(pool_t));
    pool->next = global_pools;
    global_pools = pool;

    block_t *block = (block_t *)pool->start;
    block->size = pool->total_size;
    block->next = NULL;
    block->is_free = 1;
    pool->free_list = block;

    return 1;
}

void *mymalloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    size = ALIGN(size + sizeof(block_t));
    
    if (size <= MAX_THREAD_CACHE_SIZE) {
        thread_cache_t *cache = get_thread_cache();
        if (cache) {
            for (pool_t *pool = cache->pools; pool; pool = pool->next) {
                block_t **current = &pool->free_list;

                while (*current) {
                    block_t *block = *current;

                    if (block->is_free && block->size >= size) {
                        if (block->size >= size + MIN_BLOCK_SIZE + 32) {
                            block_t *new_block = (block_t *)((char *)block + size);
                            new_block->size = block->size - size;
                            new_block->next = block->next;
                            new_block->is_free = 1;

                            block->size = size;
                            block->next = new_block;
                        }

                        *current = block->next;
                        block->is_free = 0;
                        block->next = NULL;

                        return (char *)block + sizeof(block_t);
                    }
                    current = &block->next;
                }
            }

            size_t pool_size = size > PAGE_SIZE ? size * 2 : PAGE_SIZE * 2;
            if (add_pool_to_cache(cache, pool_size)) {
                pool_t *new_pool = cache->pools;
                if (new_pool && new_pool->free_list && new_pool->free_list->size >= size) {
                    block_t *block = new_pool->free_list;
                    
                    if (block->size >= size + MIN_BLOCK_SIZE + 32) {
                        block_t *new_block = (block_t*)((char*)block + size);
                        new_block->size = block->size - size;
                        new_block->next = block->next;
                        new_block->is_free = 1;
                        
                        block->size = size;
                        new_pool->free_list = new_block;
                    } else {
                        new_pool->free_list = block->next;
                    }
                    
                    block->is_free = 0;
                    block->next = NULL;
                    
                    return (char*)block + sizeof(block_t);
                }
            }
        }
    }

    // Slow path
    spin_lock(&big_lock);

    for (pool_t *pool = global_pools; pool; pool = pool->next) {
        block_t **current = &pool->free_list;

        while(*current) {
            block_t *block = *current;

            if (block->is_free && block->size >= size) {
                if (block->size >= size + MIN_BLOCK_SIZE + 32) {
                    block_t *new_block = (block_t *)((char *)block + size);
                    new_block->size = block->size - size;
                    new_block->next = block->next;
                    new_block->is_free = 1;

                    block->size = size;
                    block->next = new_block;
                }

                *current = block->next;
                block->is_free = 0;
                block->next = NULL;

                spin_unlock(&big_lock);
                return (char *)block + sizeof(block_t);
            }
            current = &block->next;
        }
    }

    size_t pool_size = size > PAGE_SIZE ? size * 2: PAGE_SIZE * 4;
    if (!add_pool_global(pool_size)) {
        spin_unlock(&big_lock);
        return NULL;
    }
    
    pool_t *new_pool = global_pools;
    if (new_pool && new_pool->free_list && new_pool->free_list->size >= size) {
        block_t *block = new_pool->free_list;
        
        if (block->size >= size + MIN_BLOCK_SIZE + 32) {
            block_t *new_block = (block_t*)((char*)block + size);
            new_block->size = block->size - size;
            new_block->next = block->next;
            new_block->is_free = 1;
            
            block->size = size;
            new_pool->free_list = new_block;
        } else {
            new_pool->free_list = block->next;
        }
        
        block->is_free = 0;
        block->next = NULL;
        
        spin_unlock(&big_lock);
        return (char*)block + sizeof(block_t);
    }
    
    spin_unlock(&big_lock);
    return NULL;
}

void myfree(void *ptr) {
    if (!ptr) {
        return;
    }
    
    thread_cache_t *cache = get_thread_cache();
    if (cache) {
        pool_t *pool = find_pool_in_cache(cache, ptr);
        if (pool) {
            block_t *block = (block_t*)((char*)ptr - sizeof(block_t));
            if (block->is_free) {
                return;
            }
            
            block->is_free = 1;
            
            block_t **current = &pool->free_list;
            block_t *prev = NULL;
            
            while (*current && *current < block) {
                prev = *current;
                current = &(*current)->next;
            }

            block->next = *current;
            *current = block;
            
            if (block->next && (char*)block + block->size == (char*)block->next) {
                block_t *next = block->next;
                block->size += next->size;
                block->next = next->next;
            }
            
            if (prev && (char*)prev + prev->size == (char*)block) {
                prev->size += block->size;
                prev->next = block->next;
            }
            
            return;
        }
    }
    
    // slow path
    spin_lock(&big_lock);

    pool_t *pool = find_pool_global(ptr);
    if (!pool) {
        spin_unlock(&big_lock);
        return;
    }
    
    block_t *block = (block_t*)((char*)ptr - sizeof(block_t));
    if (block->is_free) {
        spin_unlock(&big_lock);
        return;
    }
    
    block->is_free = 1;
    
    block_t **current = &pool->free_list;
    block_t *prev = NULL;
    
    while (*current && *current < block) {
        prev = *current;
        current = &(*current)->next;
    }

    block->next = *current;
    *current = block;
    
    if (block->next && (char*)block + block->size == (char*)block->next) {
        block_t *next = block->next;
        block->size += next->size;
        block->next = next->next;
    }
    
    if (prev && (char*)prev + prev->size == (char*)block) {
        prev->size += block->size;
        prev->next = block->next;
    }
    
    spin_unlock(&big_lock);
}
