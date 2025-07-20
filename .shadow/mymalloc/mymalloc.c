#include <mymalloc.h>
#include <sys/mman.h>
#include <pthread.h>

#define ALIGN(size) (((size) + 7) & ~7)
#define MIN_BLOCK_SIZE (sizeof(block_t))
#define PAGE_SIZE 4096
#define NUM_SIZE_CLASSES 8
#define MAX_CACHED_SIZE 512
#define CACHE_SIZE 32

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

typedef struct cached_block {
    struct cached_block *next;
} cached_block_t;

typedef struct thread_cache {
    cached_block_t * size_classes[NUM_SIZE_CLASSES];
    int count[NUM_SIZE_CLASSES];
} thread_cache_t;

static __thread thread_cache_t *tcache = NULL;

static const size_t size_classes[NUM_SIZE_CLASSES] = {
    16, 32, 64, 128, 256, 512, 1024, 2048
};

static pool_t *pools = NULL;
spinlock_t big_lock = {UNLOCKED};

static int get_size_class(size_t size) {
    for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
        if (size <= size_classes[i]) {
            return i;
        }
    }
    return -1;
}

void *allocate_slow_path(size_t size) {
    if (size == 0) {
        return NULL;
    }

    spin_lock(&big_lock);

    size = ALIGN(size + sizeof(block_t));

    for (pool_t *pool = pools; pool; pool = pool->next) {
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
    if (!add_pool(pool_size)) {
        spin_unlock(&big_lock);
        return NULL;
    }
    
    pool_t *new_pool = pools;
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

static thread_cache_t *get_thread_cache() {
    if (!tcache) {
        tcache = (thread_cache_t *)vmalloc(NULL, sizeof(thread_cache_t));
        if (tcache) {
            for (int i = 0; i < NUM_SIZE_CLASSES; i++) {
                tcache->size_classes[i] = NULL;
                tcache->count[i] = 0;
            }
        }
    }
    return tcache;
}

static void *allocate_from_cache(int size_class) {
    thread_cache_t *cache = get_thread_cache();
    if (!cache || !cache->size_classes[size_class]) {
        return NULL;
    }
    
    cached_block_t *block = cache->size_classes[size_class];
    cache->size_classes[size_class] = block->next;
    cache->count[size_class]--;
    
    return block;
}

static void fill_cache(int size_class) {
    size_t alloc_size = size_classes[size_class];
    int batch_size = CACHE_SIZE / 2;
    
    for (int i = 0; i < batch_size; i++) {
        void *ptr = allocate_slow_path(alloc_size);
        if (!ptr) break;
        
        thread_cache_t *cache = get_thread_cache();
        if (cache && cache->count[size_class] < CACHE_SIZE) {
            cached_block_t *block = (cached_block_t *)ptr;
            block->next = cache->size_classes[size_class];
            cache->size_classes[size_class] = block;
            cache->count[size_class]++;
        } else {
            myfree(ptr);
            break;
        }
    }
}

static pool_t *find_pool(void *ptr) {
    for (pool_t *pool = pools; pool; pool = pool->next) {
        if (ptr >= pool->start && ptr < (char *)pool->start + pool->total_size) {
            return pool;
        }
    }
    return NULL;
}

static int add_pool(size_t size) {
    size_t total_size = ((size + sizeof(pool_t) + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    void *mem = vmalloc(NULL, total_size);
    if (!mem) {
        return 0;
    }

    pool_t *pool = (pool_t *)mem;
    pool->start = (char *)mem + ALIGN(sizeof(pool_t));
    pool->total_size = total_size - ALIGN(sizeof(pool_t));
    pool->next = pools;
    pools = pool;

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

    int size_class = get_size_class(size);
    if (size_class >= 0) {
        void *ptr = allocate_from_cache(size_class);
        if (ptr) {
            return ptr;
        }

        fill_cache(size_class);

        ptr = allocate_from_cache(size_class);
        if (ptr) {
            return ptr;
        }
    }

    return allocate_slow_path(size);
}

static int try_cache_free(void *ptr, size_t size) {
    int size_class = get_size_class(size);
    if (size_class < 0) {
        return 0;
    }
    
    thread_cache_t *cache = get_thread_cache();
    if (!cache || cache->count[size_class] >= CACHE_SIZE) {
        return 0;
    }
    
    cached_block_t *block = (cached_block_t *)ptr;
    block->next = cache->size_classes[size_class];
    cache->size_classes[size_class] = block;
    cache->count[size_class]++;
    
    return 1;
}

void myfree(void *ptr) {
    if (!ptr) {
        return;
    }

    block_t *block = (block_t *)((char *)ptr - sizeof(block_t));
    size_t user_size = block->size - sizeof(block_t);

    if (try_cache_free(ptr, user_size)) {
        return;
    }
    
    spin_lock(&big_lock);

    pool_t *pool = find_pool(ptr);
    if (!pool) {
        spin_unlock(&big_lock);
        return;
    }
    
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
