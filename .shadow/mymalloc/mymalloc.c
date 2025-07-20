#include <mymalloc.h>
#include <sys/mman.h>

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

#define ALIGN(size) (((size) + 7) & ~7)
#define MIN_BLOCK_SIZE (sizeof(block_t))
#define PAGE_SIZE 4096

static pool_t *pools = NULL;
spinlock_t big_lock = {UNLOCKED};

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

void myfree(void *ptr) {
    if (!ptr) {
        return;
    }
    
    spin_lock(&big_lock);

    pool_t *pool = find_pool(ptr);
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
