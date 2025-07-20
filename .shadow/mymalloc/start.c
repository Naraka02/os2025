#include <mymalloc.h>

#ifdef FREESTANDING

#define MEM_SIZE 4096

static char memory[MEM_SIZE];

void *vmalloc(void *addr, size_t length) {
    if (length > MEM_SIZE || length == 0) {
        return NULL;
    }
    if (addr == NULL) {
        return memory;
    }
    return NULL;
}

void vmfree(void *addr, size_t length) {
    (void)addr;
    (void)length;
}

void _start() {
}

int main() {
    return 0;
}

#else

#include <sys/mman.h>

void *vmalloc(void *addr, size_t length) {
    // length must be aligned to page size (4096).
    void *result = mmap(addr, length, PROT_READ | PROT_WRITE, 
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED) {
        return NULL;
    }
    return result;
}

void vmfree(void *addr, size_t length) {
    munmap(addr, length);
}

#endif
