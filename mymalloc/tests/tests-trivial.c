// This is just a demonstration of how to write test cases.
// Write good test cases by yourself ;)

#include <testkit.h>
#include <pthread.h>
#include <mymalloc.h>

SystemTest(trivial, ((const char *[]){})) {
    int *p1 = mymalloc(4);
    tk_assert(p1 != NULL, "malloc should not return NULL");
    *p1 = 1024;
    
    int *p2 = mymalloc(4);
    tk_assert(p2 != NULL, "malloc should not return NULL");
    *p2 = 2048;

    tk_assert(p1 != p2, "malloc should return different pointers");
    tk_assert(*p1 * 2 == *p2, "value check should pass");

    myfree(p1);
    myfree(p2);
}

SystemTest(vmalloc, ((const char *[]){})) {
    void *p1 = vmalloc(NULL, 4096);
    tk_assert(p1 != NULL, "vmalloc should not return NULL");
    tk_assert((uintptr_t)p1 % 4096 == 0, "vmalloc should return page-aligned address");

    void *p2 = vmalloc(NULL, 8192);
    tk_assert(p2 != NULL, "vmalloc should not return NULL");
    tk_assert((uintptr_t)p2 % 4096 == 0, "vmalloc should return page-aligned address");
    tk_assert(p1 != p2, "vmalloc should return different pointers");

    vmfree(p1, 4096);
    vmfree(p2, 8192);
}

#define N 100000
void T_malloc() {
    for (int i = 0; i < N; i++) {
        mymalloc(0);
    }
}

SystemTest(concurrent, ((const char *[]){})) {
    // We don't need this malloc_count; you can safely remove this test case.
    extern long malloc_count;
    pthread_t t1, t2, t3, t4;

    pthread_create(&t1, NULL, (void *(*)(void *))T_malloc, NULL);
    pthread_create(&t2, NULL, (void *(*)(void *))T_malloc, NULL);
    pthread_create(&t3, NULL, (void *(*)(void *))T_malloc, NULL);
    pthread_create(&t4, NULL, (void *(*)(void *))T_malloc, NULL);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t4, NULL);

    tk_assert(malloc_count == 4 * N, "malloc_count should be 4N");
}
