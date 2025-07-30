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
        void* p = mymalloc(8);
        if (p) {
            myfree(p);
        }
    }
}

SystemTest(concurrent, ((const char *[]){})) {
    pthread_t t1, t2, t3, t4;
    pthread_create(&t1, NULL, (void *(*)(void *))T_malloc, NULL);
    pthread_create(&t2, NULL, (void *(*)(void *))T_malloc, NULL);
    pthread_create(&t3, NULL, (void *(*)(void *))T_malloc, NULL);
    pthread_create(&t4, NULL, (void *(*)(void *))T_malloc, NULL);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t4, NULL);
}

#define N_THREADS 8
#define ALLOC_SIZE 16

typedef struct {
    int thread_id;
    void *ptr;
} thread_data_t;

void *T_alloc_and_check(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    data->ptr = mymalloc(ALLOC_SIZE);
    if (data->ptr) {
        *(int *)(data->ptr) = data->thread_id;
        usleep(100); 
        tk_assert(*(int *)(data->ptr) == data->thread_id, "Memory corruption detected: thread %d", data->thread_id);
    }
    return NULL;
}

SystemTest(double_allocation_test, ((const char *[]){})) {
    pthread_t threads[N_THREADS];
    thread_data_t thread_data[N_THREADS];

    for (int i = 0; i < N_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].ptr = NULL;
        pthread_create(&threads[i], NULL, T_alloc_and_check, &thread_data[i]);
    }

    for (int i = 0; i < N_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < N_THREADS; i++) {
        tk_assert(thread_data[i].ptr != NULL, "Thread %d failed to allocate memory", i);
        for (int j = i + 1; j < N_THREADS; j++) {
            tk_assert(thread_data[i].ptr != thread_data[j].ptr, "Double allocation detected: thread %d and %d have the same pointer", i, j);
        }
    }

    for (int i = 0; i < N_THREADS; i++) {
        if (thread_data[i].ptr) {
            myfree(thread_data[i].ptr);
        }
    }
}
