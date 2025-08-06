#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <pthread.h>

#define MAX_KEY_LEN 256
#define MAX_VALUE_LEN 1024
#define LOG_ENTRY_SIZE (MAX_KEY_LEN + MAX_VALUE_LEN + sizeof(int) * 2)

typedef struct log_entry {
    int key_len;
    int value_len;
    char key[MAX_KEY_LEN];
    char value[MAX_VALUE_LEN];
    int committed; // 0: not committed, 1: committed
} log_entry_t;

struct kvdb_t {
    const char *path;
    int fd;
    pthread_mutex_t mutex;
};

int kvdb_open(struct kvdb_t *db, const char *path);
int kvdb_put(struct kvdb_t *db, const char *key, const char *value);
int kvdb_get(struct kvdb_t *db, const char *key, char *buf, size_t length);
int kvdb_close(struct kvdb_t *db);
