#include <stddef.h>
#include <stdint.h>

// Modify this struct.
struct kvdb_t {
    const char *path;
    int fd;
};

int kvdb_open(struct kvdb_t *db, const char *path);
int kvdb_put(struct kvdb_t *db, const char *key, const char *value);
int kvdb_get(struct kvdb_t *db, const char *key, char *buf, size_t length);
int kvdb_close(struct kvdb_t *db);
