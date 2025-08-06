#include <kvdb.h>

static int recover_database(struct kvdb_t *db) {
    lseek(db->fd, 0, SEEK_SET);
    log_entry_t entry;
    
    while (read(db->fd, &entry, sizeof(log_entry_t)) == sizeof(log_entry_t)) {
        if (entry.committed == 0) {
            pthread_mutex_lock(&db->mutex);
            off_t pos = lseek(db->fd, -sizeof(log_entry_t), SEEK_CUR);
            entry.committed = 1;
            lseek(db->fd, pos, SEEK_SET);
            write(db->fd, &entry, sizeof(log_entry_t));
            fsync(db->fd);
            pthread_mutex_unlock(&db->mutex);
        }
    }
    return 0;
}

int kvdb_open(struct kvdb_t *db, const char *path) {
    if (!db || !path) return -1;
    
    db->fd = open(path, O_RDWR | O_CREAT, 0666);
    if (db->fd < 0) return -1;

    db->path = strdup(path);

    pthread_mutex_init(&db->mutex, NULL);

    if (flock(db->fd, LOCK_EX) == -1) {
        close(db->fd);
        return -1;
    }

    recover_database(db);

    return 0;
}

int kvdb_put(struct kvdb_t *db, const char *key, const char *value) {
    if (!db || !key || !value) return -1;

    pthread_mutex_lock(&db->mutex);

    log_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    entry.key_len = strlen(key);
    entry.value_len = strlen(value);
    strncpy(entry.key, key, MAX_KEY_LEN - 1);
    strncpy(entry.value, value, MAX_VALUE_LEN - 1);
    entry.committed = 0;

    lseek(db->fd, 0, SEEK_END);
    if (write(db->fd, &entry, sizeof(entry)) != sizeof(entry)) {
        pthread_mutex_unlock(&db->mutex);
        return -1;
    }

    if (fsync(db->fd) == -1) {
        pthread_mutex_unlock(&db->mutex);
        return -1;
    }

    entry.committed = 1;
    lseek(db->fd, -sizeof(entry), SEEK_END);
    if (write(db->fd, &entry, sizeof(entry)) != sizeof(entry)) {
        pthread_mutex_unlock(&db->mutex);
        return -1;
    }

    fsync(db->fd);
    
    pthread_mutex_unlock(&db->mutex);
    return 0;
}

int kvdb_get(struct kvdb_t *db, const char *key, char *buf, size_t length) {
    if (!db || !key || !buf) return -1;

    pthread_mutex_lock(&db->mutex);

    off_t pos = lseek(db->fd, 0, SEEK_END);
    log_entry_t entry;

    while (pos >= sizeof(log_entry_t)) {
        pos -= sizeof(log_entry_t);
        lseek(db->fd, pos, SEEK_SET);

        if (read(db->fd, &entry, sizeof(entry)) != sizeof(entry)) {
            break;
        }

        if (entry.committed == 1 && strcmp(entry.key, key) == 0) {
            size_t copy_len = (entry.value_len < length - 1) ? entry.value_len : length - 1;
            strncpy(buf, entry.value, copy_len);
            buf[copy_len] = '\0';

            pthread_mutex_unlock(&db->mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&db->mutex);
    return -1;
}

int kvdb_close(struct kvdb_t *db) {
    if (!db) return -1;
    
    pthread_mutex_lock(&db->mutex);
    
    flock(db->fd, LOCK_UN);
    
    close(db->fd);
    
    pthread_mutex_unlock(&db->mutex);
    pthread_mutex_destroy(&db->mutex);
    
    return 0;
}
