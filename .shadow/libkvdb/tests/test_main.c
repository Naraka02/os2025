#include <testkit.h>
#include <kvdb.h>

SystemTest(test_kvdb_open, ((const char *[]){})) {
    struct kvdb_t db;
    tk_assert(kvdb_open(&db, "/tmp/test.db") == 0, "Must open db");
    tk_assert(kvdb_close(&db) == 0, "Must close db");
}

SystemTest(test_kvdb_put_get, ((const char *[]){})) {
    struct kvdb_t db;
    tk_assert(kvdb_open(&db, "/tmp/test.db") == 0, "Must open db");
    tk_assert(kvdb_put(&db, "key", "value") == 0, "Must put key");
    tk_assert(kvdb_get(&db, "key", NULL, 0) == 0, "Must get key");
    tk_assert(kvdb_close(&db) == 0, "Must close db");
}

int main() {
}
