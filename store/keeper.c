// Keeper connection for ledger.db (see PLAN.md section 3 and spikes/sqlite).
//
// The installing user may only read the database. A read-only reader can
// open a WAL database only while its -wal and -shm files exist, and SQLite
// deletes them when the last connection closes. The collector therefore
// opens this extra connection first, marks it SQLITE_FCNTL_PERSIST_WAL,
// attaches it to the WAL, and closes it last, so the files survive a clean
// shutdown. It uses the SQLite compiled into moonbit-community/sqlite3.
#include <stdint.h>
#include "moonbit.h"

typedef struct sqlite3 sqlite3;
int sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
int sqlite3_file_control(sqlite3 *, const char *zDbName, int op, void *);
int sqlite3_exec(sqlite3 *, const char *sql, void *cb, void *arg, char **errmsg);
int sqlite3_close(sqlite3 *);
#define SQLITE_OPEN_READWRITE 0x00000002
#define SQLITE_OPEN_CREATE 0x00000004
#define SQLITE_FCNTL_PERSIST_WAL 10

static sqlite3 *g_keeper = 0;

int32_t nw_keeper_open(moonbit_bytes_t path_utf8z) {
  if (g_keeper) return 0;
  int rc = sqlite3_open_v2((const char *)path_utf8z, &g_keeper,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 0);
  if (rc != 0) {
    if (g_keeper) sqlite3_close(g_keeper);
    g_keeper = 0;
    return rc;
  }
  int one = 1;
  rc = sqlite3_file_control(g_keeper, "main", SQLITE_FCNTL_PERSIST_WAL, &one);
  if (rc != 0) return rc;
  return sqlite3_exec(g_keeper,
                      "PRAGMA journal_mode=WAL; SELECT count(*) FROM sqlite_master;", 0, 0, 0);
}

int32_t nw_keeper_close(void) {
  int rc = g_keeper ? sqlite3_close(g_keeper) : 0;
  g_keeper = 0;
  return rc;
}
