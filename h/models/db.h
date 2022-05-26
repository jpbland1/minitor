#include "sqlite3.h"

extern sqlite3* minitor_db;

int d_initialize_database();
int d_open_database();
int d_release_memory();
int d_close_database();
