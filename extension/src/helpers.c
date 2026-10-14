
#include "postgres.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static int cmp_u32(const void *a, const void *b) {
  uint32 x = *(const uint32 *)a;
  uint32 y = *(const uint32 *)b;
  return x < y ? -1 : x > y;
}

uint32 reserve_id(const char *subdir, const char *ext) {
  char dir[MAXPGPATH];
  snprintf(dir, sizeof(dir), "%s/%s", DataDir, subdir);
  mkdir(dir, 0700);

  for (;;) {
    int cap = 16;
    int n = 0;
    uint32 *ids = palloc(sizeof(uint32) * cap);
    DIR *d = AllocateDir(dir);
    struct dirent *de;

    while ((de = ReadDir(d, dir)) != NULL) {
      char *end;
      unsigned long v = strtoul(de->d_name, &end, 10);
      if (end == de->d_name || *end != '.' || strcmp(end + 1, ext) != 0 ||
          v == 0 || v > PG_UINT32_MAX) {
        continue;
      }
      if (n == cap) {
        cap *= 2;
        ids = repalloc(ids, sizeof(uint32) * cap);
      }
      ids[n++] = (uint32)v;
    }
    FreeDir(d);

    qsort(ids, n, sizeof(uint32), cmp_u32);
    uint32 id = 1;
    for (int i = 0; i < n; i++) {
      if (ids[i] == id) {
        id++;
      } else if (ids[i] > id) {
        break;
      }
    }
    pfree(ids);

    char path[MAXPGPATH];
    snprintf(path, sizeof(path), "%s/%u.%s", dir, id, ext);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
      close(fd);
      return id;
    }
    if (errno != EEXIST) {
      ereport(ERROR, (errmsg("pgr: could not create %s: %m", path)));
    }
  }
}
