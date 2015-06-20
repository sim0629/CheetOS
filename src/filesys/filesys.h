#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/cache.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Owned by filesys.c */
extern struct lock filesys_mutex;

/* Owned by filesys.c */
extern struct cache fs_cache;

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *path, off_t initial_size);
struct file *filesys_open (const char *path);
struct inode *filesys_open_inode (const char *path);
bool filesys_remove (const char *path);

#endif /* filesys/filesys.h */
