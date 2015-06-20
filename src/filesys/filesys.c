#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/synch.h"
#include "threads/thread.h"

struct lock filesys_mutex;

struct cache fs_cache;

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

static const char *extract_name (const char *);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  lock_init (&filesys_mutex);

  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  if (cache_init (&fs_cache, fs_device) == false)
    PANIC ("Can not initialize file system cache.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_deinit (&fs_cache);
  free_map_close ();
}

/* Creates a file located at PATH with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file located at PATH already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *path, off_t initial_size)
{
  block_sector_t inode_sector = 0;
  struct dir *dir = NULL;
  const char *name = NULL;
  bool success = false;

  name = extract_name (path);
  if (name[0] == '\0')
    return false;

  if (!dir_resolve (thread_current ()->cd, path, &dir))
    return false;
  ASSERT (dir != NULL);

  success = (free_map_allocate (1, &inode_sector)
          && inode_create (inode_sector, initial_size)
          && dir_add (dir, name, inode_sector, false));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

struct file *
filesys_open (const char *path)
{
  return file_open (filesys_open_inode (path));
}

/* Opens the inode with the given PATH.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no inode is located at PATH,
   or if an internal memory allocation fails. */
struct inode *
filesys_open_inode (const char *path)
{
  struct dir *dir = NULL;
  struct inode *inode = NULL;
  const char *name;

  if (!dir_resolve (thread_current ()->cd, path, &dir))
    return false;
  ASSERT (dir != NULL);

  name = extract_name (path);

  if (name[0] == '\0')
    inode = dir_get_inode (dir);
  else
    dir_lookup (dir, name, &inode);

  dir_close (dir);
  return inode;
}

/* Deletes the file or dir located at PATH.
   Returns true if successful, false on failure.
   Fails if no entry is located at PATH,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *path)
{
  struct dir *dir = NULL;
  const char *name;
  bool success = false;

  if (!dir_resolve (thread_current ()->cd, path, &dir))
    return false;
  ASSERT (dir != NULL);

  name = extract_name (path);

  if (name[0] == '\0')
    {
      // TODO: dealing with trailing PATH_DELIM
      ASSERT (false);
    }
  else
    {
      success = dir_remove (dir, name);
    }
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/* Extract file name from path. */
static const char *
extract_name (const char *path)
{
  const char *name = NULL;

  name = strrchr (path, PATH_DELIM);
  if (name == NULL)
    return path;

  return ++name;
}
