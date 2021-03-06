#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
    bool is_directory;
  };

static bool is_empty (const struct dir *);

static inline bool
is_special (const char *name)
{
  return strcmp (name, ".") == 0
      || strcmp (name, "..") == 0;
}

/* Creates a directory in the given SECTOR.
   Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, block_sector_t parent)
{
  struct dir *dir;

  if (!inode_create (sector, 0))
    return false;

  dir = dir_open (inode_open (sector));
  if (dir == NULL)
    return false;

  if (!dir_add (dir, ".", sector, true))
    return false;
  if (!dir_add (dir, "..", parent, true))
    return false;

  dir_close (dir);
  return true;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (const struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode, bool *is_directory)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    {
      if (is_directory != NULL)
        *is_directory = e.is_directory;
      *inode = inode_open (e.inode_sector);
    }
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector,
         bool is_directory)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  e.is_directory = is_directory;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (is_special (name))
    return false;

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Check emptiness for diretory. */
  if (e.is_directory)
    {
      struct dir *dir = dir_open (inode);
      if (!is_empty (dir))
        {
          dir_close (dir);
          return false;
        }
    }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use && !is_special(e.name))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}

/* Resolve relative/absolute path from current directory. */
bool
dir_resolve (const struct dir *cd, const char *path, struct dir **resolved,
             char *filename)
{
  struct dir *dir;
  struct dir_entry entry;
  const char *curr, *next;
  char name[NAME_MAX + 1];
  char *dir_path = NULL;

  if (path[0] == '\0')
    return false;

  if (filename == NULL)
    {
      size_t path_len = strlen (path);
      dir_path = malloc ((path_len + 2) * sizeof (char));
      strlcpy (dir_path, path, path_len + 1);
      dir_path[path_len] = PATH_DELIM;
      dir_path[path_len + 1] = '\0';
      path = dir_path;
    }

  if (path[0] == PATH_DELIM)
    {
      curr = path + 1;
      dir = dir_open_root ();
    }
  else
    {
      curr = path;
      if (cd == NULL)
        dir = dir_open_root ();
      else
        dir = dir_reopen (cd);
    }

  if (dir == NULL)
    {
      if (dir_path != NULL)
        free (dir_path);
      return false;
    }

  while (true)
    {
      next = strchr(curr, PATH_DELIM);
      if (next == NULL)
        {
          if (strlen (curr) > NAME_MAX)
            goto fail;
          *resolved = dir;
          if (filename != NULL)
            strlcpy (filename, curr, NAME_MAX + 1);
          if (dir_path != NULL)
            free (dir_path);
          return true;
        }
      if (next - curr > NAME_MAX)
        goto fail;
      else if (next - curr > 0)
        {
          strlcpy (name, curr, next - curr + 1);

          if (!lookup (dir, name, &entry, NULL))
            goto fail;
          if (!entry.is_directory)
            goto fail;

          dir_close (dir);
          dir = dir_open (inode_open (entry.inode_sector));
          if (dir == NULL)
            {
              if (dir_path != NULL)
                free (dir_path);
              return false;
            }
        }
      curr = next + 1;
    }

fail:
  dir_close (dir);
  if (dir_path != NULL)
    free (dir_path);
  return false;
}

/* Remove given DIR from its parent. */
bool
dir_remove_self (const struct dir *dir)
{
  struct dir *parent_dir;
  struct dir_entry e;
  block_sector_t sector = inode_get_sector (dir->inode);
  bool success = false;

  if (!dir_resolve (dir, "..", &parent_dir, NULL))
    return false;

  while (inode_read_at (parent_dir->inode, &e, sizeof e, parent_dir->pos)
    == sizeof e)
    {
      parent_dir->pos += sizeof e;
      if (e.in_use && e.inode_sector == sector)
        {
          success = dir_remove (parent_dir, e.name);
          goto done;
        }
    }

done:
  dir_close (parent_dir);
  return success;
}

/* Returns if dir is empty or not. */
static bool
is_empty (const struct dir *dir)
{
  struct dir_entry e;
  size_t ofs;
  size_t count = 0;

  ASSERT (dir != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use)
      {
        count++;
        if (count > 2)
          return false;
      }
  return true;
}
