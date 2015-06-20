#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Block count supporting by an inode */
#define INODE_DIRECT    12
#define INODE_INDIRECT   1
#define INODE_INDIRECT2  1

/* Block sector size in entry counts */
#define BLOCK_SECTOR_ENTRY_SIZE (BLOCK_SECTOR_SIZE / sizeof (block_sector_t))

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */

    size_t block_count;                 /* Total number of blocks in it. */
    block_sector_t direct[INODE_DIRECT];
    block_sector_t indirect[INODE_INDIRECT];
    block_sector_t indirect2[INODE_INDIRECT2];

    uint32_t unused[BLOCK_SECTOR_ENTRY_SIZE
      - (3 + INODE_DIRECT + INODE_INDIRECT + INODE_INDIRECT2)];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Prototypes */
static block_sector_t get_sector_entry (block_sector_t, off_t);
static void set_sector_entry (block_sector_t, off_t, block_sector_t);
static void zero_fill (block_sector_t);
static bool allocate_blocks (struct inode_disk *, size_t);
static void free_blocks (struct inode_disk *);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  size_t sector_pos, idx, ofs;
  block_sector_t indirect2_sector, indirect_sector, direct_sector;

  // error check
  ASSERT (inode != NULL);
  if (pos >= inode->data.length)
    return -1;

  // direct block
  sector_pos = pos / BLOCK_SECTOR_SIZE;
  if (sector_pos < INODE_DIRECT)
    {
      direct_sector = inode->data.direct[sector_pos];
      return direct_sector;
    }

  // indirect block
  sector_pos -= INODE_DIRECT;
  if (sector_pos < INODE_INDIRECT * BLOCK_SECTOR_ENTRY_SIZE)
    {
      idx = sector_pos / BLOCK_SECTOR_ENTRY_SIZE;
      ofs = sector_pos % BLOCK_SECTOR_ENTRY_SIZE;
      indirect_sector = inode->data.indirect[idx];
      direct_sector = get_sector_entry (indirect_sector, ofs);
      return direct_sector;
    }

  // indirect2 block
  sector_pos -= INODE_INDIRECT * BLOCK_SECTOR_ENTRY_SIZE;
  idx = sector_pos / BLOCK_SECTOR_ENTRY_SIZE / BLOCK_SECTOR_ENTRY_SIZE;
  ofs = sector_pos / BLOCK_SECTOR_ENTRY_SIZE % BLOCK_SECTOR_ENTRY_SIZE;
  indirect2_sector = inode->data.indirect2[idx];
  indirect_sector = get_sector_entry (indirect2_sector, ofs);
  ofs = sector_pos % BLOCK_SECTOR_ENTRY_SIZE;
  direct_sector = get_sector_entry (indirect_sector, ofs);
  return direct_sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode;
  bool success;
  size_t sectors = bytes_to_sectors (length);

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;

  disk_inode->length = length;
  disk_inode->magic = INODE_MAGIC;
  disk_inode->block_count = 0;
  success = allocate_blocks (disk_inode, sectors);
  if (success)
    cache_write (&fs_cache, sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
  else // fail to allocate blocks
    free_blocks (disk_inode);
  free (disk_inode);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (&fs_cache, inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          free_blocks (&inode->data);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read (&fs_cache, sector_idx, buffer + bytes_read, sector_ofs,
                  chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   A write at end of file would extend the inode. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  /* Extend file if needed. */
  if (inode->data.length < offset + size)
    {
      off_t length = offset + size;
      size_t sectors = bytes_to_sectors (length);
      if (!allocate_blocks (&inode->data, sectors))
        return 0;
      inode->data.length = length;
      cache_write (&fs_cache, inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
    }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_write (&fs_cache, sector_idx, buffer + bytes_written, sector_ofs,
                   chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/* Returns the sector of INODE */
block_sector_t
inode_get_sector (const struct inode *inode)
{
  return inode->sector;
}

/* Get sector entry. */
static block_sector_t
get_sector_entry (block_sector_t sector, off_t idx)
{
  block_sector_t entry;
  cache_read (&fs_cache, sector, &entry,
              idx * sizeof (block_sector_t), sizeof (block_sector_t));
  return entry;
}

/* Set sector entry. */
static void
set_sector_entry (block_sector_t sector, off_t idx, block_sector_t entry)
{
  cache_write (&fs_cache, sector, &entry,
               idx * sizeof (block_sector_t), sizeof (block_sector_t));
}

/* Write zeros to a sector. */
static void
zero_fill (block_sector_t sector)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  cache_write (&fs_cache, sector, zeros, 0, BLOCK_SECTOR_SIZE);
}

/* Allocate blocks to an inode or extend an inode. */
static bool
allocate_blocks (struct inode_disk *disk_inode, size_t sectors)
{
  block_sector_t sector;
  size_t index = 0;
  size_t i, j, k;

  if (sectors == 0)
    return true;

  for (i = 0; i < INODE_DIRECT; i++)
    {
      if (index >= disk_inode->block_count)
        {
          if (!free_map_allocate (1, &sector))
            return false;
          zero_fill (sector);
          disk_inode->direct[i] = sector;
          disk_inode->block_count++;
        }
      index++;
      if (index >= sectors)
        return true;
    }

  for (i = 0; i < INODE_INDIRECT; i++)
    {
      if (index >= disk_inode->block_count)
        {
          if (!free_map_allocate (1, &sector))
            return false;
          zero_fill (sector);
          disk_inode->indirect[i] = sector;
        }
      for (j = 0; j < BLOCK_SECTOR_ENTRY_SIZE; j++)
        {
          if (index >= disk_inode->block_count)
            {
              if (!free_map_allocate (1, &sector))
                return false;
              zero_fill (sector);
              set_sector_entry (disk_inode->indirect[i], j, sector);
              disk_inode->block_count++;
            }
          index++;
          if (index >= sectors)
            return true;
        }
    }

  for (i = 0; i < INODE_INDIRECT2; i++)
    {
      if (index >= disk_inode->block_count)
        {
          if (!free_map_allocate (1, &sector))
            return false;
          zero_fill (sector);
          disk_inode->indirect2[i] = sector;
        }
      for (j = 0; j < BLOCK_SECTOR_ENTRY_SIZE; j++)
        {
          if (index >= disk_inode->block_count)
            {
              if (!free_map_allocate (1, &sector))
                return false;
              zero_fill (sector);
              set_sector_entry (disk_inode->indirect2[i], j, sector);
              disk_inode->indirect2[i] = sector;
            }
          for (k = 0; k < BLOCK_SECTOR_ENTRY_SIZE; k++)
            {
              if (index >= disk_inode->block_count)
                {
                  if (!free_map_allocate (1, &sector))
                    return false;
                  zero_fill (sector);
                  set_sector_entry (
                    get_sector_entry (disk_inode->indirect2[i], j),
                    k, sector);
                  disk_inode->block_count++;
                }
              index++;
              if (index >= sectors)
                return true;
            }
        }
    }

  return false;
}

/* Free allocated blocks in an inode. */
static void
free_blocks (struct inode_disk *disk_inode)
{
  block_sector_t sector;
  size_t index = 0;
  size_t i, j, k;

  for (i = 0; i < INODE_DIRECT; i++)
    {
      if (index >= disk_inode->block_count)
        return;
      sector = disk_inode->direct[i];
      free_map_release (sector, 1);
      index++;
    }

  for (i = 0; i < INODE_INDIRECT; i++)
    {
      for (j = 0; j < BLOCK_SECTOR_ENTRY_SIZE; j++)
        {
          if (index >= disk_inode->block_count)
            return;
          sector = get_sector_entry (disk_inode->indirect[i], j);
          free_map_release (sector, 1);
          index++;
        }
      free_map_release (disk_inode->indirect[i], 1);
    }

  for (i = 0; i < INODE_INDIRECT2; i++)
    {
      for (j = 0; j < BLOCK_SECTOR_ENTRY_SIZE; j++)
        {
          for (k = 0; k < BLOCK_SECTOR_ENTRY_SIZE; k++)
            {
              if (index >= disk_inode->block_count)
                return;
              sector = get_sector_entry (get_sector_entry (disk_inode->indirect2[i], j), k);
              free_map_release (sector, 1);
              index++;
            }
          free_map_release (get_sector_entry (disk_inode->indirect2[i], j), 1);
        }
      free_map_release (disk_inode->indirect2[i], 1);
    }
}
