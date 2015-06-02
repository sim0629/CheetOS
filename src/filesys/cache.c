#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "devices/block.h"
#include "threads/malloc.h"
#include "cache.h"

#define MAX_ENTRY 64

struct cache_entry
  {
    struct list_elem elem; /* entry_list element */

    bool valid;
    bool dirty;
    block_sector_t sector;
    char data[BLOCK_SECTOR_SIZE];
  };

static void cache_flush_entry(struct cache *, struct cache_entry *);

bool
cache_init(struct cache *cache, struct block *block)
{
  size_t i;

  cache->block = block;
  cache->entries = malloc (MAX_ENTRY * sizeof (struct cache_entry));
  if (cache->entries == NULL)
    return false;

  list_init (&cache->entry_list);
  for (i = 0; i < MAX_ENTRY; i++)
    {
      cache->entries[i].valid = false;
      cache->entries[i].dirty = false;
      list_push_back (&cache->entry_list, &cache->entries[i].elem);
    }
  return true;
}

void
cache_deinit(struct cache *cache)
{
  cache_flush (cache);
  cache->block = NULL;
  free (cache->entries);
  cache->entries = NULL;
}

void
cache_read(struct cache *cache, block_sector_t sector,
           void *buffer, int offset, int size)
{
  size_t i;
  struct cache_entry *entry = NULL;

  for (i = 0; i < MAX_ENTRY; i++)
    {
      struct cache_entry *e = &cache->entries[i];
      if (e->valid && e->sector == sector)
        {
          entry = e;
          break;
        }
    }

  if (entry == NULL)
    {
      entry = list_entry (list_front (&cache->entry_list),
                          struct cache_entry,
                          elem);
      if (entry->dirty)
        cache_flush_entry (cache, entry);
      entry->valid = true;
      entry->dirty = false;
      entry->sector = sector;
      block_read (cache->block, sector, entry->data);
    }

  memcpy (buffer, entry->data + offset, size);

  list_remove (&entry->elem);
  list_push_back (&cache->entry_list, &entry->elem);
}

void
cache_write(struct cache *cache, block_sector_t sector,
            const void *buffer, int offset, int size)
{
  size_t i;
  struct cache_entry *entry = NULL;

  for (i = 0; i < MAX_ENTRY; i++)
    {
      struct cache_entry *e = &cache->entries[i];
      if (e->valid && e->sector == sector)
        {
          entry = e;
          break;
        }
    }

  if (entry == NULL)
    {
      entry = list_entry (list_front (&cache->entry_list),
                          struct cache_entry,
                          elem);
      if (entry->dirty)
        cache_flush_entry (cache, entry);
      entry->valid = true;
      entry->dirty = false;
      entry->sector = sector;
      block_read (cache->block, sector, entry->data);
    }

  entry->dirty = true;
  memcpy (entry->data + offset, buffer, size);

  list_remove (&entry->elem);
  list_push_back (&cache->entry_list, &entry->elem);
}

void
cache_flush(struct cache *cache)
{
  size_t i;

  for (i = 0; i < MAX_ENTRY; i++)
    {
      struct cache_entry *entry = &cache->entries[i];
      if (entry->dirty)
        cache_flush_entry (cache, entry);
    }
}

void
cache_invalidate(struct cache *cache, block_sector_t sector, size_t cnt)
{
  size_t i;

  for (i = 0; i < MAX_ENTRY; i++)
    {
      struct cache_entry *entry = &cache->entries[i];
      if (entry->valid && entry->sector >= sector
          && entry->sector - sector < cnt)
        {
          entry->valid = false;
          entry->dirty = false;
          list_remove (&entry->elem);
          list_push_front (&cache->entry_list, &entry->elem);
        }
    }
}

static void
cache_flush_entry(struct cache *cache, struct cache_entry *entry)
{
  ASSERT (entry->valid && entry->dirty);

  block_write (cache->block, entry->sector, entry->data);
  entry->dirty = false;
}
