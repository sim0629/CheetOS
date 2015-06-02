#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <list.h>
#include "devices/block.h"

struct cache_entry;

struct cache
  {
    struct block *block;
    struct cache_entry *entries;
    struct list entry_list;
  };

bool cache_init(struct cache *cache, struct block *block);
void cache_deinit(struct cache *cache);

void cache_read(struct cache *cache, block_sector_t sector,
                void *buffer, int offset, int size);
void cache_write(struct cache *cache, block_sector_t sector,
                 const void *buffer, int offset, int size);
void cache_invalidate(struct cache *cache, block_sector_t sector,
                      size_t cnt);
void cache_flush(struct cache *cache);

#endif
