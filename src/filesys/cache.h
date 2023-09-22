#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"

#define CACHE_MAX_SIZE 64        /* The cache maxes out at 64 blocks. */
#define CACHE_TO_DISK_FREQ 3000  /* Write cache to disk every 30 seconds. */

/* Cache entry state definitions. */
#define CACHE_OC 0x0            /* Occupied (initial) */
#define CACHE_A 0x01            /* Accessed bit. */
#define CACHE_D 0x02            /* Dirty bit. */
#define CACHE_P 0x04            /* Pinned bit. */

/* Entry for the file buffer cache. */
struct cache_entry
{
  void *file_data;              /* Address of cached file data. */
  uint8_t state;                /* State of the cache entry. */
  block_sector_t sector;        /* The sector of the file on disk. */
  struct rwlock rw_lock;        /* Read-write lock for cache entry. */
};

/* Sector to fetch for read-ahead. */
struct sector_to_fetch
{
  block_sector_t sector;        /* Sector to read in. */
  struct list_elem elem;        /* Element to add to fetch list. */
};

/* Buffer Cache operations. */
void buffer_cache_init (void);
bool cache_read (block_sector_t, uint32_t, uint32_t, void *);
bool cache_write (block_sector_t, uint32_t, uint32_t, void *);
void cache_flush (void);

/* Asynch cache operations. */
void async_write_behind (void * UNUSED);
void async_read_ahead (void * UNUSED);

#endif