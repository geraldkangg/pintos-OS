#include <debug.h>
#include <string.h>
#include <stdio.h>
#include "devices/timer.h"
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Buffer cache as a hash table. */
static struct cache_entry *cache[CACHE_MAX_SIZE];
static struct lock lock_cache;
static uint8_t cache_size;

/* Clock hand for pointing at entries. */
static uint8_t clock_hand;

/* Fetch list for read-ahead. */
static struct list fetch_list;
static struct lock read_ahead_lock;
static struct condition read_ahead_cond;

static struct cache_entry *cache_create_entry (block_sector_t);
static struct cache_entry *cache_evict_entry (void);
static struct cache_entry *cache_by_sector (block_sector_t);
static void invoke_read_ahead (block_sector_t);
static void advance_clock_hand (void);

/* Initialize the buffer cache. */
void
buffer_cache_init (void)
{
  /* Initialize cache with NULL values. */
  for (int i = 0; i < CACHE_MAX_SIZE; i++)
    cache[i] = NULL;
  cache_size = 0;

  /* Initialize lock for cache and clock hand. */
  lock_init (&lock_cache);
  clock_hand = 0;

  /* Initialize read-ahead fetch list. */
  list_init (&fetch_list);
  lock_init (&read_ahead_lock);
  cond_init (&read_ahead_cond);

  /* Start threads to run asynchronous cache functions including write-behind
    and read-ahead. */
  thread_create ("async_write_behind", PRI_MAX, async_write_behind, NULL);
  thread_create ("async_read_ahead", PRI_DEFAULT, async_read_ahead, NULL);
}

/* Reads from the cached data with the given sector starting at ofs until size
   bytes are read into buf. If no cached data, read from file system and store
   data in cache. */
bool
cache_read (block_sector_t sector, uint32_t ofs, uint32_t size, void *buf)
{
  /* Search for the given sector in the cache. */
  struct cache_entry *c = cache_by_sector (sector);

  /* If it doesn't exist, create (or evict) an entry for the sector. */
  if (c == NULL)
    c = cache_create_entry (sector);
  
  /* If creating didn't work, we can't bring it into cache. */
  if (c == NULL)
    return false;
  
  /* Copy data to buf starting at ofs. */
  rwlock_acquire_read (&c->rw_lock);
  memcpy (buf, c->file_data + ofs, size);
  rwlock_release_read (&c->rw_lock);

  /* Set the accessed bit to true. */
  rwlock_acquire_write (&c->rw_lock);
  c->state |= CACHE_A;
  rwlock_release_write (&c->rw_lock);

  /* Add the next sector to be read to the fetch list. */
  invoke_read_ahead (sector);

  return true;
}

/* Writes into the cached data with the given sector starting at ofs until size
   bytes are read from buf. If no cached data, create/evict cache entry. */
bool
cache_write (block_sector_t sector, uint32_t ofs, uint32_t size, void *buf)
{
  /* Search for the given sector in the cache. */
  struct cache_entry *c = cache_by_sector (sector);

  /* If it doesn't exist, create (or evict) an entry for the sector. */
  if (c == NULL)
    c = cache_create_entry (sector);
  
  /* If creating didn't work, we can't bring it into cache. */
  if (c == NULL)
    return false;
  
  /* Copy data in buf to file_data starting at ofs. */
  rwlock_acquire_write (&c->rw_lock);
  memcpy (c->file_data + ofs, buf, size);

  /* Set the accessed and dirty bits to true. */
  c->state |= CACHE_D;
  c->state |= CACHE_A;
  rwlock_release_write (&c->rw_lock);

  return true;
}

/* Flush the cache, write all entries back to filesys. */
void
cache_flush (void)
{
  for (int i = 0; i < CACHE_MAX_SIZE; i++)
  {
    struct cache_entry *c = cache[i];
    if (c != NULL && (c->state | CACHE_D) == c->state)
    {
      rwlock_acquire_write (&c->rw_lock);
      block_write (fs_device, c->sector, c->file_data);
      rwlock_release_write (&c->rw_lock);
      c->state &= ~CACHE_D;
    }
  }
}

/* Try to create a new cache entry. If cache is at max size, evict. */
static struct cache_entry *
cache_create_entry (block_sector_t sector)
{
  lock_acquire (&lock_cache);
  struct cache_entry *c;

  /* Create a new cache entry for sector if cache is not maxed out. */
  if (cache_size < CACHE_MAX_SIZE)
  {
    /* Initialize cache entry and file data in heap. */
    c = malloc (sizeof (struct cache_entry));
    if (c == NULL)
      return NULL;

    c->file_data = malloc (BLOCK_SECTOR_SIZE);
    if (c->file_data == NULL)
    {
      lock_release (&lock_cache);
      free (c);
      return NULL;
    }

    /* Initialize the metadata of the cache entry. */
    rwlock_init (&c->rw_lock);
    rwlock_acquire_write (&c->rw_lock);
    c->state = CACHE_OC;
    c->sector = sector;

    /* Add cache entry to buffer cache. */
    cache[cache_size++] = c;
  }
  /* Otherwise, evict a cache entry and replace it with sector. */
  else
  {
    c = cache_evict_entry ();
    rwlock_acquire_write (&c->rw_lock);
    c->sector = sector;
  }

  /* Read from file system into file_data. Pin so it is not
     evicted. */
  c->state |= CACHE_P;
  block_read (fs_device, sector, c->file_data);
  c->state &= ~CACHE_P;
  rwlock_release_write (&c->rw_lock);

  lock_release (&lock_cache);

  return c;
}

/* Evict a cache entry from the cache using the clock algorithm. */
static struct cache_entry *
cache_evict_entry (void)
{
  struct cache_entry *c = cache[clock_hand];
  while (true)
  {
    /* Check that cache entry is not pinned. */
    if ((c->state | CACHE_P) != c->state)
    {
      /* Check if cache entry is accessed. If so, set unaccessed and move on. */
      if ((c->state | CACHE_A) == c->state)
      {
        c->state &= ~CACHE_A;
      }
      /* Otherwise, write back to filesys. Pin so it is not evicted in another
         process. */
      else
      {
        /* Only write back to filesys if dirty. */
        if ((c->state | CACHE_D) == c->state)
        {
          c->state |= CACHE_P;
          rwlock_acquire_read (&c->rw_lock);
          block_write (fs_device, c->sector, c->file_data);
          rwlock_release_read (&c->rw_lock);
          c->state &= ~CACHE_P;

          /* Reset dirty bit after the data is written back to filesys. */
          c->state &= ~CACHE_D;
        }

        break;
      }
    }
    advance_clock_hand ();
    c = cache[clock_hand];
  }
  return c;
}

/* Search the cache (hash table) by sector. */
static struct cache_entry *
cache_by_sector (block_sector_t sector)
{
  lock_acquire (&lock_cache);
  for (int i = 0; i < CACHE_MAX_SIZE; i++)
  {
    if (cache[i] == NULL)
      continue;
    else if (cache[i]->sector == sector)
    {
      lock_release (&lock_cache);
      return cache[i];
    }
  }
  lock_release (&lock_cache);
  return NULL;
}

/* Add sector to the fetch list and invoke read ahead for that sector. */
static void
invoke_read_ahead (block_sector_t sector)
{
  struct sector_to_fetch *item = malloc (sizeof (struct sector_to_fetch));
  if (item == NULL)
    return;
  item->sector = sector + 1; // We need to read the next sector
  lock_acquire (&read_ahead_lock);
  list_push_back (&fetch_list, &item->elem);
  cond_broadcast (&read_ahead_cond, &read_ahead_lock);
  lock_release (&read_ahead_lock);
}

/* Advance the clock hand to the next cache entry. */
static void
advance_clock_hand (void)
{
  if (clock_hand == CACHE_MAX_SIZE - 1)
    clock_hand = 0;
  else
    clock_hand++;
}

/* Asynchronously write dirty cached files back to the file system every 5
   seconds. */
void
async_write_behind (void *aux UNUSED)
{
  while (true)
  {
    /* Make the timer sleep for 3000 ticks (30 seconds) without busy waiting. */
    timer_sleep (CACHE_TO_DISK_FREQ);

    for (int i = 0; i < CACHE_MAX_SIZE; i++)
    {
      struct cache_entry *c = cache[i];
      if (c == NULL)
        continue;
      else if ((c->state | CACHE_D) == c->state)
      {
        rwlock_acquire_read (&c->rw_lock);
        block_write (fs_device, c->sector, c->file_data);
        rwlock_release_read (&c->rw_lock);
        c->state &= ~CACHE_D;
      }
    }
  }
}

/* Asynchronously read the next block in the fetch list from disk. */
void
async_read_ahead (void *aux UNUSED)
{
  while (true)
  {
    lock_acquire (&read_ahead_lock);

    /* Wait until fetch list is not empty. */
    while (list_empty (&fetch_list))
      cond_wait (&read_ahead_cond, &read_ahead_lock);

    struct sector_to_fetch *item = list_entry (list_pop_front (&fetch_list),
                                struct sector_to_fetch, elem);
    lock_release (&read_ahead_lock);
    if (cache_by_sector (item->sector) == NULL)
      cache_create_entry (item->sector);
    free (item);
  }
}
