#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#define INODE_MAGIC 0x494e4f44   /* Identifies an inode. */
#define NUM_DIRECT 12            /* Number of direct blocks. */ 
#define BLOCKS_PER_INDIRECT 128  /* Number of blocks per indirect block. */
#define INVALID_SECTOR (block_sector_t) -1  /* Null block sector. */

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    bool isdir;                                /* If inode is dir. */
    off_t length;                              /* File size in bytes. */
    unsigned magic;                            /* Magic number. */
    uint32_t unused[111];                      /* Not used. */
    block_sector_t direct_blocks[NUM_DIRECT];  /* Direct blocks. */
    block_sector_t indirect_block;             /* Indirect block. */
    block_sector_t doubly_indirect_block;      /* Doubly indirect block. */
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
    struct lock dir_lock;               /* Lock for directory inodes. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  char buf[sizeof (struct inode_disk)];
  cache_read (inode->sector, 0, BLOCK_SECTOR_SIZE, &buf);
  struct inode_disk *data = (struct inode_disk *)buf;
  off_t file_size = data->length;

  if (pos < file_size)
  {
    int index = pos / BLOCK_SECTOR_SIZE;

    if (index < NUM_DIRECT)
    {
      /* Direct block. */
      return data->direct_blocks[index];
    }
    else if (index < NUM_DIRECT + BLOCKS_PER_INDIRECT)
    {
      /* Indirect block. */
      block_sector_t indirect_block[BLOCKS_PER_INDIRECT];
      cache_read (data->indirect_block, 0,
                  BLOCK_SECTOR_SIZE, &indirect_block);
      return indirect_block[index - NUM_DIRECT];
    }
    else
    {
      /* Doubly indirect block. */
      block_sector_t doubly_indirect_block[BLOCKS_PER_INDIRECT];
      cache_read (data->doubly_indirect_block, 0,
                  BLOCK_SECTOR_SIZE, &doubly_indirect_block);
      int doubly_indirect_index = (index - NUM_DIRECT - 
                                  BLOCKS_PER_INDIRECT) / BLOCKS_PER_INDIRECT;
      block_sector_t indirect_block[BLOCKS_PER_INDIRECT];
      cache_read (doubly_indirect_block[doubly_indirect_index], 0,
                  BLOCK_SECTOR_SIZE, &indirect_block);
      int indirect_index = (index - NUM_DIRECT -
                           BLOCKS_PER_INDIRECT) % BLOCKS_PER_INDIRECT;
      return indirect_block[indirect_index];
    }
  }
  else
  {
    /* Past end of file. */
    return INVALID_SECTOR;
  }
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
inode_create (block_sector_t sector, off_t length, bool isdir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);

  if (disk_inode != NULL)
  {
    size_t sectors = bytes_to_sectors (length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->isdir = isdir;

    /* Allocate direct blocks. */
    size_t i;
    for (i = 0; i < NUM_DIRECT && i < sectors; i++)
    {
      if (free_map_allocate (1, &disk_inode->direct_blocks[i]))
      {
        static char zeros[BLOCK_SECTOR_SIZE];
        cache_write (disk_inode->direct_blocks[i], 0,
                     BLOCK_SECTOR_SIZE, zeros);
      }
      else
        goto failure;
    }

    /* Allocate indirect block. */
    if (i < sectors)
    {
      if (free_map_allocate (1, &disk_inode->indirect_block))
      {
        static char zeros[BLOCK_SECTOR_SIZE];
        cache_write (disk_inode->indirect_block, 0,
                     BLOCK_SECTOR_SIZE, zeros);
      }
      else
        goto failure;

      block_sector_t indirect_block[BLOCKS_PER_INDIRECT];
      size_t j;
      for (j = 0; j < BLOCKS_PER_INDIRECT && i < sectors; j++)
      {
        if (free_map_allocate (1, &indirect_block[j]))
        {
          static char zeros[BLOCK_SECTOR_SIZE];
          cache_write (indirect_block[j], 0,
                       BLOCK_SECTOR_SIZE, zeros);
        }
        else
          goto failure;
        i++;
      }

      cache_write (disk_inode->indirect_block, 0,
                   BLOCK_SECTOR_SIZE, &indirect_block);
    }

    /* Allocate doubly indirect block */
    if (i < sectors)
    {
      if (free_map_allocate (1, &disk_inode->doubly_indirect_block))
      {
        static char zeros[BLOCK_SECTOR_SIZE];
        cache_write (disk_inode->doubly_indirect_block, 0,
                     BLOCK_SECTOR_SIZE, zeros);
      }
      else
        goto failure;

      block_sector_t doubly_indirect_block[BLOCKS_PER_INDIRECT];
      size_t k;
      for (k = 0; k < BLOCKS_PER_INDIRECT && i < sectors; k++)
      {
        if (free_map_allocate (1, &doubly_indirect_block[k]))
        {
          static char zeros[BLOCK_SECTOR_SIZE];
          cache_write (doubly_indirect_block[k], 0,
                       BLOCK_SECTOR_SIZE, zeros);
        }
        else
          goto failure;

        block_sector_t indirect_block[BLOCKS_PER_INDIRECT];
        size_t l;
        for (l = 0; l < BLOCKS_PER_INDIRECT && i < sectors; l++)
        {
          if (free_map_allocate (1, &indirect_block[l]))
          {
            static char zeros[BLOCK_SECTOR_SIZE];
            cache_write (indirect_block[l], 0,
                       BLOCK_SECTOR_SIZE, zeros);
          }
          else
            goto failure;
          i++;

          cache_write (doubly_indirect_block[k], 0,
                   BLOCK_SECTOR_SIZE, &indirect_block);
        }
      }

      cache_write (disk_inode->doubly_indirect_block, 0,
                   BLOCK_SECTOR_SIZE, &doubly_indirect_block);
    }

    cache_write (sector, 0, BLOCK_SECTOR_SIZE, disk_inode);
    success = true;
    return success;
  }

  failure:
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
  lock_init (&inode->dir_lock);

  /* Read sector in from memory so that it is cached for the open inode. */
  char buf[sizeof (struct inode_disk)];
  cache_read (inode->sector, 0, BLOCK_SECTOR_SIZE, &buf);

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
          char buf[sizeof (struct inode_disk)];
          cache_read (inode->sector, 0, BLOCK_SECTOR_SIZE, &buf);
          struct inode_disk *data = (struct inode_disk *)buf;
          free_map_release (inode->sector, 1);
          free_map_release (data->direct_blocks[0],
                            bytes_to_sectors (data->length)); 
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

      /* Read from cache. */
      cache_read (sector_idx, sector_ofs, chunk_size, buffer + bytes_read);
      
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
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

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
      
      /* Write to buffer cache. */
      cache_write (sector_idx, sector_ofs, chunk_size,
                   (void *)buffer + bytes_written);

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
  char buf[sizeof (struct inode_disk)];
  cache_read (inode->sector, 0, BLOCK_SECTOR_SIZE, &buf);
  struct inode_disk *data = (struct inode_disk *)buf;
  return data->length;
}

/* Returns whether or not the given inode is a directory. */
bool
is_dir (struct inode *inode)
{
  char buf[sizeof (struct inode_disk)];
  cache_read (inode->sector, 0, BLOCK_SECTOR_SIZE, &buf);
  struct inode_disk *data = (struct inode_disk *)buf;
  return data->isdir;
}

/* Returns whether or not the inode is removed. */
bool
is_removed (struct inode *inode)
{
  return inode->removed;
}

/* Acquire an inode's directory lock. */
void
dir_lock_acquire (struct inode *inode)
{
  lock_acquire (&inode->dir_lock);
}

/* Release an inode's directory lock. */
void
dir_lock_release (struct inode *inode)
{
  lock_release (&inode->dir_lock);
}
