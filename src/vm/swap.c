#include "vm/swap.h"
#include <bitmap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/page.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
#define TAKEN true

/* Swap Table */
static struct block *swap_table;
static struct bitmap *swap_vacancy_map;

/* Lock for swap table operations. */
static struct lock st_lock;

/* Initialize the swap table and its assets. */
void
swap_table_init (void)
{
  lock_init (&st_lock);
  swap_table = block_get_role (BLOCK_SWAP);

  /* Allocate one bit per page in the block. */
  swap_vacancy_map = bitmap_create (block_size (swap_table));
  bitmap_set_all (swap_vacancy_map, !TAKEN);
}

/* Write to sectors in swap table from the given physical address. */
int
swap_write (void *paddr)
{
  lock_acquire (&st_lock);

  /* Find SECTORS_PER_PAGE open slots in swap_table and flip the bits to
     taken. */
  off_t open_slot = bitmap_scan_and_flip (swap_vacancy_map, 0,
                                          SECTORS_PER_PAGE, !TAKEN);
  if ((unsigned) open_slot == BITMAP_ERROR)
    PANIC ("SWAP TABLE FULL!");

  /* Iterate over each sector in a page (8) to write the page to the swap
     table. */
  for (int i = 0; i < SECTORS_PER_PAGE; i++)
    block_write (swap_table, open_slot + i, paddr + (i * BLOCK_SECTOR_SIZE));
  
  lock_release (&st_lock);
  return open_slot;
}

/* Read sector at swap_index from swap table into the given virtual address. */
void
swap_read (int swap_index, void *paddr)
{
  lock_acquire (&st_lock);
  /* Check if the bit at index swap_index is taken. */
  if (bitmap_test (swap_vacancy_map, swap_index) == TAKEN)
  {
    /* Iterate through each contiguous sector for the page, read the sector
       back to the given kernel address, and flip the bit at the sector to
       free. */
    for (int i = 0; i < SECTORS_PER_PAGE; i++)
    {
      block_read (swap_table, swap_index + i, paddr + (i * BLOCK_SECTOR_SIZE));
      bitmap_flip (swap_vacancy_map, swap_index + i);
    }
  }
  lock_release (&st_lock);
}