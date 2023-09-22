#include "vm/frame.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

/* List to store frames in use. */
static struct list frame_table;

/* Synchronize frame table. */
static struct lock ft_lock;

/* Clock hand for eviction clock algorithm. */
static struct list_elem *clock_hand;

/* Eviction (clock algorithm) functions */
static struct frame *evict_frame (void);
static void advance_clock_hand (void);

static struct frame *add_frame (struct page *);
static struct frame *find_vacant_frame (void);
static struct frame *frame_by_paddr (void *);

/* Initialize the frame list. */
void
frame_table_init (void)
{
  list_init (&frame_table);
  lock_init (&ft_lock);
  clock_hand = list_begin (&frame_table);
}

/* Allocate physical memory for a given virtual address. */
void *
falloc_get_page (struct page *spte)
{
  lock_acquire (&ft_lock);
  /* Search for vacant frame. */
  struct frame *frame = find_vacant_frame ();
  
  /* Try to add new frame if no vacant frames. */
  if (frame == NULL)
    frame = add_frame (spte);

  /* If adding frame didn't work, do eviction strategy. */
  if (frame == NULL)
    frame = evict_frame ();

  /* If eviction strategy failed, return NULL. */
  if (frame == NULL)
  {
    lock_release (&ft_lock);
    return NULL;
  }

  /* Add current thread as owner of frame and point to its respective
     virtual address. */
  frame->owner = thread_current ();
  frame->spte = spte;

  lock_release (&ft_lock);
  return frame->paddr;
}

/* Free a page in physical memory. */
void
falloc_free_page (void *paddr)
{
  struct frame *frame = frame_by_paddr (paddr);
  if (frame == NULL)
    return;
  /* Reset SPTE and thread owner, then zero out physical memory. */
  frame->spte = NULL;
  frame->owner = NULL;
  memset (paddr, 0, PGSIZE);
}

/* Add a new frame to the frame table. */
static struct frame *
add_frame (struct page *spte)
{
  struct frame *frame = malloc (sizeof (struct frame));
  if (frame == NULL)
    return NULL;

  /* Allocate a kernel user page, zeroed out if no bytes are read. */
  void *paddr = palloc_get_page (spte->bytes_read == 0 
                                 ? PAL_USER | PAL_ZERO
                                 : PAL_USER);
  if (paddr == NULL)
  {
    free (frame);
    return NULL;
  }

  frame->paddr = paddr;
  frame->spte = spte;
  frame->owner = thread_current ();
  list_push_back (&frame_table, &frame->elem);
  clock_hand = list_begin (&frame_table);

  return frame;
}

/* Evict a frame using the clock algorithm. */
static struct frame *
evict_frame (void)
{
  struct frame *victim = list_entry (clock_hand, struct frame, elem);
  while (true)
  {
    if (!victim->spte->pinned)
    {
      /* If the page has been accessed recently, set accessed bit to 0 and move
         on. */
      if (pagedir_is_accessed (victim->owner->pagedir, victim->spte->vaddr))
      {
        pagedir_set_accessed (victim->owner->pagedir, victim->spte->vaddr, false);
      }
      /* If the page is dirty, write back to file system or swap. */
      else
      {
        /* If mapped, write file back to filesys. */
        if (victim->spte->mapping > -1)
        {
          munmap_file (victim->spte->mapping);
        }
        /* Otherwise, write to swap table. Pin so it isn't evicted somewhere
           else while writing to swap. */
        else
        {
          victim->spte->pinned = true;
          victim->spte->swap_index = swap_write (victim->paddr);
          victim->spte->pinned = false;
        }

        /* Set page dirty bit to 0 because it was written back to filesys/disk. */
        pagedir_set_dirty (victim->owner->pagedir, victim->spte->vaddr, false);

        /* Clear SPTE and free frame. */
        victim->spte->kpage = NULL;
        victim->spte->loaded = false;
        pagedir_clear_page (thread_current ()->pagedir, victim->spte->vaddr);
        falloc_free_page (victim->paddr);
        break;
      }
    }
    advance_clock_hand ();
    victim = list_entry (clock_hand, struct frame, elem);
  }
  return victim;
}

/* Advance the clock hand for the clock algorithm. */
static void
advance_clock_hand (void)
{
  clock_hand = list_next (clock_hand) == list_end (&frame_table)
                ? list_begin (&frame_table)
                : list_next (clock_hand);
}

/* Find an unused frame in the frame table. */
static struct frame *
find_vacant_frame (void)
{
  struct list_elem *e;
  for (e = list_begin (&frame_table);
       e != list_end (&frame_table);
       e = list_next (e))
  {
    struct frame *frame = list_entry (e, struct frame, elem);
    if (frame->spte == NULL)
      return frame;
  }
  return NULL;
}

/* Search the frame table for the frame with the given physical address. */
static struct frame *
frame_by_paddr (void *paddr)
{
  struct list_elem *e;
  for (e = list_begin (&frame_table);
        e != list_end (&frame_table);
        e = list_next (e))
  {
    struct frame *frame = list_entry (e, struct frame, elem);
    if (frame->paddr == paddr)
      return frame;
  }
  return NULL;
}