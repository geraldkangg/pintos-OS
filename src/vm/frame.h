#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <stdbool.h>
#include <stddef.h>
#include "threads/thread.h"

/* Struct to represent a frame in the frame table. */
struct frame {
  void *paddr;              /* Physical address for the frame. */
  struct page *spte;        /* Pointer to supp. page table entry holding frame. */
  struct thread *owner;     /* Owner of the frame (based on vaddr). */
  struct list_elem elem;    /* Element to be added in frame list. */
};

/* Frame list operations. */
void frame_table_init (void);

/* For user allocation of virtual + physical memory. */
void *falloc_get_page (struct page *);
void falloc_free_page (void *);

#endif /* vm/frame.h */