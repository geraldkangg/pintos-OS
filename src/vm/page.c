#include "vm/page.h"
#include <stdio.h>
#include <stdlib.h>
#include <hash.h>
#include <string.h>
#include <lib/round.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"

static void free_spte (struct hash_elem *elem, void *aux UNUSED);

/* Initialize the SPT as a hash table. */
void
spt_init (struct hash *spt)
{
  hash_init (spt, page_hash_func, page_less_func, NULL);
}

/* Initialize the MMT as a hash table. */
void
mmt_init (struct list *mmt)
{
  list_init (mmt);
}

/* Destroy the SPT and its entries. */
void
spt_destruct (void)
{
  hash_destroy (&thread_current ()->spt, free_spte);
}

/* Hash function for SPTE. */
unsigned
page_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct page *sp_elem = hash_entry (elem, struct page, h_elem);
  return hash_bytes (&sp_elem->vaddr, sizeof (sp_elem->vaddr));
}

/* Hash comparison function for SPTE. */
bool
page_less_func (const struct hash_elem *a, const struct hash_elem *b,
                void *aux UNUSED)
{
  struct page *sp_a = hash_entry (a, struct page, h_elem);
  struct page *sp_b = hash_entry (b, struct page, h_elem);
  return sp_a->vaddr < sp_b->vaddr;
}

/* Add an entry to the SPT. */
void
page_add_page (struct page *spte)
{
  struct thread *t = thread_current ();

  /* Check if already in supplementary page table. */
  if (page_find_page (spte->vaddr) != NULL)
    return;

  /* Add page into the supplemental page table. */
  lock_acquire (&t->spt_lock);
  hash_insert (&t->spt, &spte->h_elem); 
  lock_release (&t->spt_lock);
}

/* Find a SPTE with the given virtual address. */
struct page *
page_find_page (void *vaddr)
{
  struct page spte;
  struct hash_elem *elem;

  spte.vaddr = pg_round_down (vaddr);
  lock_acquire (&thread_current ()->spt_lock);
  elem = hash_find (&thread_current ()->spt, &spte.h_elem);
  lock_release (&thread_current ()->spt_lock);

  return elem != NULL ? hash_entry (elem, struct page, h_elem) : NULL;
}

/* Free the memory of a SPTE. (to be used for clearing entire SPT) */
static void
free_spte (struct hash_elem *elem, void *aux UNUSED)
{
  page_free_page (elem);
}

/* Free individual SPTE. */
void
page_free_page (struct hash_elem *elem)
{
  struct thread *t = thread_current ();
  lock_acquire (&t->spt_lock);
  struct page *spte = hash_entry (elem, struct page, h_elem);

  if (spte == NULL)
  {
    lock_release (&t->spt_lock);
    return;
  }

  /* Remove SPTE data from disk. */
  if (spte->swap_index > -1)
    swap_read (spte->swap_index, spte->vaddr);

  /* Clear related page in the page table and delte the SPTE. */
  void *paddr = pagedir_get_page (t->pagedir, spte->vaddr);
  pagedir_clear_page (t->pagedir, spte->vaddr);
  falloc_free_page (paddr);
  hash_delete (&t->spt, elem);
  free (spte);
  lock_release (&t->spt_lock);
}

/* Find a Memory Mapped File with the given mapping. */
struct mmap_info *
mmt_find_file (int mapping)
{
  struct thread *t = thread_current ();
  struct list_elem *e;
  for (e = list_begin (&t->mmt);
       e != list_end (&t->mmt);
       e = list_next (e))
  {
    struct mmap_info *mmte = list_entry (e, struct mmap_info, elem);
    if (mmte->mapping == mapping)
      return mmte;
  }
  return NULL;
}

/* Add an entry to the Memory Mapped Table. */
void
mmt_add_file (struct mmap_info *mmte)
{
  struct thread *t = thread_current ();

  /* Check if already in supplementary page table. */
  if (mmt_find_file (mmte->mapping) != NULL)
    return;

  /* Add page into the supplemental page table. */
  lock_acquire (&t->mmt_lock);
  list_push_back (&t->mmt, &mmte->elem);
  lock_release (&t->mmt_lock);
  return;
}

/* Free the memory of a MMT and corresponding SPT page. */
void
free_mmt (struct mmap_info *mmap)
{
  if (mmap == NULL)
    return;
  struct thread *t = thread_current ();
  lock_acquire (&t->mmt_lock);
  list_remove (&mmap->elem);
  lock_release (&t->mmt_lock);
  free (mmap);
}

/* Add a new mapping to the memory mapping table. */
bool
mmap_file (void *vaddr, unsigned len)
{
  struct mmap_info *mmte = malloc (sizeof (struct mmap_info));
  if (mmte == NULL)
    return false;
  mmte->start = vaddr;
  mmte->mapping = thread_current ()->mapid;
  mmte->len_file = len;
  mmt_add_file (mmte);
  return true;
}

/* Unmap file given a map ID. */
void
munmap_file (mapid_t mapping)
{
  struct mmap_info *mmap = mmt_find_file (mapping);
  void *vaddr = mmap->start;

  for (; vaddr < mmap->start + mmap->len_file; vaddr += PGSIZE)
  {
    struct page *spte = page_find_page (vaddr);
    if (spte == NULL)
      return;

    /* Only write back to the file system if the file was changed
       (i.e. its page is dirty). */
    spte->pinned = true;
    if (pagedir_is_dirty (thread_current ()->pagedir, spte->vaddr))
    {
      file_write_at (spte->executable, spte->kpage, spte->bytes_read,
                     spte->file_start_ofs); 
    }
    spte->pinned = false;

    page_free_page (&spte->h_elem);
  }

  free_mmt (mmap);
}