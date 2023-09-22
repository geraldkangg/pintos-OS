#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include <hash.h>
#include "threads/thread.h"

/* Define mapid*/
typedef int mapid_t;

/* Struct to represent a SPTE. */
struct page
{
  void *vaddr;                  /* Page virtual address. */
  uint8_t* kpage;               /* Respective physical address. */
  bool writable;                /* Whether or not the page is writable. */
  bool loaded;                  /* The page is loaded into physical memory. */
  bool pinned;                  /* If page is pinned, can't be evicted. */
  struct hash_elem h_elem;      /* Element to store in SPT. */
  uint32_t bytes_read;          /* Number of bytes read into physical memory. */
  uint32_t file_start_ofs;      /* Byte offset til the start of the file. */
  struct file *executable;      /* The executable used by the page. */
  int swap_index;               /* Index in the swap table. */
  mapid_t mapping;              /* Map ID of mapped file. -1 if unmapped. */
};

/* SPT Control */
void spt_init (struct hash *);
void spt_destruct (void);
unsigned page_hash_func (const struct hash_elem *, void * UNUSED);
bool page_less_func (const struct hash_elem *, const struct hash_elem *,
                     void * UNUSED);

/* SPT operations.*/
void page_add_page (struct page *);
struct page *page_find_page (void *);
void page_free_page (struct hash_elem *);

/* Struct to represent memory mapped file information. */
struct mmap_info
{
  void *start;            /* Starting virtual address of the mapped file. */
  unsigned len_file;      /* Length of the file that is mapped. */
  mapid_t mapping;        /* Assigned mapping */
  struct list_elem elem;  /* Element to put in lists */
};

/* Memory mapping table control and operations. */
void mmt_init (struct list *);
void mmt_add_file (struct mmap_info *);
void free_mmt (struct mmap_info *);
struct mmap_info *mmt_find_file (int mapping);

/* Memory mapping operations. */
bool mmap_file (void *, unsigned);
void munmap_file (mapid_t);
#endif /* vm/page.h */