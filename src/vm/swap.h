#ifndef VM_SWAP_H
#define VM_SWAP_H

/* Swap table operations. */
void swap_table_init (void);
int swap_write (void *);
void swap_read (int, void *);

#endif