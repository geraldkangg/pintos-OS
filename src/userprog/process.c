#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/page.h"

#define WORD_SIZE 4

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip)(void), void **esp);

/* Initialize process info struct. */
void
process_info_init (struct process_info *pi, tid_t tid)
{
  pi->tid = tid;
  pi->exit_status = 0;
  pi->dead = false;
  sema_init (&pi->wait_sema, 0);
  sema_init (&pi->load_sema, 0);
}

/* Find process_info in a specified parent with the given tid. */
struct process_info *
process_info_by_tid (struct thread *parent, tid_t tid)
{
  struct list_elem *e;

  for (e = list_begin (&parent->children);
       e != list_end (&parent->children);
       e = list_next (e))
  {
    struct process_info *pi = list_entry (e, struct process_info, elem);
    if (pi->tid == tid)
      return pi;
  }
  
  return NULL;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Reduce file_name to only the executable name. */
  char *fn_only = palloc_get_page (0);
  if (fn_only == NULL)
    return TID_ERROR;
  strlcpy (fn_only, file_name, PGSIZE);
  char *file_name_save_ptr;
  strtok_r (fn_only, " ", &file_name_save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (fn_only, PRI_DEFAULT, start_process, fn_copy);
  palloc_free_page (fn_only);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);

  struct thread *child = thread_by_tid (tid);
  struct process_info *pi = malloc (sizeof (struct process_info));
  if (pi == NULL)
    return TID_ERROR;
  process_info_init (pi, tid);
  
  /* Add child thread's process_info to children list on current thread. */
  list_push_back (&thread_current ()->children, &pi->elem);
  child->parent = thread_current ();

#ifdef FILESYS
  /* Set child process's cwd to parent's. */
  if (thread_current ()->cwd == NULL)
    child->cwd = dir_open_root ();
  else
    child->cwd = dir_reopen (thread_current ()->cwd);
#endif

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load(file_name, &if_.eip, &if_.esp);

  /* Store executable load status and release lock on parent. */
  struct thread *cur = thread_current ();
  if (cur->parent != NULL)
  {
    struct process_info *child_p = process_info_by_tid (cur->parent, cur->tid);
    child_p->loaded_executable = success;
    sema_up (&child_p->load_sema);
  }

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
  {
    thread_current ()->exit = -1;
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&if_)
               : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid UNUSED)
{
  struct process_info *dying_process = NULL;

  /* Check for existing child thread of current thread with tid child_tid. */
  dying_process = process_info_by_tid (thread_current (), child_tid);

  /* Return -1 if child_tid is not a child thread or is invalid. */
  if (dying_process == NULL) return -1;

  /* Wait for dying process to finish. */
  if (!dying_process->dead)
    sema_down (&dying_process->wait_sema);
  
  /* Make a copy of the dying process's exit status. */
  int exit_status = dying_process->exit_status;

  /* Remove process_info from parent thread and free its space. */
  list_remove (&dying_process->elem);
  free (dying_process);

  return exit_status;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;

  struct file *file = cur->executable;
  if (file != NULL)
    file_allow_write (file);

  /* Print process exit statement. */
  printf ("%s: exit(%d)\n", thread_name (), cur->exit);

  /* Set exit status and set status of process death. */
  struct process_info *exiting_process;
  exiting_process = process_info_by_tid (cur->parent, cur->tid);
  exiting_process->exit_status = cur->exit;
  exiting_process->dead = true;

  /* Release waiting parent. */
  sema_up (&exiting_process->wait_sema);

  /* Free all child process information. */
  struct list_elem *e = list_begin (&cur->children);
  while (e != list_end (&cur->children))
  {
    struct process_info *child_p = list_entry (e, struct process_info, elem);
    e = list_next (e);
    free (child_p);
  }

  /* Release held lock. */
  if (cur->held_lock != NULL)
  {
    lock_release (cur->held_lock);
    cur->held_lock = NULL;
  }

  /* Free all file descriptors. */
  close_all_thread_fds ();

  /* Unmap all files. */
  struct list_elem *map_elem = list_begin (&cur->mmt);
  while (map_elem != list_end (&cur->mmt))
  {
    struct list_elem *temp = list_next (map_elem);
    struct mmap_info *mmte = list_entry (map_elem, struct mmap_info, elem);
    map_elem = temp;
    munmap_file (mmte->mapping);
  }

  /* Free the entire SPT. */
  spt_destruct ();

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *tokens);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
bool build_stack_args (void **esp, char *tokens);
bool check_page_size (int);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Retrieve file name token. */
  char *file_name_;
  char *file_name_save_ptr;
  char *file_name_cp = palloc_get_page (0);
  if (file_name_cp == NULL)
    goto done;
  strlcpy (file_name_cp, file_name, strlen (file_name) + 1);
  file_name_ = strtok_r ((char *)file_name, " ", &file_name_save_ptr);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open (file_name_);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name_);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2
      || ehdr.e_machine != 3 || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name_);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
             Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                        - read_bytes);
        }
        else
        {
          /* Entirely zero.
             Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack (esp, file_name_cp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;
done:
  /* We arrive here whether the load is successful or not. */
  if (success)
    file_deny_write (file);
  else
    file_close(file);
  palloc_free_page (file_name_cp);
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  thread_current ()->executable = file;
  uint32_t file_start = ofs;

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

  #ifdef VM
    /* Initialize new SPTE. */
    struct page *spte = malloc (sizeof (struct page));
    if (spte == NULL)
      break;
    spte->vaddr = upage;
    spte->writable = writable;
    spte->bytes_read = page_read_bytes;
    spte->file_start_ofs = file_start;
    spte->loaded = false;
    spte->pinned = false;
    spte->executable = file;
    spte->swap_index = -1;
    spte->mapping = -1;

    page_add_page (spte);

    file_start += page_read_bytes;
  #else
    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page (PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
    {
      palloc_free_page (kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable))
    {
      palloc_free_page (kpage);
      return false;
    }
  #endif

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp, char *tokens)
{
  uint8_t *kpage;
  bool success = false;

#ifdef VM
  /* Initialize new SPTE. */
  struct page *spte = malloc (sizeof (struct page));
  if (spte == NULL)
    return false;
  spte->vaddr = ((uint8_t *)PHYS_BASE) - PGSIZE;
  spte->writable = true;
  spte->bytes_read = 0;
  spte->file_start_ofs = 0;
  spte->loaded = false;
  spte->pinned = false;
  spte->executable = NULL;
  spte->swap_index = -1;
  spte->mapping = -1;

  page_add_page (spte);
  kpage = falloc_get_page (spte);
#else
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
#endif

  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
    {
      *esp = PHYS_BASE;
      success = build_stack_args (esp, tokens);
    }
    else
    {
#ifdef VM
      falloc_free_page (kpage);
      page_free_page (spte->vaddr);
#else
      palloc_free_page (kpage);
#endif
    }
  }
  return success;
}

/* Parse tokens and push arguments onto the stack esp. */
bool build_stack_args (void **esp, char *tokens)
{
  char *token, *token_save_ptr;
  int argc = 0;
  char **argv = palloc_get_page (0);
  if (argv == NULL)
    return false;
  int bytes_added = 0; // Used to ensure the max page size is not exceeded
  bool success = true;

  /* Calculate the number of arguments. */
  for (token = strtok_r (tokens, " ", &token_save_ptr);
       token != NULL;
       token = strtok_r(NULL, " ", &token_save_ptr))
  {
    if (!check_page_size (argc + 1))
    {
      success = false;
      goto done;
    }
    argv[argc++] = token;
  }

  /* Push argument names onto stack. */
  for (int i = 0; i < argc; i++)
  {
    int len = strlen (argv[i]) + 1;
    bytes_added += len;
    if (!check_page_size (bytes_added))
    {
      success = false;
      goto done;
    }
    *esp -= len;
    strlcpy ((char *)*esp, argv[i], len);
    argv[i] = (char *)*esp;
  }

  /* Align stack pointer to nearest multiple of four. */
  bytes_added += (*esp - (void *)((uintptr_t)*esp & ~3));
  if (!check_page_size (bytes_added))
  {
    success = false;
    goto done;
  }
  *esp = (void *)((uintptr_t)*esp & ~3);

  /* Push NULL sentinel. */
  bytes_added += WORD_SIZE;
  if (!check_page_size (bytes_added))
  {
    success = false;
    goto done;
  }
  *esp -= WORD_SIZE;
  *((void **)*esp) = NULL;

  /* Push argument pointers onto stack. */
  for (int i = argc - 1; i >= 0; i--)
  {
    bytes_added += WORD_SIZE;
    if (!check_page_size (bytes_added))
    {
      success = false;
      goto done;
    }
    *esp -= WORD_SIZE;
    *((void **)*esp) = argv[i];
  }

  /* Push pointer to first argument onto stack. */
  bytes_added += WORD_SIZE;
  if (!check_page_size (bytes_added))
  {
    success = false;
    goto done;
  }
  void *argv0 = *esp;
  *esp -= WORD_SIZE;
  *((void **)*esp) = argv0;

  /* Push argc onto stack. */
  bytes_added += WORD_SIZE;
  if (!check_page_size (bytes_added))
  {
    success = false;
    goto done;
  }
  *esp -= WORD_SIZE;
  *((int *)*esp) = argc;

  /* Push fake return address onto stack. */
  bytes_added += WORD_SIZE;
  if (!check_page_size (bytes_added))
  {
    success = false;
    goto done;
  }
  *esp -= WORD_SIZE;
  *((void **)*esp) = NULL;

  done:
    palloc_free_page (argv);
    return success;
}

/* Checks that size does not exceed PGSIZE. */
bool
check_page_size (int size)
{
  return size <= PGSIZE;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
