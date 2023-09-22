#include "userprog/syscall.h"
#include <lib/round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#endif
#ifdef FILESYS
#include "filesys/directory.h"
#include "filesys/inode.h"
#endif

/* Argument number constants. */
#define ARG_1 1
#define ARG_2 2
#define ARG_3 3
#define ERROR -1
#define PTR_SIZE 4

/* File variables and structs. */
static struct list file_list;
static int next_fd = 2;

/* Lock for edits to the file_list. */
struct lock file_list_lock;

/* Struct to represent important file information. */
struct file_info
{
  struct file *f;         /* Related file. */
  int fd;                 /* Related file descriptor. */
  struct list_elem elem;  /* Element to put in lists. */
  struct thread *owner;   /* Thread owning fd and f. */
};

/* Close all file descriptors for the given thread id. */
void
close_all_thread_fds (void)
{
  struct list_elem *e = list_begin (&file_list);
  while (e != list_end (&file_list))
  {
    struct file_info *fi = list_entry (e, struct file_info, elem);
    struct list_elem *temp = list_next (e);
    if (fi->owner->tid == thread_current ()->tid)
    {
      /* Remove fd from open file list. */
      lock_acquire (&file_list_lock);
      list_remove (e);
      lock_release (&file_list_lock);

      /* Close open file. */
      file_close (fi->f);

      /* Free the file_info. */
      free (fi);
    }
    e = temp;
  }
}

static void syscall_handler (struct intr_frame *);
static void sys_halt (void);
static void sys_exit (struct intr_frame *);
static void sys_exec (struct intr_frame *);
static void sys_wait (struct intr_frame *);
static void sys_create (struct intr_frame *);
static void sys_remove (struct intr_frame *);
static void sys_open (struct intr_frame *);
static void sys_filesize (struct intr_frame *);
static void sys_read (struct intr_frame *);
static void sys_write (struct intr_frame *);
static void sys_seek (struct intr_frame *);
static void sys_tell (struct intr_frame *);
static void sys_close (struct intr_frame *);
static void sys_mmap (struct intr_frame *);
static void sys_munmap (struct intr_frame *);
static void sys_chdir (struct intr_frame *);
static void sys_mkdir (struct intr_frame *);
static void sys_readdir (struct intr_frame *);
static void sys_isdir (struct intr_frame *);
static void sys_inumber (struct intr_frame *);
static bool validate_args (void *, int);
static bool is_valid_buffer (void *, unsigned);
static bool is_valid_string (const char *);
static bool is_valid_ptr (const void *);
static struct file_info *file_info_by_fd (int);
static bool is_fd_owner (int fd);
static bool is_valid_fd (int);
static void error_exit (void);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init (&file_list);
  lock_init (&file_list_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  /* Ensure system call number is valid. */
  if (!is_valid_ptr (f->esp))
    error_exit ();

  /* Get system call number. */
  int sys_num = *(int *)(f->esp);

  switch (sys_num)
  {
    case SYS_HALT:
      sys_halt ();
      break;
    case SYS_EXIT:
      sys_exit (f);
      break;
    case SYS_EXEC:
      sys_exec (f);
      break;
    case SYS_WAIT:
      sys_wait (f);
      break;
    case SYS_CREATE:
      sys_create (f);
      break;
    case SYS_REMOVE:
      sys_remove (f);
      break;
    case SYS_OPEN:
      sys_open (f);
      break;
    case SYS_FILESIZE:
      sys_filesize (f);
      break;
    case SYS_READ:
      sys_read (f);
      break;
    case SYS_WRITE:
      sys_write (f);
      break;
    case SYS_SEEK:
      sys_seek (f);
      break;
    case SYS_TELL:
      sys_tell (f);
      break;
    case SYS_CLOSE:
      sys_close (f);
      break;
    case SYS_MMAP:
      sys_mmap (f);
      break;
    case SYS_MUNMAP:
      sys_munmap (f);
      break;
    case SYS_CHDIR:
      sys_chdir (f);
      break;
    case SYS_MKDIR:
      sys_mkdir (f);
      break;
    case SYS_READDIR:
      sys_readdir (f);
      break;
    case SYS_ISDIR:
      sys_isdir (f);
      break;
    case SYS_INUMBER:
      sys_inumber (f);
      break;
    default:
      break;
  }
}

/* Terminates Pintos by calling shutdown_power_off(). */
static void
sys_halt (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. */
static void
sys_exit (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  int status = *((int *)esp + ARG_1);
  f->eax = status;
  thread_current ()->exit = status;
  thread_exit ();
  NOT_REACHED ();

  err:
    error_exit ();
}

/* Runs the executable whose name is given. */
static void
sys_exec (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  if (!is_valid_string (*((char **)esp + ARG_1)))
    goto err;

  char *file = *((char **)esp + ARG_1);
  tid_t child_tid = process_execute (file);
  struct process_info *child_p = process_info_by_tid (thread_current (),
                                                      child_tid);

  if (child_tid == TID_ERROR)
  {
    f->eax = -1;
    goto err;
  }

  /* Wait on child to load executable. */
  sema_down (&child_p->load_sema);

  /* Check if child successfully loaded executable. */
  if (!child_p->loaded_executable)
    child_tid = -1;

  f->eax = child_tid;
  return;

  err:
    error_exit ();
}

/* Waits for a child process. */
static void
sys_wait (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  tid_t tid = *((tid_t *)esp + ARG_1);
  int status = process_wait (tid);
  f->eax = status;
  return;

  err:
    error_exit ();
}

/* Creates a new file. */
static void
sys_create (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 2))
    goto err;

  if (!is_valid_string (*((char **)esp + ARG_1)))
    goto err;

  char *filename = *((char **)esp + ARG_1);
  unsigned initial_size = *((unsigned *)esp + ARG_2);
  f->eax = filesys_create (filename, initial_size, false);
  return;
  
  err:
    error_exit ();
}

/* Deletes a file. */
static void
sys_remove (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  if (!is_valid_string (*((char **)esp + ARG_1)))
    goto err;

  char *filename = *((char **)esp + ARG_1);
  f->eax = filesys_remove (filename);
  return;

  err:
    error_exit ();
}

/* Opens a file. */
static void
sys_open (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  if (!is_valid_string (*((char **)esp + ARG_1)))
    goto err;

  char *name = *((char **)esp + ARG_1);
  struct file *file = filesys_open (name);

  if (file == NULL)
    {
      f->eax = -1;
      return;
    }
  else
    {
      struct file_info *fi = malloc (sizeof (struct file_info));
      fi->f = file;
      fi->fd = next_fd;
      fi->owner = thread_current ();
      lock_acquire (&file_list_lock);
      list_push_back (&file_list, &fi->elem);
      lock_release (&file_list_lock);

      next_fd++;
      f->eax = fi->fd;
      return;
    }

  err:
    error_exit ();
}

/* Returns the size, in bytes, of a file. */
static void
sys_filesize (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  int fd = *((int *)esp + ARG_1);
  struct file_info *fi = file_info_by_fd (fd);

  if (fi == NULL)
  {
    f->eax = -1;
    return;
  }
  else 
  {
    int length = file_length (fi->f);
    f->eax = length;
    return;
  }

  err:
    error_exit ();
}

/* Reads size bytes from the file open. */
static void
sys_read (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 3))
    goto err;

  if (!is_valid_buffer (*((void **)esp + ARG_2), *((unsigned *)esp + ARG_3)))
    goto err;

  int fd = *((int *)esp + ARG_1);
  void *buffer = *((void **)esp + ARG_2);
  unsigned size = *((unsigned *)esp + ARG_3);

  if (fd == 0)
  {
    f->eax = input_getc();
    return;
  }

  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = -1;
    return;
  }

  if (is_dir (file_get_inode (fi->f)))
  {
    f->eax = -1;
    return;
  }

  int bytes_read = file_read (fi->f, buffer, size);
  f->eax = bytes_read;

  return;

  err:
    error_exit ();
}

/* Writes size bytes from buffer to the open file fd. */ 
static void
sys_write (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 3))
    goto err;

  if (!is_valid_buffer (*((void **)esp + ARG_2), *((unsigned *)esp + ARG_3)))
    goto err;

  if (!is_valid_string (*((char **)esp + ARG_2)))
    goto err;

  int fd = *((int *)esp + ARG_1);
  const char *buffer = *((char **)esp + ARG_2);
  unsigned size = *((unsigned *)esp + ARG_3);

  if (fd == 1)
  {
    putbuf (buffer, size);
    f->eax = size;
    return;
  }

  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = -1;
    return;
  }

  if (is_dir (file_get_inode (fi->f)))
  {
    f->eax = -1;
    return;
  }

  int bytes_written = file_write (fi->f, buffer, size);
  f->eax = bytes_written;

  return;

  err:
    error_exit ();
}

/* Changes the next byte to be read or written in open file. */
static void
sys_seek (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 2))
    goto err;

  int fd = *((int *)esp + ARG_1);
  unsigned position = *((unsigned *)esp + ARG_2);
  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = -1;
    return;
  }
  struct file *file = fi->f;
  file_seek (file, position);
  return;

  err:
    error_exit ();
}

/* Returns the position of the next byte to be read or written in open file. */
static void
sys_tell (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;
  
  int fd = *((int *)esp + ARG_1);
  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = -1;
    return;
  }
  struct file *file = fi->f;
  file_tell (file);
  return;
  
  err:
    error_exit ();
}

/* Closes file descriptor. */
static void
sys_close (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  int fd = *((int *)esp + ARG_1);

  if (fd == 0 || fd == 1 || !is_valid_fd (fd) || !is_fd_owner(fd))
    goto err;

  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = -1;
    return;
  }

  file_close (fi->f);

  lock_acquire (&file_list_lock);
  list_remove (&fi->elem);
  lock_release (&file_list_lock);
  free (fi);
  return;

  err:
    error_exit ();
}

#ifdef VM
/* Map file open at fd into virtual pages starting at a
   specific virtual address. */
static void
sys_mmap (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 2))
    goto err;

  int fd = *((int *)esp + ARG_1);
  void *vaddr = *((void **)esp + ARG_2);

  if (fd == 0 || fd == 1 || !is_valid_fd (fd) || !is_fd_owner(fd)
      || pg_ofs (vaddr) != 0)
  {
    f->eax = ERROR;
    return;
  }

  struct file_info *fi = file_info_by_fd (fd);

  struct file *mapped_file = file_reopen (fi->f);
  int len_file = file_length (mapped_file);

  /* Check that file is not empty or NULL. */
  if (len_file == 0 || vaddr == NULL)
  {
    f->eax = ERROR;
    return;
  }

  /* Check that file does not overlap stack. */
  if (vaddr >= (PHYS_BASE - PGSIZE) && vaddr < PHYS_BASE)
  {
    f->eax = ERROR;
    return;
  }

  /* Check that the file does not overlap other virtual addresses. */
  void *overlap_vaddr = vaddr;
  while (overlap_vaddr < vaddr + len_file)
  {
    struct page *spte = page_find_page (overlap_vaddr);
    if (spte != NULL)
    {
      f->eax = -1;
      return;
    }
    overlap_vaddr += PGSIZE;
  }

  unsigned file_start = 0;
  void *curr_vaddr = vaddr;
  for (; curr_vaddr < vaddr + len_file; curr_vaddr += PGSIZE)
  {
    /* Initialize new SPTE. */
    struct page *new_page = malloc (sizeof (struct page));
    new_page->vaddr = curr_vaddr;
    new_page->writable = true;
    new_page->loaded = false;
    new_page->pinned = false;
    new_page->bytes_read = len_file > PGSIZE ? PGSIZE : len_file;
    new_page->file_start_ofs = file_start;
    new_page->executable = mapped_file;
    new_page->swap_index = -1;
    new_page->mapping = thread_current ()->mapid;
    page_add_page (new_page);

    file_start += new_page->bytes_read;
  }

  if (!mmap_file (vaddr, len_file))
  {
    f->eax = -1;
    return;
  }

  f->eax = thread_current ()->mapid;
  thread_current ()->mapid++;

  return;

  err:
    error_exit ();
}

/* Unmap the mapping designated by a prior call to mmap */
static void
sys_munmap (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  mapid_t mapping = *((mapid_t *)esp + ARG_1);
  munmap_file (mapping);

  return;

  err:
    error_exit ();
}
#endif

#ifdef FILESYS
/* Change the current working directory of the process. */
static void
sys_chdir (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  char *path = *((char **)esp + ARG_1);

  if (!is_valid_string (path))
    goto err;
  
  /* Find inode associated with dir path. */
  struct inode *inode = path_lookup (path);
  if (inode == NULL)
  {
    f->eax = false;
    return;
  }

  struct dir *dir = dir_open (inode);
  if (dir == NULL)
  {
    inode_close (inode);
    f->eax = false;
    return;
  }

  dir_close (thread_current ()->cwd);
  thread_current ()->cwd = dir_reopen (dir);

  f->eax = true;
  return;

  err:
    error_exit ();
}

/* Creates a directory. */
static void
sys_mkdir (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;

  char *dir = *((char **)esp + ARG_1);

  if (!is_valid_string (dir))
    goto err;
  
  f->eax = filesys_create (dir, 0, true);
  return;
  
  err:
    error_exit ();
}

/* Reads a directory entry from a file descriptor and puts the name into 
   the second parameter. */
static void
sys_readdir (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 2))
    goto err;
  
  int fd = *((int *)esp + ARG_1);
  char *name = *((char **)esp + ARG_2);

  if (!is_valid_string (name))
    goto err;
  
  /* Ensure that the file descriptor exists. */
  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = false;
    return;
  }

  /* Ensure that the given file is a directory. */
  struct file *dir_file = fi->f;
  if (dir_file == NULL || !is_dir (file_get_inode (dir_file)))
  {
    f->eax = false;
    return;
  }

  /* Get the directory struct from the file. */
  struct dir *dir = dir_open (file_get_inode (dir_file));
  if (dir == NULL)
  {
    f->eax = false;
    return;
  }

  /* Read the next directory entry (skipping . and ..). */
  f->eax = dir_readdir (dir, name);
  return;

  err:
    error_exit ();
}

/* Returns true if the given fd is a directory, false otherwise. */
static void
sys_isdir (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;
  
  int fd = *((int *)esp + ARG_1);

  /* Ensure that the file descriptor exists. */
  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = false;
    return;
  }

  f->eax = is_dir (file_get_inode (fi->f));
  return;

  err:
    error_exit ();
}

/* Returns the sector of the inode associated with fd. */
static void
sys_inumber (struct intr_frame *f)
{
  void *esp = f->esp;

  if (!validate_args (esp, 1))
    goto err;
  
  int fd = *((int *)esp + ARG_1);

  /* Ensure that the file descriptor exists. */
  struct file_info *fi = file_info_by_fd (fd);
  if (fi == NULL)
  {
    f->eax = -1;
    return;
  }

  f->eax = inode_get_inumber (file_get_inode (fi->f));
  return;

  err:
    error_exit ();
}
#endif

/* Checks if given buffer page is in user memory. */
static bool
is_valid_buffer (void *buf, unsigned size)
{
  struct page *spte = page_find_page (buf);
  if (spte != NULL)
    return true;

  void *curr_buf = buf;
  int bytes_left = size;

  while (bytes_left > 0)
  {
    if (!is_valid_ptr (curr_buf))
      return false;
    // Get next page
    unsigned bytes_till_page = PGSIZE - pg_ofs (curr_buf);
    curr_buf = (char *)curr_buf + bytes_till_page;
    bytes_left -= bytes_till_page;
  }
  return true;
}

/* Checks if given string is valid in user memory. */
static bool
is_valid_string (const char *str)
{
  struct page *spte = page_find_page ((void *)str);
  if (spte != NULL)
    return true;

  int cnt = 0;
  while (true)
  {
    if (!is_valid_ptr (str + cnt))
      return false;

    char cur_c = *(str + cnt);
    if (cur_c == '\0')
      break;
    
    cnt++;
  }

  return true;
}

/* Validate the argument addresses of a syscall. */
static bool
validate_args (void *ptr, int num_args)
{
  for (int i = 1; i <= num_args; i++)
  {
    void *arg = (int *)ptr + i;
    if (!is_valid_ptr (arg))
      return false;
  }
  return true;
}

/* Safe user memory access. Used to verify user pointer before dereference. */
static bool
is_valid_ptr (const void *ptr)
{
  if (ptr == NULL || ptr >= PHYS_BASE)
    return false;

  struct thread *t = thread_current ();
  for (int i = 0; i < PTR_SIZE; i++)
  {
    const char *cur_ptr = (char *)ptr + i;
    if (cur_ptr == NULL || !is_user_vaddr (cur_ptr)
        || pagedir_get_page (t->pagedir, cur_ptr) == NULL)
      return false;
  }
  return true;
}

/* Find file_info with the given fd. */
static struct file_info *
file_info_by_fd (int fd)
{
  struct list_elem *e;

  for (e = list_begin (&file_list);
       e != list_end (&file_list);
       e = list_next (e))
  {
    struct file_info *fi = list_entry (e, struct file_info, elem);
    if (fi->fd == fd) return fi;
  }

  return NULL;
}

/* Check if the current thread is the owner of the given fd. */
static bool
is_fd_owner (int fd)
{
  struct file_info *fi = file_info_by_fd (fd);
  return fi->owner == thread_current ();
}

/* Check if the given file descriptor is valid by searching fd list. */
static bool
is_valid_fd (int fd)
{
  struct list_elem *e;

  for (e = list_begin (&file_list);
       e != list_end (&file_list);
       e = list_next (e))
  {
    struct file_info *fi = list_entry (e, struct file_info, elem);
    if (fi->fd == fd) return true;
  }

  return false;
}

static void
error_exit (void)
{
  thread_current ()->exit = ERROR;
  thread_exit ();
}
