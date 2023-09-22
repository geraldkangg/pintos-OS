#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
static bool split_path (const char *, struct dir **, char **);
static bool cwd_is_removed (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  /* Initialize the buffer cache. */
  buffer_cache_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  if (cwd_is_removed ())
    return false;
  
  char *file_name;
  struct dir *dir;
  bool success = split_path (name, &dir, &file_name);
  if (!success)
    return false;
  
  block_sector_t inode_sector = 0;

  success = dir != NULL && free_map_allocate (1, &inode_sector);

  if (isdir)
  {
    block_sector_t parent_sector = inode_get_inumber (dir_get_inode (dir));
    success = dir_create (inode_sector, 16, parent_sector);
  }
  else
  {
    success = inode_create (inode_sector, initial_size, isdir);
  }

  if (!success && inode_sector != 0) 
  {
    free_map_release (inode_sector, 1);
    return false;
  }

  success = dir_add (dir, file_name, inode_sector);
  dir_close (dir);
  free (file_name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  if (cwd_is_removed ())
    return NULL;

  /* Can't open empty file. */
  if (strlen (name) == 0)
    return NULL;

  char *path = malloc (strlen (name) + 1);
  strlcpy (path, name, strlen (name) + 1);
  struct inode *inode = path_lookup (path);
  if (inode == NULL)
    return NULL;
  struct file *file = file_open (inode);
  free (path);
  return file;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  if (cwd_is_removed ())
    return false;

  char *path = malloc (strlen (name) + 1);
  strlcpy (path, name, strlen (name) + 1);
  struct inode *inode = path_lookup (path);
  if (inode == NULL)
    return false;
  
  /* Can't remove the root directory. */
  if (inode_get_inumber (inode) == ROOT_DIR_SECTOR)
    return false;

  if (is_dir (inode)) {
    char dirent_name[NAME_MAX + 1];
    struct dir *dir = dir_open (inode);
    /* Check if the directory contains any entries. */
    if (dir_readdir (dir, dirent_name))
    {
      dir_close (dir);
      return false;
    }
    dir_close (dir);
  }

  /* Split the path into directory and file. */
  char *file_name;
  struct dir *parent_dir;
  if (!split_path (name, &parent_dir, &file_name))
    return false;
  
  bool success = parent_dir != NULL && dir_remove (parent_dir, file_name);
  dir_close (parent_dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/* Split a given path into directory and file name. */
static bool
split_path (const char *path, struct dir **dir, char **name)
{
  /* Create a path copy to use. */
  char *cp = malloc (strlen (path) + 1);
  if (cp == NULL)
    return false;
  strlcpy (cp, path, strlen (path) + 1);

  char *last_slash = strrchr (cp, '/');
  /* No slash was found, entire path is file name. */
  if (last_slash == NULL)
  {
    if (thread_current ()->cwd == NULL)
      *dir = dir_open_root ();
    else
      *dir = dir_reopen (thread_current ()->cwd);
    *name = cp;
  }
  /* Slash is found, separate directory and new file name. */
  else
  {
    struct inode *dir_inode;
    /* If absolute path, open root directory. */
    if (strcmp (last_slash, cp) == 0)
    {
      dir_inode = inode_open (ROOT_DIR_SECTOR);
    }
    else
    {
      *last_slash = '\0';
      dir_inode = path_lookup (cp);
    }
    /* Return false if path is invalid. */
    if (dir_inode == NULL)
    {
      free (cp);
      return false;
    }
    *dir = dir_open (dir_inode);
    if (dir == NULL)
    {
      inode_close (dir_inode);
      free (cp);
      return false;
    }

    char *slashed_name = last_slash + 1;
    *name = malloc (strlen (slashed_name) + 1);
    if (*name == NULL)
    {
      free (cp);
      return false;
    }
    strlcpy (*name, slashed_name, strlen (slashed_name) + 1);
    free (cp);
  }

  return true;
}

/* Return whether or not the inode of the CWD is removed. */
static bool
cwd_is_removed (void)
{
  if (thread_current ()->cwd == NULL)
    return false;

  /* If the CWD is removed, set the thread's cwd to NULL. */
  return is_removed (dir_get_inode (thread_current ()->cwd));
}
