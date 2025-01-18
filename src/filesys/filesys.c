#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"

#define PATH_MAX_LEN 100

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
struct dir * get_directory_from_path (const char *raw_path, char *file_name);

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
  cache_init();

  if (format) 
    do_format ();

  free_map_open ();

  thread_current ()->dir = dir_open_root ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_close();
  free_map_close ();
}


/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. 
   
   create a directory if is_dir with the given path*/
bool
filesys_create (const char *name, off_t initial_size, bool is_dir)
{
  block_sector_t inode_sector = 0;
  char file_name[PATH_MAX_LEN];
  struct dir *dir = get_directory_from_path (name, file_name);

  bool success;
  if (is_dir)
    success = (dir != NULL && free_map_allocate (1, &inode_sector)
               && dir_create (inode_sector, 16) // 16 from create root dir in do_format
               && dir_add (dir, file_name, inode_sector));
  else
    success = (dir != NULL && free_map_allocate (1, &inode_sector)
               && inode_create (inode_sector, initial_size, is_dir)
               && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  if (is_dir && success)
    {
      // treat . and .. as file names, and store their inode sectors in this dir
      struct dir *new_dir = dir_open (inode_open (inode_sector));
      dir_add (new_dir, ".", inode_sector);
      dir_add (new_dir, "..", inode_get_inumber (dir_get_inode (dir)));
      dir_close (new_dir);
    }
  dir_close (dir);
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
  char file_name[PATH_MAX_LEN];
  struct dir *dir = get_directory_from_path (name, file_name);

  struct inode *inode = NULL;
  if (dir != NULL)
    dir_lookup (dir, file_name, &inode);
  dir_close (dir);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char file_name[PATH_MAX_LEN];
  struct dir *dir = get_directory_from_path (name, file_name);

  struct inode *inode;
  dir_lookup (dir, file_name, &inode);

  struct dir *cur_dir = dir_open (inode);
  char temp[PATH_MAX_LEN];

  bool success = false;
  // cannot remove a not empty parent dir
  if (inode_is_dir (inode) && (cur_dir == NULL || dir_readdir (cur_dir, temp)))
    goto done;

  success = dir != NULL && dir_remove (dir, file_name);

done:
  dir_close (dir);
  if (cur_dir)
    dir_close (cur_dir);
  return success;
}



bool filesys_chdir (const char *dir_name)
{
  char path[PATH_MAX_LEN];
  strlcpy (path, dir_name, PATH_MAX_LEN);
  strlcat (path, "/0", PATH_MAX_LEN);

  char name[PATH_MAX_LEN];
  struct dir *dir = get_directory_from_path (path, name);
  if (!dir)
    return false;
  dir_close (thread_current ()->dir);
  thread_current ()->dir = dir;
  return true;
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");

  // for all persistence tests
  struct dir *root = dir_open_root ();
  dir_add (root, ".", ROOT_DIR_SECTOR);
  dir_add (root, "..", ROOT_DIR_SECTOR);  
  dir_close (root);

  free_map_close ();
  printf ("done.\n");
}

struct dir *
get_directory_from_path (const char *raw_path, char *file_name)
{
  if (thread_current ()->dir_removed || !raw_path || !file_name || strlen (raw_path) == 0)
    return NULL;

  struct dir *dir = NULL;

  char *path = (char *)malloc (sizeof (char) * (strlen (raw_path) + 1));
  if (!path)
    return NULL;
  memcpy (path, raw_path, sizeof (char) * (strlen (raw_path) + 1));

  /* absolute path start with "/" */
  if (path[0] == '/')
    dir = dir_open_root ();
  else /* otherwise, relative path. open current directory*/
    dir = dir_reopen (thread_current ()->dir);

  if (!inode_is_dir (dir_get_inode (dir)))
    {
      free (path);
      return NULL;
    }

  char *save_ptr;
  char *token = strtok_r (path, "/", &save_ptr);

  for (char *next_token = strtok_r (NULL, "/", &save_ptr); token && next_token;
       token = next_token, next_token = strtok_r (NULL, "/", &save_ptr))
    {
      struct inode *inode = NULL;
      if (!dir_lookup (dir, token, &inode) || !inode_is_dir (inode))
        {
          dir_close (dir);
          free (path);
          return NULL;
        }
      dir_close (dir);
      dir = dir_open (inode);
    }

  if (token != NULL)
    strlcpy (file_name, token, PATH_MAX_LEN);
  else // for persistent
    strlcpy (file_name, ".", PATH_MAX_LEN);

  return dir;
}
