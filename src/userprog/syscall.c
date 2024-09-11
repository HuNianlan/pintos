#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "userprog/process.h"

#define STDIN 0
#define STDOUT 1

typedef int pid_t;

/* Store all the current opened file*/
static struct list open_file_list;
struct lock file_lock;

static void syscall_handler (struct intr_frame *);

static bool is_valid_pointer (const void *ptr);
static bool is_valid_buffer (const void *buffer, unsigned size);
static int allocate_fd (void);
static struct file_descripter *find_file_descripter (int fd);
static struct file *find_file (int fd);

static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
// void seek (int fd, unsigned position);
// unsigned tell (int fd);
static void close (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&open_file_list);
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  // printf ("system call!\n");
  // thread_exit ();
  uint32_t *esp = f->esp;
  if (!is_valid_pointer (esp) || !is_valid_pointer (esp + 1)
      || !is_valid_pointer (esp + 2) || !is_valid_pointer (esp + 3))
    {
      exit (-1);
      return;
    }
  else
    {
      int syscall_number = *esp;
      switch (syscall_number)
        {
        case SYS_HALT:
          halt ();
          break;
        case SYS_EXIT:
          exit (*(esp + 1));
          break;
        case SYS_EXEC:
          f->eax = exec ((char *)*(esp + 1));
          break;
        case SYS_WAIT:
          f->eax = wait (*(esp + 1));
          break;
        case SYS_CREATE:
          f->eax = create ((char *)*(esp + 1), *(esp + 2));
          break;
        // case SYS_REMOVE:
        //   f->eax = remove ((char *)*(esp + 1));
        //   break;
        case SYS_OPEN:
          f->eax = open ((char *)*(esp + 1));
          break;
        case SYS_FILESIZE:
          f->eax = filesize (*(esp + 1));
          break;
        case SYS_READ:
        // printf("ready to read\n");
          f->eax = read (*(esp + 1), (void *)*(esp + 2), *(esp + 3));
          break;
        case SYS_WRITE:
          f->eax = write (*(esp + 1), (void *)*(esp + 2), *(esp + 3));
          break;
        // case SYS_SEEK:
        //   seek (*(esp + 1), *(esp + 2));
        //   break;
        // case SYS_TELL:
        //   f->eax = tell (*(esp + 1));
        //   break;
        case SYS_CLOSE:
          close (*(esp + 1));
          break;
        default:
          exit (-1);
          break;
        }
    }
}

/* check ptr when accessing user memory */
bool
is_valid_pointer (const void *ptr)
{
  // printf("%d\n",pagedir_get_page (thread_current ()->pagedir, ptr));
  if (ptr == NULL || !is_user_vaddr (ptr)
      || pagedir_get_page (thread_current ()->pagedir, ptr) == NULL
      || ptr < (void *)0x08048000)
      // printf ("call creatce\n");
        return false;
  return true;
}

static void
halt (void)
{
  shutdown_power_off ();
}

static void
exit (int status)
{
  struct thread *t = thread_current ();
  // struct list_elem *l = list_begin (&t->fd_list);
  t->exit_status = status;
  // printf ("%s: exit(%d)\n", t->name, status);

  thread_exit ();
}

static int
write (int fd, const void *buffer, unsigned size)
{
  if (buffer == NULL || !is_valid_buffer(buffer, size))
  {
    exit(-1);
    return -1;
  }

  lock_acquire (&file_lock);

  if (fd == STDOUT) // writes to the console
    {
      putbuf ((char *)buffer, (size_t)size);
      lock_release (&file_lock);
      return size;
    }
  else if (fd == STDIN)
    {
      lock_release (&file_lock);
      return -1;
    }
  else
    {
      struct file *f = find_file (fd);

      if (f == NULL)
        {
          // printf ("file not found.\n");
          lock_release (&file_lock);
          return -1;
        }
      int status = file_write (f, buffer, size);
      lock_release (&file_lock);
      return status;
    }
  return -1;
}

/* Creates a new file called file initially initial_size bytes in size. Returns
 * true if successful, false otherwise. Creating a new file does not open it:
 * opening the new file is a separate operation which would require a open
 * system call.*/
static bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL || !is_valid_pointer(file))
  {
    exit(-1);
    return -1;
  }
  return filesys_create (file, initial_size);
}

static int
open (const char *file)
{
  if (file == NULL || !is_valid_pointer(file))
  {
    exit(-1);
    return -1;
  }
  // printf("file name: %s\n", file);

  struct file *f = filesys_open (file);

  if (f == NULL)
    {
      return -1;
    }
  lock_acquire (&file_lock);
  struct file_descripter *fd = malloc (sizeof (struct file_descripter));
  if (fd == NULL)
    {
      // printf("malloc failed\n");
      file_close (f);
      lock_release (&file_lock);
      return -1; // open fail
    }
  struct thread *cur = thread_current ();
  fd->fd = allocate_fd ();
  fd->file = f;
  fd->owner = thread_current ()->tid;

  list_push_back (&cur->fd_list, &fd->thread_elem);
  list_push_back (&open_file_list, &fd->elem);

  lock_release (&file_lock);
  return fd->fd;
}

void
close (int fd)
{
  struct file_descripter *fd_found = find_file_descripter (fd);

  if (fd_found == NULL || fd_found->owner != thread_current ()->tid)
    exit (-1);

  lock_acquire (&file_lock);
  list_remove (&fd_found->thread_elem);
  list_remove (&fd_found->elem);
  file_close (fd_found->file);
  lock_release (&file_lock);
  free (fd_found);
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of
 * bytes actually read (0 at end of file), or -1 if the file could not be read
 * (due to a condition other than end of file). Fd 0 reads from the keyboard
 * using input_getc().*/
static int
read (int fd, void *buffer, unsigned size)
{
  // printf("enter read\n");
  if (buffer == NULL || !is_valid_buffer(buffer, size))
  {
    exit(-1);
    return -1;
  }

  lock_acquire (&file_lock);

  if (fd == STDIN) // reads from the keyboard
    {
      for (unsigned i = 0; i < size; i++)
        *((char **)buffer)[i] = input_getc ();
      lock_release (&file_lock);
      return size;
    }
  else if (fd == STDOUT)
    {
      lock_release (&file_lock);
      return -1;
    }
  else // read from file
    {
      // printf ("file read \n");
      struct file *f = find_file (fd);

      if (f == NULL)
        {
          // printf ("file not found.\n");
          lock_release (&file_lock);
          return -1;
        }
      int status = file_read (f, buffer, size);
      lock_release (&file_lock);
      return status;
    }
}

static int filesize (int fd)
{
  struct file *f = find_file (fd);
  if (f == NULL)
    exit (-1);

  return file_length (f);
}

static pid_t
exec (const char *cmd_line)
{
  if (cmd_line == NULL || !is_valid_pointer (cmd_line))
    {
      exit (-1);
      return -1;
    }

  lock_acquire (&file_lock);
  int status = process_execute (cmd_line);
  lock_release (&file_lock);
  return status;
}

static int
wait (pid_t pid)
{
  struct thread *t = get_thread_by_tid (pid);
  if (t == NULL)
    {
      exit (-1);
    }
  return process_wait (pid);
}

bool
is_valid_buffer (const void *buffer, unsigned size)
{
  void *ptr = (void *)buffer;
  for (unsigned i = 0; i < size; i++)
    {
      if (!is_valid_pointer ((void *)ptr))
        return false;
      ptr++;
    }
  return true;
}

int
allocate_fd ()
{
  static int fd = 1;
  return ++fd;
}

static struct file_descripter *
find_file_descripter (int fd)
{
  struct thread *cur = thread_current ();
  for (struct list_elem *l = list_begin (&cur->fd_list);
       l != list_end (&cur->fd_list); l = list_next (l))
    {
      if (list_entry (l, struct file_descripter, thread_elem)->fd == fd)
        return list_entry (l, struct file_descripter, thread_elem);
    }
  return NULL;
}

static struct file *
find_file (int fd)
{
  struct file_descripter *fde = find_file_descripter (fd);
  if (fde == NULL)
    return NULL;
  return fde->file;
}

