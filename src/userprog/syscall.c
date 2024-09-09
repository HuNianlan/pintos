#include "userprog/syscall.h"
//#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"

#define STDIN 0
#define STDOUT 1

typedef int pid_t;

/* Store all the current opened file*/
static struct list open_file_list;
struct lock file_lock;


/* System Calls for pj2*/

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

static void syscall_handler (struct intr_frame *);
bool is_valid_pointer(void* ptr);
static struct file *find_file (int fd);
static struct file_descripter *find_file_descripter (int fd);
int allocate_fd (void);

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

  // 把所有后面可能用到的ptr都检查是否valid
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
        case SYS_REMOVE:
          f->eax = remove ((char *)*(esp + 1));
          break;
        case SYS_OPEN:
          f->eax = open ((char *)*(esp + 1));
          break;
        case SYS_FILESIZE:
          f->eax = filesize (*(esp + 1));
          break;
        case SYS_READ:
          f->eax = read (*(esp + 1), (void *)*(esp + 2), *(esp + 3));
          break;
        case SYS_WRITE:
          f->eax = write (*(esp + 1), (void *)*(esp + 2), *(esp + 3));
          break;
        case SYS_SEEK:
          seek (*(esp + 1), *(esp + 2));
          break;
        case SYS_TELL:
          f->eax = tell (*(esp + 1));
          break;
        case SYS_CLOSE:
          close (*(esp + 1));
          break;
        default:
          exit(-1);
          break;
        }
    }
}

/* The kernel must be very careful about doing so, because the user can
 * pass a null pointer, a pointer to unmapped virtual memory, or a pointer
 * to kernel virtual address space (above PHYS_BASE). All of these types of
 * invalid pointers must be rejected without harm to the kernel or other
 * running processes, by terminating the offending process and freeing
 * its resources.
 */
bool
is_valid_pointer (void *ptr)
{
  if ((!is_user_vaddr (ptr))
      || (pagedir_get_page (thread_current ()->pagedir, ptr) == NULL))
    return false;
  return true;
}

/* If the corresponding file to fd is in open_file_list, return the file ptr;
 * else, return NULL. */
static struct file *
find_file (int fd)
{
  struct file_descripter *fde = find_file_descripter (fd);
  if (fde == NULL)
    return NULL;
  return fde->file;
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

int
allocate_fd ()
{
  static int fd = 1;
  return ++fd;
}

void
halt (void)
{
  shutdown_power_off ();
}

/* Should close all files
  and print message "name of process:exit(status)"*/
void
exit (int status)
{
  struct thread *t = thread_current ();
  struct list_elem *l = list_begin (&t->fd_list);
  t->exit_status = status;
//  printf ("%s:exit(%d)\n", t->name, status);

  while (!list_empty (&t->fd_list))
    {
      close (list_entry (l, struct file_descripter, thread_elem)->fd);
    }
  thread_exit ();
}

pid_t
exec (const char *cmd_line)
{
  lock_acquire (&file_lock);
  int status = process_execute (cmd_line);
  lock_release (&file_lock);
  return status;
}

int
wait (pid_t pid)
{
  return process_wait (pid);
}

/* Creates a new file called file initially initial_size bytes in size. Returns
 * true if successful, false otherwise. Creating a new file does not open it:
 * opening the new file is a separate operation which would require a open
 * system call.*/
bool
create (const char *file, unsigned initial_size)
{
  // printf ("call create %s\n", file);
  return filesys_create (file, initial_size);
}

/* Deletes the file called file. Returns true if successful, false otherwise. A
 * file may be removed regardless of whether it is open or closed, and removing
 * an open file does not close it.*/
bool
remove (const char *file)
{
  // printf ("call remove file %s\n", file);
  return filesys_remove (file);
}

int
open (const char *file)
{
  lock_acquire (&file_lock);
  struct file *f = filesys_open (file);

  if (f == NULL)
    return -1;
  // 要加file descripter
  struct file_descripter *fde = malloc (sizeof (struct file_descripter));
  if (fde == NULL)
    {
      file_close (f);
      lock_release (&file_lock);
      return -1; // open fail
    }
  struct thread *cur = thread_current ();
  fde->fd = allocate_fd ();
  fde->file = f;
  fde->owner = thread_current ()->tid;

  list_push_back (&cur->fd_list, &fde->thread_elem);
  list_push_back (&open_file_list, &fde->elem);
  // 这里是因为，如果要用双向链表，由于类型必须是list_element，
  // 只能创造一个没啥用的elem在struct file_descripter里，绕一个弯

  lock_release (&file_lock);
  return fde->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
int
filesize (int fd)
{
  struct file *f = find_file (fd);
  if (f == NULL)
    exit (-1);

  return file_length (f);
}

// 我也不知道为啥。。
int
read (int fd, void *buffer, unsigned size)
{
  lock_acquire (&file_lock);

  if (fd == STDIN)
    {
      for (unsigned int i = 0; i < size; i++)
          *((char **)buffer)[i] = input_getc ();
      lock_release (&file_lock);
      return size;
    }
  else
    {
      struct file *f = find_file (fd);

      if (f == NULL)
          return -1;
      int status = file_read (f, buffer, size);
      lock_release (&file_lock);
      return status;
    }
}

int
write (int fd, const void *buffer, unsigned size)
{
  lock_acquire (&file_lock);
  if (fd == STDOUT)
    {
      putbuf ((char *)buffer, (size_t)size);
      lock_release (&file_lock);
      return (int)size;
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
        exit (-1);
      lock_release (&file_lock);
      return (int)file_write (f, buffer, size);
    }
}

void
seek (int fd, unsigned position)
{
  struct file *f = find_file (fd);
  if (f == NULL)
    exit (-1);

  file_seek (f, position);
}

unsigned
tell (int fd)
{
  struct file *f = find_file (fd);
  if (f == NULL)
    exit (-1);

  return file_tell (f);
}

void
close (int fd)
{
  struct file_descripter *f = find_file_descripter (fd);
  lock_acquire (&file_lock);

  if (f == NULL || f->owner != thread_current ()->tid)
    exit (-1);

  list_remove (&f->thread_elem);
  list_remove (&f->elem);
  file_close (f->file);
  lock_release (&file_lock);
  free (f);
}
