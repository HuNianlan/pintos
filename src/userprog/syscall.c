#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

#define STDIN 0
#define STDOUT 1

typedef int pid_t;

static void syscall_handler (struct intr_frame *);

bool is_valid_pointer (void *ptr);
bool is_valid_buffer (const void *buffer, unsigned size);

// void halt (void);
void exit (int status);
// pid_t exec (const char *cmd_line);
// int wait (pid_t pid);
// bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
// int open (const char *file);
// int filesize (int fd);
// int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
// void seek (int fd, unsigned position);
// unsigned tell (int fd);
// void close (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
        // case SYS_HALT:
        //   halt ();
        //   break;
        case SYS_EXIT:
          exit (*(esp + 1));
          break;
        // case SYS_EXEC:
        //   f->eax = exec ((char *)*(esp + 1));
        //   break;
        // case SYS_WAIT:
        //   f->eax = wait (*(esp + 1));
        //   break;
        // case SYS_CREATE:
        //   f->eax = create ((char *)*(esp + 1), *(esp + 2));
        //   break;
        // case SYS_REMOVE:
        //   f->eax = remove ((char *)*(esp + 1));
        //   break;
        // case SYS_OPEN:
        //   f->eax = open ((char *)*(esp + 1));
        //   break;
        // case SYS_FILESIZE:
        //   f->eax = filesize (*(esp + 1));
        //   break;
        // case SYS_READ:
        //   f->eax = read (*(esp + 1), (void *)*(esp + 2), *(esp + 3));
        //   break;
        case SYS_WRITE:
          f->eax = write (*(esp + 1), (void *)*(esp + 2), *(esp + 3));
          break;
        // case SYS_SEEK:
        //   seek (*(esp + 1), *(esp + 2));
        //   break;
        // case SYS_TELL:
        //   f->eax = tell (*(esp + 1));
        //   break;
        // case SYS_CLOSE:
        //   close (*(esp + 1));
        //   break;
        default:
          exit (-1);
          break;
        }
    }
}

/* check ptr when accessing user memory */
bool
is_valid_pointer (void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr)
      || pagedir_get_page (thread_current ()->pagedir, ptr) == NULL
      || ptr < (void *)0x08048000)
    return false;
  return true;
}

void
exit (int status)
{
  struct thread *t = thread_current ();
  // struct list_elem *l = list_begin (&t->fd_list);
  t->exit_status = status;
  printf ("%s: exit(%d)\n", t->name, status);

  thread_exit ();
}

int
write (int fd, const void *buffer, unsigned size)
{
  if (!is_valid_buffer (buffer, size))
    exit (-1);

  if (fd == STDOUT)
    {
      putbuf ((char *)buffer, (size_t)size);
      // lock_release (&file_lock);
      return size;
    }
  else if (fd == STDIN)
    {
      // lock_release (&file_lock);
      return -1;
    }
    return -1;
}

bool
is_valid_buffer (const void *buffer, unsigned size)
{
  void *ptr = (void*)buffer;
  for (unsigned i = 0; i < size; i++)
    {
      if (!is_valid_pointer ((void *)ptr))
        return false;
      ptr++;
    }
  return true;
}
