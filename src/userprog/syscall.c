#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#define STDIN 0
#define STDOUT 1

static void syscall_handler (struct intr_frame *);

static bool usr_ptr_check(void *);
static struct file *find_file (int);

static void halt (void);
static void exit (int status);
static pid_t exec (const char *file);
static int wait (pid_t);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned length);
static int write (int fd, const void *buffer, unsigned length);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

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
  uint32_t* esp = f->esp;

  if (!usr_ptr_check (esp) || !usr_ptr_check (esp + 1) ||
      !usr_ptr_check (esp + 2) || !usr_ptr_check (esp + 3))
    exit (-1);
  else{
    int number = *esp;
    switch (number)
    {
    case SYS_HALT:
      halt ();
      break;
    case SYS_EXIT:
      exit (*(esp + 1));
      break;
    case SYS_EXEC:
      f->eax = exec ((char *) *(esp + 1));
      break;
    case SYS_WAIT:
      f->eax = wait (*(esp + 1));
      break;
    case SYS_CREATE:
      f->eax = create ((char *) *(esp + 1), *(esp + 2));
      break;
    case SYS_REMOVE:
      f->eax = remove ((char *) *(esp + 1));
      break;
    case SYS_OPEN:
      f->eax = open ((char *) *(esp + 1));
      break;
    case SYS_FILESIZE:
      f->eax = filesize (*(esp + 1));
      break;
    case SYS_READ:
      f->eax = read (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
      break;
    case SYS_WRITE:
      f->eax = write (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
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
    }
  }
}


void halt (void){
  shutdown_power_off();
}


void exit (int status){
  struct thread* cur= thread_current();
  cur->status_exit = status;
  thread_exit();

}


pid_t exec (const char *cmdline){
  int pid = process_execute(cmdline);
  return pid;
}

int wait (pid_t pid){
  process_wait(pid);
};


bool create (const char *file, unsigned initial_size){  
  return filesys_create (file, initial_size);}


bool remove (const char *file){
  return filesys_remove (file);
}
int open (const char *file){}

int filesize (int fd){ 

  return file_length (find_file (fd));}

int read (int fd, void *buffer, unsigned length){}

int write (int fd, const void *buffer, unsigned length){
  if (fd == STDOUT)
    {
      putbuf ((char *)buffer, (size_t)length);
      return length;
    }
    return -1;}

void seek (int fd, unsigned position){}
unsigned tell (int fd){}
void close (int fd){}


struct file *find_file (int fd)
{
  // for (struct list_elem *l = list_begin (&open_file_list);
  //      l != list_end (&open_file_list); l = list_next (l))
  //   {
  //     if (list_entry (l, struct file_descripter, elem)->fd == fd)
  //       return list_entry (l, struct file_descripter, elem)->file;
  //   }
  // return NULL;
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
int result;
asm ("movl $1f, %0; movzbl %1, %0; 1:"
: "=&a" (result) : "m" (*uaddr));
return result;
}

bool usr_ptr_check(void *ptr)
{
  if(!is_user_vaddr(ptr)) return false;
  // if ((pagedir_get_page (thread_current ()->pagedir, ptr) == NULL))
  //   return false;
  if(get_user(ptr) == -1) return false;
  return true;
}