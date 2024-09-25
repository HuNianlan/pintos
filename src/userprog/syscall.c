#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

typedef int pid_t;

/* Store all the current opened file*/
struct lock file_lock;

static void syscall_handler (struct intr_frame *);

static bool is_valid_pointer (const void *ptr);
static bool is_valid_buffer (const void *buffer, unsigned size);
static int allocate_fd (void);
static struct file_descripter *find_file_descripter (int fd);
static struct file *find_file (int fd);

static void halt (void);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static mapid_t mmap (int, void *);
static void munmap (mapid_t);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
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
        case SYS_MMAP:
          f->eax = mmap(*(esp+1),(void *)*(esp+2));
          break;
        case SYS_MUNMAP:
          munmap (*(esp + 1));
          break;

        default:
          exit (-1);
          break;
        }
    }
}

/* Terminates Pintos by calling shutdown_power_off().*/
static void
halt (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. If the
 * process's parent waits for it (see below), this is the status that will be
 * returned. Conventionally, a status of 0 indicates success and nonzero values
 * indicate errors.*/
void
exit (int status)
{
  if(lock_held_by_current_thread(&file_lock))
    lock_release(&file_lock);
  struct thread *t = thread_current ();
  t->exit_status = status;
  struct list_elem *l;
  while (!list_empty (&t->fd_list))
    {
      l = list_begin (&t->fd_list);
      close (list_entry (l, struct file_descripter, thread_elem)->fd);
    }

  thread_exit ();
}

/**
 * Writes a specified number of bytes from the buffer to the open file
 * descriptor.
 *
 * @param fd      The file descriptor to which data will be written.
 * @param buffer  The source buffer from which data is to be written.
 * @param size    The number of bytes to write from the buffer.
 *
 * @return        Returns the number of bytes actually written, which may be
 *                less than the requested size if some bytes could not be
 *                written. In the event of an error, returns -1.
 *
 * Description:
 *
 * - If the file descriptor is 1 (STDOUT_FILENO), the data will be written to
 * the console using a single call to putbuf(), unless the size exceeds a few
 *   hundred bytes, in which case it may be broken up.
 *
 * - Writing to file descriptor 0 (STDIN_FILENO) is not allowed, and the
 * function will return -1 in that case.
 *
 * - Writing past the end of a file does not extend the file in the basic file
 *   system. The function will attempt to write as many bytes as possible up to
 *   the end-of-file, returning the actual number written, or 0 if no bytes
 *   could be written at all.
 *
 * - The function acquires a file lock before writing and releases it afterward
 *   to ensure thread safety.
 */
static int
write (int fd, const void *buffer, unsigned size)
{
  if (buffer == NULL || !is_valid_buffer (buffer, size))
    {
      exit (-1);
    }

  lock_acquire (&file_lock);

  // Case 1: Writes to the console
  if (fd == STDOUT_FILENO)
    {
      putbuf ((char *)buffer, (size_t)size);
      lock_release (&file_lock);
      return size;
    }

  // Case 2: Trying to write to the input stream is invalid
  else if (fd == STDIN_FILENO)
    {
      lock_release (&file_lock);
      return -1;
    }

  // Case 3: Writing to a regular file
  else
    {
      struct file *f = find_file (fd);
      if (f == NULL)
        {
          lock_release (&file_lock);
          return -1;
        }

      int status = file_write (f, buffer, size);
      lock_release (&file_lock);
      return status;
    }
  return -1;
}

/**
 * Creates a new file with the specified name and an initial size.
 *
 * @param file          The name of the file to be created.
 * @param initial_size  The initial size of the file in bytes.
 *
 * @return              Returns true if the file was successfully created,
 *                      false otherwise.
 *
 * Description:
 *
 * - This function creates a new file but does not open it. Opening the file
 *   requires a separate operation, typically via the `open` system call.
 *
 * - If the provided file name is NULL or the pointer is invalid, the process
 *   will terminate with an exit code of -1.
 */
static bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL || !is_valid_pointer (file))
    {
      exit (-1);
    }
  return filesys_create (file, initial_size);
}

/**
 * Opens the file with the given name and returns a file descriptor (fd).
 *
 * @param file  The name of the file to be opened.
 *
 * @return      Returns a non-negative integer file descriptor id if
 * successful, or -1 if the file could not be opened.
 *
 * Description:
 *
 * - File descriptors 0 (STDIN_FILENO) and 1 (STDOUT_FILENO) are reserved for
 *   the console. This function will never return these reserved descriptors.
 *
 * - Each process maintains its own independent set of file descriptors.
 *
 * - When a file is opened multiple times (either by the same or different
 *   processes), a new file descriptor is allocated for each open. These
 *   descriptors are closed independently and do not share a file position.
 *
 * - If the provided file name is NULL or the pointer is invalid, the process
 *   will terminate with an exit code of -1.
 */
static int
open (const char *file)
{
  if (file == NULL || !is_valid_pointer (file))
    {
      exit (-1);
    }

  lock_acquire (&file_lock); // must acquire lock before filesys_open

  struct file *f = filesys_open (file);
  if (f == NULL)
    {
      lock_release (&file_lock);
      return -1;
    }

  struct file_descripter *fd = malloc (sizeof (struct file_descripter));
  if (fd == NULL)
    {
      file_close (f);
      lock_release (&file_lock);
      return -1;
    }

  struct thread *cur = thread_current ();
  fd->fd = allocate_fd ();
  fd->file = f;

  list_push_back (&cur->fd_list, &fd->thread_elem);

  lock_release (&file_lock);
  // printf("open complete\n");
  return fd->fd;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
 * closes all its open file descriptors, as if by calling this function for
 * each one.*/
void
close (int fd)
{
  struct file_descripter *fd_found = find_file_descripter (fd);

  if (fd_found == NULL)
    {
      exit (-1);
    }

  lock_acquire (&file_lock);
  list_remove (&fd_found->thread_elem);
  file_close (fd_found->file);
  lock_release (&file_lock);
  free (fd_found);
}

/**
 * Reads a specified number of bytes from the file associated with the given
 * file descriptor (fd) into the buffer.
 *
 * @param fd      The file descriptor to read from.
 * @param buffer  The buffer where the data will be stored.
 * @param size    The number of bytes to read from the file.
 *
 * @return        Returns the number of bytes actually read. If the end of the
 * file is reached, 0 is returned. Returns -1 if the file could not be read
 * (for reasons other than end-of-file).
 *
 * Description:
 *
 * - If fd is 0 (STDIN_FILENO), the function reads from the keyboard using
 * `input_getc()`.
 *
 * - If fd is 1 (STDOUT_FILENO), the function returns -1 as reading from the
 * output stream is not allowed.
 *
 * - For other file descriptors, the function attempts to read from the
 * corresponding file.
 *
 * - If the buffer pointer is invalid, the process will terminate with an exit
 * code of -1.
 */
static int
read (int fd, void *buffer, unsigned size)
{
  if (buffer == NULL || !is_valid_buffer (buffer, size))
    {
      exit (-1);
    }
  // printf("%d\n",fd);
  lock_acquire (&file_lock);
  // Case 1: Reading from the keyboard (file descriptor 0)
  if (fd == STDIN_FILENO)
    {
      for (unsigned i = 0; i < size; i++)
        *((char **)buffer)[i] = input_getc ();
      lock_release (&file_lock);
      return size;
    }

  // Case 2: Trying to read from the output stream is invalid
  else if (fd == STDOUT_FILENO)
    {
      lock_release (&file_lock);
      return -1;
    }

  // Case 3: Reading from a regular file
  else
    {
      struct file *f = find_file (fd);

      if (f == NULL)
        {
          lock_release (&file_lock);
          return -1;
        }
      int status = file_read (f, buffer, size);
      lock_release (&file_lock);
      return status;
    }
}

/* Returns the size, in bytes, of the file open as fd.*/
static int
filesize (int fd)
{
  struct file *f = find_file (fd);
  if (f == NULL)
    exit (-1);

  return file_length (f);
}

/**
 * Changes the next byte to be read or written in the open file associated with
 * the given file descriptor (fd) to the specified position.
 *
 * @param fd        The file descriptor of the open file.
 * @param position  The new position in the file, expressed in bytes from the
 *                  beginning of the file. A position of 0 indicates the start
 * of the file.
 *
 * Description:
 *
 * - A seek operation moves the file pointer to the specified position,
 * allowing subsequent read or write operations to occur at that location.
 *
 * - Seeking past the current end of the file is not considered an error. In
 * that case:
 *
 *   - A later read operation will return 0 bytes, indicating the end of the
 * file.
 *
 *   - A later write operation will extend the file, filling any unwritten gap
 * with zeros.
 *
 * - In Pintos, however, files have a fixed length until project 4 is
 * implemented, meaning that attempts to write past the end of a file will
 * return an error.
 *
 * - The seek operation relies on the file system's built-in mechanisms and
 * does not require special handling in the system call implementation.
 *
 * - If the file associated with the given fd is not found, the process will
 *   terminate with an exit code of -1.
 */
static void
seek (int fd, unsigned position)
{
  struct file *f = find_file (fd);
  if (f == NULL)
    exit (-1);

  file_seek (f, position); // Move the file pointer to the specified position
}

/* Returns the position of the next byte to be read or written in open file fd,
 * expressed in bytes from the beginning of the file.*/
static unsigned
tell (int fd)
{
  struct file *f = find_file (fd);
  if (f == NULL)
    exit (-1);

  return file_tell (f);
}

/**
 * Executes a new process from the given command line, passing any arguments,
 * and returns the process's program ID (pid).
 *
 * @param cmd_line  A string containing the name of the executable and any
 *                  arguments to be passed to the new process.
 *
 * @return          Returns the new process's pid if the process is
 * successfully started. Returns -1 if the executable cannot be loaded or run.
 *
 * Description:
 * - This function creates and runs a new process using the specified
 * executable and arguments. It returns the process ID (pid) of the new
 * process.
 * - If the executable cannot be loaded or the process cannot start, the
 * function returns -1, which is an invalid pid.
 * - The parent process must wait for the child process to successfully load
 * the executable before returning from `exec()`. This requires synchronization
 *   mechanisms to ensure that the child process has completed loading.
 * - If the `cmd_line` pointer is invalid or NULL, the process will terminate
 * with an exit code of -1.
 *
 * - The function acquires a file lock during the execution of the process to
 *   ensure thread safety and releases it afterward.
 */
static pid_t
exec (const char *cmd_line)
{
  if (cmd_line == NULL || !is_valid_pointer (cmd_line))
    {
      exit (-1);
    }

  lock_acquire (&file_lock);
  int status = process_execute (cmd_line);
  lock_release (&file_lock);
  return status;
}

/**
 * Waits for a child process with the specified process ID (pid) to terminate
 * and retrieves the child's exit status.
 *
 * @param pid  The process ID of the child process to wait for.
 *
 * @return     Returns the exit status of the child process if it called
 * `exit()`. If the child process was terminated by the kernel or did not call
 *             `exit()`, the function returns -1.
 *             If `pid` is not a valid child of the calling process, or if the
 * process has already waited for this child, the function also returns -1.
 *
 * Description:
 *
 * - The function blocks the calling process until the child process `pid` has
 *   terminated. After the child process exits, the function returns its exit
 * status.
 *
 * - If `pid` refers to a process that was terminated by the kernel (e.g.,
 * killed due to an exception), the function returns -1.
 *
 * - If `pid` is not a direct child of the calling process (i.e., the process
 * did not receive `pid` as the return value from a successful call to
 * `exec()`), the function returns -1. A parent cannot wait on a grandchild or
 * orphaned process.
 *
 * - The function ensures that each child process can only be waited on once.
 *   If the parent process has already waited for this child process, calling
 *   `wait()` again will fail and return -1.
 *
 * - The kernel must support waiting for child processes that have already
 * terminated before the parent calls `wait()`. In such cases, the function
 * should still allow the parent to retrieve the child's exit status.
 *
 * - All resources associated with the child process must be freed regardless
 * of whether the parent waits for the child or not. The design ensures that
 * all processes' resources are released appropriately.
 *
 * - The function relies on `process_wait()` to handle the detailed waiting
 *   behavior. Pintos ensures that the system does not terminate until the
 * initial process exits.
 */
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

/* Deletes the file called file. Returns true if successful, false otherwise. A
 * file may be removed regardless of whether it is open or closed, and removing
 * an open file does not close it. */
static bool
remove (const char *file)
{
  return filesys_remove (file);
}

/* check validtion of ptr when accessing user memory */
bool
is_valid_pointer (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr)
      ||find_vme(pg_round_down(ptr)) == NULL
      // || pagedir_get_page (thread_current ()->pagedir, ptr) == NULL
      || ptr < (void *)0x08048000)
    return false;
  return true;
}

/* check validtion of buffer when accessing user memory */
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

/* Find the current thread 's corresponding file_descripter to the file descripter id*/
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

/* Find the current thread 's corresponding file to the file descripter id*/
static struct file *
find_file (int fd)
{
  struct file_descripter *fde = find_file_descripter (fd);
  if (fde == NULL)
    return NULL;
  return fde->file;
}


static mapid_t mmap (int fd, void *addr){
  if (addr == NULL || (pg_ofs (addr) != 0)||fd == 0 || fd == 1)
    return -1;

  struct thread *t = thread_current ();

  struct file_descripter *fde = find_file_descripter (fd);
  if (fde == NULL) return -1;
  
  
  int32_t len = file_length (fde->file);
  if (len <= 0) return -1;
  
  int ofs = 0;

  while (ofs < len){
    /*overlap with existing page*/
    if (find_vme (addr + ofs)|| pagedir_get_page (t->pagedir, addr + ofs)) return -1;	  
      ofs += PGSIZE;
  }

  lock_acquire (&file_lock);
  struct file* file = file_reopen(fde->file);
  if(file == NULL){
    lock_release(&file_lock);
    return -1;
  }

  struct mmap_file *mmap_file = malloc(sizeof(struct mmap_file));
  
    if (mmap_file == NULL) {
        file_close(file);
        lock_release (&file_lock);
        return -1;
    }

    mmap_file->id = t->next_mapid++;
    mmap_file->file = file;
    list_init(&mmap_file->vm_entries);
    // mmap_file->vaddr = addr;
    list_push_back(&t->mmap_list, &mmap_file->elem);


  for (int offset = 0; offset < len; offset += PGSIZE) {
      size_t read_bytes = len - offset < PGSIZE ? len - offset : PGSIZE;
      size_t zero_bytes = PGSIZE - read_bytes;

      struct vm_entry *vme = malloc(sizeof(struct vm_entry));
      if (vme == NULL) {
          munmap(mmap_file->id);  // Roll back changes
          lock_release (&file_lock);
          return -1;
      }
      
      vme->type = VM_FILE;
      vme->vaddr = addr + offset;
      vme->read_bytes = read_bytes;
      vme->zero_bytes = zero_bytes;
      vme->offset = offset;
      vme->file = file;
      vme->writable = true;

      if (!insert_vme(t->vm, vme)) {
          free(vme);
          munmap(mmap_file->id);  // Roll back changes
          lock_release (&file_lock);
          return -1;
      }

      list_push_back(&mmap_file->vm_entries, &vme->mmap_elem);
    }

  lock_release (&file_lock);
  return mmap_file->id;

}

static void munmap (mapid_t mapping){
  struct thread *curr = thread_current();
  struct list_elem *e;

    for (e = list_begin(&curr->mmap_list); e != list_end(&curr->mmap_list); e = list_next(e)) {
        struct mmap_file *mmap_file = list_entry(e, struct mmap_file, elem);

        if (mmap_file->id == mapping) {
          remove_mmap(mmap_file);
          // while (!list_empty(&mmap_file->vm_entries)) {
          //     struct list_elem *velem = list_pop_front(&mmap_file->vm_entries);
          //     struct vm_entry *vme = list_entry(velem, struct vm_entry, mmap_elem);

          //     if (pagedir_is_dirty(curr->pagedir, vme->vaddr)) {
          //         file_write_at(mmap_file->file, vme->vaddr, vme->read_bytes, vme->offset);
          //     }

          //     frame_free(pagedir_get_page(curr->pagedir, vme->vaddr));
          //     pagedir_clear_page(curr->pagedir, vme->vaddr);

          //     delete_vme(curr->vm, vme);
          //     free(vme);
          // }

            file_close(mmap_file->file);
            list_remove(&mmap_file->elem);
            free(mmap_file);
            return;
        }
    }
  }


// static void remove_mmap(struct mmap_file* mmap_file){
//   struct thread* curr = thread_current();
//   while (!list_empty(&mmap_file->vm_entries)) {
//     struct list_elem *velem = list_pop_front(&mmap_file->vm_entries);
//     struct vm_entry *vme = list_entry(velem, struct vm_entry, mmap_elem);

//     if (pagedir_is_dirty(curr->pagedir, vme->vaddr)) {
//         file_write_at(mmap_file->file, vme->vaddr, vme->read_bytes, vme->offset);
//     }

//     frame_free(pagedir_get_page(curr->pagedir, vme->vaddr));
//     pagedir_clear_page(curr->pagedir, vme->vaddr);

//     delete_vme(curr->vm, vme);
//     free(vme);
//   }
// }