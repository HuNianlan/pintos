#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

void syscall_init (void);
void exit (int status); // used in exception, page_fault()

struct file_descripter
{
    int fd;
    struct file *file;
    struct dir* dir; /* newlly added for subdirs. record the dir of the file (close needs to accept a file descriptor for a directory.)*/
    struct list_elem thread_elem;
};

#endif /* userprog/syscall.h */
