#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

struct file_descripter
{
    int fd;
    tid_t owner; // used in file close
    struct file *file;
    struct list_elem elem;
    struct list_elem thread_elem;
};

void syscall_init (void);

void exit (int status);
void close (int fd);

struct lock file_lock;

#endif /* userprog/syscall.h */
