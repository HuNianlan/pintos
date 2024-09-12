#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

void syscall_init (void);
void exit (int status);

struct file_descripter
{
    int fd;
    tid_t owner; // used in file close
    struct file *file;
    struct list_elem elem;
    struct list_elem thread_elem;
};

struct list open_file_list;
int allocate_fd (void);
#endif /* userprog/syscall.h */
