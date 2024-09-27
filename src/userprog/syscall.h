#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

void syscall_init (void);
void exit (int status); // used in exception, page_fault()
void close (int fd);

#endif /* userprog/syscall.h */
