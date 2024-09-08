#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);

void exit (int status);
struct lock file_lock;

#endif /* userprog/syscall.h */
