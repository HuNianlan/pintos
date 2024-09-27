#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"
#include <stdbool.h>

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool handle_mm_fault(struct vm_entry* vme);
bool grow_stack (void*);

typedef int mapid_t;

struct mmap_file {
    mapid_t id;
    struct file *file;
    struct list vm_entries;    /* List of vm_entry objects */
    struct list_elem elem;
};


struct file_descripter
{
    int fd;
    struct file *file;
    struct list_elem thread_elem;
};

void remove_mmap(struct mmap_file* mmap_file);
struct mmap_file *find_mmap_file (int mapid);

#endif /* userprog/process.h */
