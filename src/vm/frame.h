#ifndef VM_FRAM_H
#define VM_FRAM_H

#include "lib/kernel/hash.h"
#include <hash.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"

struct page_frame
{
    struct thread *t;          /* The associated thread. */
    struct vm_entry vme;
    void *kpage;               /* Kernel page, mapped to physical address */

    struct hash_elem helem;    /* see ::frame_map */
    struct list_elem lelem;    /* see ::frame_list */

    void *upage;               /* User (Virtual Memory) Address, pointer to page */

    bool pinned;               /* Used to prevent a frame from being evicted, while it is acquiring some resources.
                                    If it is true, it is never evicted. */
};



/* Functions for Frame manipulation. */

void vm_frame_init (void);
void* vm_frame_allocate (enum palloc_flags flags, void *upage);

void vm_frame_free (void*);
void vm_frame_remove_entry (void*);

void vm_frame_pin (void* kpage);
void vm_frame_unpin (void* kpage);


#endif /* vm/fram.h */