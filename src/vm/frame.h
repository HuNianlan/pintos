#ifndef VM_FRAM_H
#define VM_FRAM_H

// #include "lib/kernel/hash.h"
// #include <hash.h>

// #include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"
#include <stdbool.h>
#include "lib/kernel/list.h"


struct frame
{
    void *kpage;                /* Kernel virtual address of the frame */

    struct thread *owner;       /* The associated thread. */
    struct vm_entry* vme;       /**/

    struct list_elem elem;    /* see ::frame_list */

    bool reference_bit;         /* Reference bit for CLOCK algorithm */


    bool pinned;               /* Used to prevent a frame from being evicted, while it is acquiring some resources.
                                    If it is true, it is never evicted. */
};



/* Functions for Frame manipulation. */

void frame_init (void);
// bool lru_insert(struct page_frame*);
// void lru_remove(struct page_frame*);

void *frame_alloc(struct vm_entry *vme,enum palloc_flags flags);
void frame_free(void *kpage);

/* Evict a page using the CLOCK algorithm */
void frame_evict(void);

//swap out page

void vm_frame_pin (void* upage);
void vm_frame_unpin (void* upage);

struct frame* find_frame(void* upage);
#endif /* vm/fram.h */