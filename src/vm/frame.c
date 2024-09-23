#include "vm/frame.h"
#include "vm/page.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"

static struct list frame_table;
static struct lock frame_table_lock;
/* Clock hand pointer */
static struct list_elem *clock_hand;


void frame_init (void){
    list_init(&frame_table);
    lock_init(&frame_table_lock);

}

/* Allocate a frame to the provided vm_entry */
void *
frame_alloc(struct vm_entry *vme)
{
    void *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL) {
        /* Implement appropriate frame eviction here if needed */
        PANIC("Out of memory: frame allocation failed and eviction not handled.");
    }

    struct frame *f = malloc(sizeof(struct frame));
    if (f == NULL) {
        palloc_free_page(kpage);
        return NULL;
    }

    f->kpage = kpage;
    f->owner = thread_current();
    f->vme = vme;

    lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &f->elem);
    lock_release(&frame_table_lock);

    return kpage;
}

/* Free a frame */
void
frame_free(void *kpage)
{
    lock_acquire(&frame_table_lock);

    struct list_elem *e;
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
        struct frame *f = list_entry(e, struct frame, elem);
        if (f->kpage == kpage) {
            list_remove(e);
            palloc_free_page(kpage);
            free(f);
            break;
        }
    }

    lock_release(&frame_table_lock);
}


// bool lru_insert(struct page_frame*);
// void lru_remove(struct page_frame*);

/* Evict a frame using the CLOCK algorithm */
void *
frame_evict(void)
{
    lock_acquire(&frame_table_lock);

    /* Ensure the clock hand is initialized */
    if (clock_hand == NULL || clock_hand == list_end(&frame_table)) {
        clock_hand = list_begin(&frame_table);
    }

    while (true) {
        struct frame *f = list_entry(clock_hand, struct frame, elem);

        if (f->reference_bit) {
            /* If reference bit is set, clear it and advance the hand */
            f->reference_bit = false;
        } else {
            /* If reference bit is clear, evict this frame */
            list_remove(clock_hand);
            
            /* Update the page directory and free resources */
            pagedir_clear_page(f->owner->pagedir, f->vme->vaddr);
            palloc_free_page(f->kpage);
            free(f->vme);
            free(f);

            /* Return the evicted frame's page */
            lock_release(&frame_table_lock);
            return f->kpage;
        }

        /* Move the clock hand forward. */
        clock_hand = list_next(clock_hand);
        if (clock_hand == list_end(&frame_table)) {
            clock_hand = list_begin(&frame_table);
        }
    }
}
