#include "vm/frame.h"
#include "vm/page.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"

static struct list frame_table;
static struct lock frame_table_lock;
/* Clock hand pointer */
static struct list_elem *clock_hand;
static void vm_frame_set_pinned (void *kpage, bool new_value);
static struct frame* find_victim(void);
void frame_init (void){
    list_init(&frame_table);
    lock_init(&frame_table_lock);

}

/* Allocate a frame to the provided vm_entry */
void *
frame_alloc(struct vm_entry *vme,enum palloc_flags flags)
{   

    void *kpage = palloc_get_page(flags);
    if (kpage == NULL) {

        frame_evict();
        kpage = palloc_get_page(flags);
        ASSERT(kpage != NULL);
        /* Implement appropriate frame eviction here if needed */
        // PANIC("Out of memory: frame allocation failed and eviction not handled.");
    }

    struct frame *f = malloc(sizeof(struct frame));
    if (f == NULL) {
        palloc_free_page(kpage);
        free(f);
        return NULL;
    }

    f->kpage = kpage;
    f->owner = thread_current();
    f->vme = vme;
    f->pinned = false;

    lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &f->elem);
    lock_release(&frame_table_lock);

    return kpage;
}

/* Free a frame using its kpage but not include its vm_entry*/
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
void
frame_evict(void)
{
    lock_acquire(&frame_table_lock);
    struct frame* victim = find_victim();
    struct thread* t = victim->owner;
    struct vm_entry* vme = victim->vme;

    switch (vme->type)
    {
    case VM_BIN:
        if(pagedir_is_dirty (t->pagedir, vme->vaddr)){
            vme->swap_index = swap_out(victim->kpage);
            vme->type = VM_ANON;
        }

        break;
    case VM_FILE:
        if(pagedir_is_dirty (t->pagedir, vme->vaddr)){
            file_write_back(vme);
        }
        break;
    case VM_ANON:
        vme->swap_index = swap_out(victim->kpage);
    
    default:
        break;
    }
    
    
    /* Update the page directory and free resources */
    pagedir_clear_page(t->pagedir, vme->vaddr);
    
    palloc_free_page(victim->kpage);
    free(victim);

    /* Return the evicted frame's page */
    lock_release(&frame_table_lock);
}


/*find the victim page and remove its elem from frame_table*/
static struct frame* find_victim(void){
    /*f is the victim page*/
    struct frame *f = NULL;
    /* Ensure the clock hand is initialized */
    if (clock_hand == NULL || clock_hand == list_end(&frame_table)) {
        clock_hand = list_begin(&frame_table);
    }

    while (true) {
        f = list_entry(clock_hand, struct frame, elem);
        if(!f->pinned){
            if (f->reference_bit) {
                /* If reference bit is set, clear it and advance the hand */
                f->reference_bit = false;
            } else {
                /* If reference bit is clear, evict this frame */
                list_remove(clock_hand);
                return f;
            }
        }
            /* Move the clock hand forward. */
            clock_hand = list_next(clock_hand);
            if (clock_hand == list_end(&frame_table)) {
                clock_hand = list_begin(&frame_table);
            }
    }
}

static struct frame* find_frame(void* kpage){
    struct list_elem* e;
    struct frame* f = NULL;
    for(e = list_front(&frame_table);e!= list_tail(&frame_table);e = list_next(e)){
        f = list_entry(e,struct frame,elem);
        if(f->kpage == kpage){
            return f;
        }
    }
    return NULL;
}

static void
vm_frame_set_pinned (void *kpage, bool new_value)
{
  lock_acquire (&frame_table_lock);

  // lookup
  struct frame* f = find_frame(kpage);  
//   struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (f == NULL) {
    PANIC ("The frame to be pinned/unpinned does not exist");
  }

  f->pinned = new_value;

  lock_release (&frame_table_lock);
}

void
vm_frame_unpin (void* kpage) {
  vm_frame_set_pinned (kpage, false);
}

void
vm_frame_pin (void* kpage) {
  vm_frame_set_pinned (kpage, true);
}