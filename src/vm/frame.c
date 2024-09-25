#include "vm/frame.h"
#include "vm/page.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static struct list frame_table;
static struct lock frame_table_lock;
static struct list_elem *get_circular_clock (void);
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
    // printf("lock acquire in f alloc\n");
    // printf("success\n");
    // printf("input vaddr: %u\n",vme->vaddr);
    ASSERT(is_user_vaddr(vme->vaddr));
    void *kpage = palloc_get_page(flags);
    if (kpage == NULL) {
        frame_evict();
        kpage = palloc_get_page(flags);
        ASSERT(kpage != NULL);
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

    // lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &f->elem);
    // printf("frame alloc %u,%u,%u\n",f,f->vme,vme->vaddr);
    // lock_release(&frame_table_lock);

    // lock_release(&frame_lock);

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
            // printf("sb: %d\n",f);
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
    victim->vme->is_loaded = false;


    /* Update the page directory and free resources */
    // printf("evict value %u,%u,%u\n",victim,victim->vme,victim->vme->vaddr);
    pagedir_clear_page(t->pagedir, pg_round_down(vme->vaddr));

    palloc_free_page(victim->kpage);
    // frame_free(victim->kpage);
    list_remove(&victim->elem);
    free(victim);
    lock_release(&frame_table_lock);
}


/*find the victim page and remove its elem from frame_table*/
static struct frame* find_victim(void){
    /*f is the victim page*/
    struct list_elem* e = get_circular_clock();
    struct frame *f = list_entry(e, struct frame, elem);
    /* Ensure the clock hand is initialized */
    // if (clock_hand == NULL || clock_hand == list_end(&frame_table)) {
    //     clock_hand = list_begin(&frame_table);
    // }
    
    // while (true) {
        while(f->pinned||pagedir_is_accessed (f->owner->pagedir, f->vme->vaddr)){
            pagedir_set_accessed (f->owner->pagedir, f->vme->vaddr, false);
            e = get_circular_clock();
            f = list_entry(e, struct frame, elem);
                /* If reference bit is clear, evict this frame */
                // printf("find: %d\n",f);
                // list_remove(clock_hand);

            /* Move the clock hand forward. */
            // clock_hand = list_next(clock_hand);
            // if (clock_hand == list_end(&frame_table)) {
            //     // printf("chuan\n");
            //     clock_hand = list_begin(&frame_table);
            // }
            }
    return f;

}

struct frame* find_frame(void* upage){
    // lock_acquire(&frame_table_lock);
    struct list_elem* e;
    struct frame* f = NULL;
    for(e = list_front(&frame_table);e!= list_tail(&frame_table);e = list_next(e)){
        f = list_entry(e,struct frame,elem);
        if(f->vme->vaddr == upage) return f;
    }
    // lock_release(&frame_table_lock);
    return NULL;

}

static void
vm_frame_set_pinned (void *upage, bool new_value)
{
  struct frame* f = find_frame(upage);  
  f->pinned = new_value;
}

void
vm_frame_unpin (void* upage) {
  vm_frame_set_pinned (upage, false);
}

void
vm_frame_pin (void* upage) {
  vm_frame_set_pinned (upage, true);
}


static struct list_elem *
get_circular_clock (void)
{
  if(list_empty(&frame_table))
    return NULL;
  if (clock_hand == NULL || clock_hand == list_end (&frame_table))
    {
    //   if (list_empty (&frame_table))
    //     return NULL;
    //   else
        return (clock_hand = list_begin (&frame_table));
    }
  clock_hand = list_next (&frame_table);
  if (clock_hand == list_end (&clock_hand))
      return get_circular_clock ();
  return clock_hand;
}