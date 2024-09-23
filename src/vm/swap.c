#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include <bitmap.h>
#include <debug.h>

// The swap block device
static struct block *swap_block;
// Bitmap to track used/unused swap slots
static struct bitmap *swap_map;
// Lock to synchronize access to the swap space
static struct lock swap_lock;

// Number of sectors per page
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init(void) 
{
    swap_block = block_get_role(BLOCK_SWAP);
    if (swap_block == NULL) {
        PANIC("No swap block device found.");
    }
    
    // Initialize swap map
    swap_map = bitmap_create(block_size(swap_block) / SECTORS_PER_PAGE);
    if (swap_map == NULL) {
        PANIC("Could not create swap bitmap.");
    }

    lock_init(&swap_lock);
}

void swap_in(swap_slot_t slot, void *frame) 
{
    ASSERT(slot < bitmap_size(swap_map));
    ASSERT(frame != NULL);

    lock_acquire(&swap_lock);

    if (bitmap_test(swap_map, slot)) {
        for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
            block_read(swap_block, slot * SECTORS_PER_PAGE + i, (uint8_t *)frame + i * BLOCK_SECTOR_SIZE);
        }
        bitmap_reset(swap_map, slot);
    }

    lock_release(&swap_lock);
}

swap_slot_t swap_out(void *frame) 
{
    ASSERT(frame != NULL);

    lock_acquire(&swap_lock);

    swap_slot_t slot = bitmap_scan_and_flip(swap_map, 0, 1, false);
    if (slot == BITMAP_ERROR) {
        PANIC("Out of swap slots.");
    }

    for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
        block_write(swap_block, slot * SECTORS_PER_PAGE + i, (uint8_t *)frame + i * BLOCK_SECTOR_SIZE);
    }

    lock_release(&swap_lock);
    return slot;
}