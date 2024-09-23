#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

// Page slot in swap space
typedef size_t swap_slot_t;

// Initialize the swap space
void swap_init(void);

// Swap in the page from the swap slot to a frame
void swap_in(swap_slot_t slot, void *frame);

// Swap out the page from a frame to a swap slot
swap_slot_t swap_out(void *frame);

#endif /* vm/swap.h */




