#include "vm/swap.h"
#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/debug.h"

static struct block *swap_block;

static struct bitmap *swap_bitmap;

struct lock swap_lock;

void swap_init (void) // Initialize the swap table
{
    lock_init(&swap_lock);
    swap_block = block_get_role(BLOCK_SWAP);
    if (swap_block == NULL)
    {
        PANIC("Swap partition full");
    }
    size_t num_slot = block_size(swap_block) / SECTORS_PER_PAGE;
    swap_bitmap = bitmap_create(num_slot);
    if (swap_bitmap == NULL)
    {
        PANIC("Create swap bitmap failed");
    }
    bitmap_set_all(swap_bitmap, SWAP_FREE);
    
}

size_t swap_out (void *kpage) // Swap out the page
{

    lock_acquire(&swap_lock);
    size_t free_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, SWAP_FREE);
    if (free_index == BITMAP_ERROR)
    {
        PANIC("Swap partition full");
    }
    size_t i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) // Write the page to the swap block
    {
        block_write(swap_block, free_index * SECTORS_PER_PAGE + i, kpage + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_lock);
    return free_index;
}


void swap_in (size_t used_index, void *kpage) // Swap in the page
{
   
    lock_acquire(&swap_lock);
    if (bitmap_test(swap_bitmap, used_index) == SWAP_FREE)
    {
        PANIC("Swap page not in use");
    }
    size_t i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) // Read the page from the swap block
    {
        block_read(swap_block, used_index * SECTORS_PER_PAGE + i, kpage + i * BLOCK_SECTOR_SIZE);
    }
    bitmap_flip(swap_bitmap, used_index);
    lock_release(&swap_lock);
}