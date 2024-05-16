#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include <list.h>
#include "vm/page.h"

/* frame_list is being used for storing the FIFO information 
required for the second chance eviction algorithm. */

struct list lru_list;

struct list_elem* lru_clock;

// init lru_list, lru_clock, vm_lock
void lru_list_init(void);


struct page* alloc_page_frame (enum palloc_flags flags);


void add_page_to_lru_list(struct page* page);

void delete_from_lru_list(struct page* page);

void free_page(void* kaddr);
void __free_page (struct page* page);


struct page* get_page_with_kaddr (void *kaddr);


static struct list_elem* get_next_lru_clock(void);


void try_to_free_pages (void);

#endif