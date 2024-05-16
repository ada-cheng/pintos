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


void lru_list_init(void);


struct page* alloc_page_frame (enum palloc_flags flags);


void add_page_to_spe(struct page* page);


void free_page(void* kaddr);

struct page* get_page (void *kaddr);


static struct list_elem* next_ele_in_LRU(void);


void evict_pages (void);

#endif