#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "lib/kernel/list.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/frame.h"

extern struct lock file_lock;
/* lock to synchronize between processes on frame table */
struct lock vm_lock;

bool flag;
int cnt = 0;

void lru_list_init(){
  list_init(&lru_list);
  lock_init(&vm_lock);    
  lru_clock = NULL;
}


struct page* alloc_page_frame(enum palloc_flags flags) // allocate a frame for a page
{
    void* kaddr = palloc_get_page(flags);
    if (kaddr == NULL) {
        evict_pages();
        kaddr = palloc_get_page(flags);
        if (kaddr == NULL) return NULL;
    }

    struct page* frame = (struct page*)malloc(sizeof(struct page));
    if (!frame) {
        palloc_free_page(kaddr);
        return NULL;
    }

    memset(frame, 0, sizeof(struct page));
    frame->t = thread_current();
    frame->kaddr = kaddr;

    return frame;
}


void add_page_to_spe(struct page* page) // add a page to the lru list
{
  ASSERT (page);
  lock_acquire(&vm_lock);
  list_push_back(&lru_list, &page->lru);
  lock_release(&vm_lock);
}




struct page* get_page(void *kaddr) // get a page with a kernel address
{
    ASSERT(pg_ofs(kaddr) == 0);

    struct page* temp = NULL;
    struct list_elem* e;

    lock_acquire(&vm_lock);
    for (e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
        temp = list_entry(e, struct page, lru);
        if (temp->kaddr == kaddr) break;
        temp = NULL;
    }
    lock_release(&vm_lock);

    return temp;
}


void free_page(void* kaddr){ // free a page with a kernel address

    struct page* page = get_page(kaddr);
    ASSERT(page!=NULL);
    lock_acquire(&vm_lock);
    if (lru_clock == &page->lru)
    {
      lru_clock = list_remove (lru_clock);
    }
    else
    {
      list_remove (&page->lru);
    }
    lock_release(&vm_lock);
    palloc_free_page(page->kaddr);
    free(page);
    
}



static struct list_elem* next_ele_in_LRU(void){ // get the next lru clock by iterating the lru list

  ASSERT(!list_empty(&lru_list));

  if(lru_clock==NULL){
      lru_clock = list_begin(&lru_list);
  }
  else lru_clock = list_next(lru_clock);
  
  if(lru_clock == list_tail(&lru_list))
    lru_clock = list_begin(&lru_list);
  return lru_clock;
}


void evict_pages(void) { // try to free pages by iterating the lru list and checking the accessed bit
    ASSERT(!list_empty(&lru_list));

    struct page* page;
    struct list_elem* elem;

    lock_acquire(&vm_lock);

    while (1) {
        elem = next_ele_in_LRU();
        page = list_entry(elem, struct page, lru);

        if (pagedir_is_accessed(page->t->pagedir, page->spe->vaddr)) {
            pagedir_set_accessed(page->t->pagedir, page->spe->vaddr, false);
            continue;
        }

        if (pagedir_is_dirty(page->t->pagedir, page->spe->vaddr) || page->spe->type == ANON) {
            if (page->spe->type == FILE) {
                lock_acquire(&file_lock);
                file_write_at(page->spe->file, page->kaddr, page->spe->read_bytes, page->spe->offset);
                lock_release(&file_lock);
            } else {
                page->spe->type = ANON;
                page->spe->swap_slot = swap_out(page->kaddr);
            }
            page->spe->is_loaded = false;
            pagedir_clear_page(page->t->pagedir, page->spe->vaddr);
            lock_release(&vm_lock);
            break;
        }
    }

    lock_acquire(&vm_lock);
    if (lru_clock == &page->lru)
    {
      lru_clock = list_remove (lru_clock);
    }
    else
    {
      list_remove (&page->lru);
    }
    lock_release(&vm_lock);
    palloc_free_page(page->kaddr);
    free(page);

}