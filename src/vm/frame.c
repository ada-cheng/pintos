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

// allocate a page from USER POOL with palloc_get_page
// add an entry to frame table if succed
struct page* alloc_page_frame(enum palloc_flags flags)
{
    void* kaddr = palloc_get_page(flags);
    if (kaddr == NULL) {
        try_to_free_pages();
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


/* Add an entry to frame table */
void add_page_to_lru_list(struct page* page)
{
  ASSERT (page);
  lock_acquire(&vm_lock);
  list_push_back(&lru_list, &page->lru);
  lock_release(&vm_lock);
}


/* Remove the entry from frame table and free the memory space */
void delete_from_lru_list (struct page *page)
{
  ASSERT (page);


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
}

// get page with kaddr
struct page* get_page_with_kaddr (void *kaddr)
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


void free_page(void* kaddr){
    struct page* page = get_page_with_kaddr(kaddr);
    ASSERT(page!=NULL);
    __free_page (page);

}


void __free_page (struct page* page){
    delete_from_lru_list(page);
    palloc_free_page(page->kaddr);
    free(page);
}



static struct list_elem* get_next_lru_clock(void){

  ASSERT(!list_empty(&lru_list));

  if(lru_clock==NULL){
      lru_clock = list_begin(&lru_list);
  }
  else lru_clock = list_next(lru_clock);
  
  if(lru_clock == list_tail(&lru_list))
    lru_clock = list_begin(&lru_list);
  return lru_clock;
}


void try_to_free_pages(void) {
    ASSERT(!list_empty(&lru_list));

    struct page* page;
    struct list_elem* elem;

    lock_acquire(&vm_lock);

    while (1) {
        elem = get_next_lru_clock();
        page = list_entry(elem, struct page, lru);

        if (pagedir_is_accessed(page->t->pagedir, page->spe->vaddr)) {
            pagedir_set_accessed(page->t->pagedir, page->spe->vaddr, false);
            continue;
        }

        if (pagedir_is_dirty(page->t->pagedir, page->spe->vaddr) || page->spe->type == VM_ANON) {
            if (page->spe->type == VM_FILE) {
                lock_acquire(&file_lock);
                file_write_at(page->spe->file, page->kaddr, page->spe->read_bytes, page->spe->offset);
                lock_release(&file_lock);
            } else {
                page->spe->type = VM_ANON;
                page->spe->swap_slot = swap_out(page->kaddr);
            }
            page->spe->is_loaded = false;
            pagedir_clear_page(page->t->pagedir, page->spe->vaddr);
            lock_release(&vm_lock);
            break;
        }
    }

    __free_page(page);
}