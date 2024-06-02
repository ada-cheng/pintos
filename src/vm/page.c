#include "vm/page.h"
#include <stdio.h>
#include <string.h>
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "vm/frame.h"
#include "userprog/pagedir.h"

extern struct lock file_lock;
struct spt_entry *find_spe(void *vaddr);


void spt_init(struct hash* spt){
    ASSERT(spt!=NULL);
    hash_init(spt, spt_hash_func, spt_less_func, NULL);
}


unsigned spt_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spe = hash_entry (e, struct spt_entry, elem);
  return hash_bytes (&spe->vaddr, sizeof spe->vaddr);
}


bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void* aux)
{
    const struct spt_entry *spe_a = hash_entry (a, struct spt_entry, elem);
    const struct spt_entry *spe_b = hash_entry (b, struct spt_entry, elem);
    return spe_a->vaddr < spe_b->vaddr;
    
}

bool insert_spe(struct hash *spt, struct spt_entry *spe)
{
    ASSERT (spt != NULL);
    ASSERT (spe != NULL);
    return hash_insert (spt, &spe->elem) == NULL;

}

bool remove_spe(struct hash *spt, struct spt_entry *spe)
{
    ASSERT (spt != NULL);
    ASSERT (spe != NULL);
    return hash_delete (spt, &spe->elem) != NULL;

}

struct spt_entry *find_spe(void *vaddr)
{
    struct spt_entry spe;
    struct hash_elem *e;
    spe.vaddr = pg_round_down(vaddr);
    e = hash_find (&thread_current()->spt, &spe.elem);
    return e != NULL ? hash_entry (e, struct spt_entry, elem) : NULL;
}


void destroy_spt(struct hash *spt){
    ASSERT(spt!=NULL);
    hash_destroy(spt, spt_destroy_func);
}

void spt_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  ASSERT (e != NULL);
  struct spt_entry *spe = hash_entry (e, struct spt_entry, elem);
  void *kaddr;

  if(spe->is_loaded){
      kaddr = pagedir_get_page(thread_current()->pagedir, spe->vaddr);
      free_page(kaddr);
      pagedir_clear_page(thread_current()->pagedir, spe->vaddr);
  }
 
  free (spe);
}


bool load_file(void* kaddr, struct spt_entry *spe)
{

    ASSERT(spe->type == BIN || spe->type == FILE);
    bool success = false;
    lock_acquire(&file_lock);

    file_seek(spe->file, spe->offset);
   
                              

    if(file_read(spe->file, kaddr, spe->read_bytes) == (int) spe->read_bytes)
    {
    memset(kaddr + spe->read_bytes, 0, spe->zero_bytes);
    success = true;
    }

    lock_release(&file_lock);
    return success;
}