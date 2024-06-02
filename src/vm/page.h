#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <debug.h>
#include "lib/kernel/hash.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/vaddr.h"

#define BIN 0
#define FILE 1
#define ANON 2


struct mmap_entry{
    int mapid;
    struct file* file;
    struct list_elem elem;
    struct list spte_list;
};


struct spt_entry{

    uint8_t type; 
    void *vaddr; 

    bool writable; 
    bool is_loaded; 

    struct file* file;

    size_t offset;     
    size_t read_bytes;
    size_t zero_bytes;
    struct hash_elem elem; 
    struct list_elem mmap_elem; 

    size_t swap_slot; 
};


void spt_init(struct hash* spt);

unsigned spt_hash_func(const struct hash_elem *e, void *aux);

bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void* aux);

bool insert_spe(struct hash *spt, struct spt_entry *spe);

bool remove_spe(struct hash *spt, struct spt_entry *spe);

void destroy_spt(struct hash *spt);

void spt_destroy_func (struct hash_elem *e, void *aux UNUSED);

struct spt_entry* find_spe(void* vaddr);


bool load_file(void *kaddr, struct spt_entry* spe);

#endif