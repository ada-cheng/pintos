#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool page_fault_handle(struct spt_entry *spe);
bool stack_growth(void *fault_addr);

#endif /**< userprog/process.h */
