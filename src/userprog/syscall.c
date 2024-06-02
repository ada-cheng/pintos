#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include <threads/vaddr.h>
#include "threads/thread.h"
#include "lib/kernel/stdio.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#define SYSCALL_NUMBER 20

static void syscall_handler (struct intr_frame *);

static void (*syscall_table[SYSCALL_NUMBER])(struct intr_frame *f);
void syscall_halt(struct intr_frame *f);
void syscall_exit(struct intr_frame *f);
void syscall_exec(struct intr_frame *f);
void syscall_wait(struct intr_frame *f);
void syscall_write(struct intr_frame *f);
void syscall_create(struct intr_frame *f);
void syscall_remove(struct intr_frame *f);
void syscall_open(struct intr_frame *f);
void syscall_filesize(struct intr_frame *f);
void syscall_read(struct intr_frame *f);
void syscall_seek(struct intr_frame *f);
void syscall_tell(struct intr_frame *f);
void syscall_close(struct intr_frame *f);
void syscall_mmap(struct intr_frame *f);
void syscall_munmap(struct intr_frame *f);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Check the address is valid */
static void* check_address(const void *vaddr)
{
  if (!vaddr)
  {
    thread_current()->exit_status = -1;
    thread_exit();
  }
  if(!is_user_vaddr(vaddr)){
    thread_current()->exit_status = -1;
    thread_exit();
  }


  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr){
    thread_current()->exit_status = -1;
    thread_exit();
  }

  uint8_t* byte_check = (uint8_t*)vaddr;
  for (int i = 0; i < 4; i++){
    if(!is_user_vaddr(byte_check + i) || get_user(byte_check + i) == -1 )
    {
      thread_current()->exit_status = -1;
      thread_exit();
    }
  }
  return ptr;
}

/* Check the string is valid */
static void* check_string(const void *str){
  if (!is_user_vaddr(str)){
    thread_current()->exit_status = -1;
    thread_exit();
  }

  uint8_t* byte_check = (uint8_t*)str;
  while(1){
    if( get_user(byte_check) == -1)
    {
      thread_current()->exit_status = -1;
      thread_exit();
    }
    if(*byte_check == '\0')
      break;
    byte_check++;
  }

  return byte_check;
}

/* Check the ptr and the following size is valid */
static void * check_size(const void *vaddr, unsigned size)
{
    if (!is_user_vaddr(vaddr))
    {
        thread_current()->exit_status = -1;
        thread_exit();
    }

    for (unsigned i = 0; i < size; i++)
    {
        if ( get_user(vaddr + i) == -1)
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
    }

    return (void *) vaddr;

}


void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_table[SYS_HALT] = syscall_halt;
  syscall_table[SYS_EXIT] = syscall_exit;
  syscall_table[SYS_EXEC] = syscall_exec;
  syscall_table[SYS_WAIT] = syscall_wait;
  syscall_table[SYS_WRITE] = syscall_write;
 
  syscall_table[SYS_CREATE] = syscall_create;
  syscall_table[SYS_REMOVE] = syscall_remove;
  syscall_table[SYS_OPEN] = syscall_open;
  syscall_table[SYS_FILESIZE] = syscall_filesize;
  syscall_table[SYS_READ] = syscall_read;
  
  syscall_table[SYS_SEEK] = syscall_seek;
  syscall_table[SYS_TELL] = syscall_tell;
  syscall_table[SYS_CLOSE] = syscall_close;
  syscall_table[SYS_MMAP] = syscall_mmap;
  syscall_table[SYS_MUNMAP] = syscall_munmap;
 

}

/* The system call handler */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  check_size(f->esp, sizeof(int));
  int syscall_number = *(uint32_t*)f->esp;
  if(syscall_number < 0 || syscall_number >= SYSCALL_NUMBER){
    thread_current()->exit_status = -1;
    thread_exit();
  }
  syscall_table[syscall_number](f);
}

/* The halt system call */
void syscall_halt(struct intr_frame *f){
  shutdown_power_off();
}

/* The exit system call */



void syscall_exit(struct intr_frame *f){
  check_size(f->esp + 4, sizeof(int));
  thread_current()->exit_status = *(uint32_t*)(f->esp +4);
  thread_exit();
}

/* The exec system call */
void syscall_exec(struct intr_frame *f){
  char **cmd_line = (char**)check_size(f->esp + 4, sizeof(char*));
  check_string(*cmd_line);
  f->eax = process_execute(*cmd_line);
  
}

/* The wait system call */
void syscall_wait(struct intr_frame *f){
  check_size(f->esp + 4, sizeof(int));  
  f->eax = process_wait(*(uint32_t*)(f->esp + 4));
}

/* The write system call */
void syscall_write(struct intr_frame *f){

  check_size(f->esp + 4, sizeof(int));
  check_size(f->esp+12, sizeof(unsigned));

  int fd = *(uint32_t*)(f->esp + 4);
  void *buffer = *(void**)check_size(f->esp + 8, sizeof(void*));
  unsigned size = *(uint32_t*)(f->esp + 12);

  check_size(buffer, size);
  if(fd == 1){
    
    putbuf(buffer, size);
    f->eax = size;
  }
  else{
    struct list_elem *e;
    struct file_entry *file_entry;
    for(e = list_begin(&thread_current()->files); e != list_end(&thread_current()->files); e = list_next(e))//find the file
    {
      file_entry = list_entry(e, struct file_entry, e);
      if(file_entry->fd == fd){
        lock_acquire(&file_lock);
        f->eax = file_write(file_entry->file, buffer, size);
        lock_release(&file_lock);
        return;
    
      }
    }
    f->eax = 0;
  }
}

/* The create system call */
void syscall_create(struct intr_frame* f)
{
    char* file_name = *(char**) check_size(f->esp + 4, 4);
    check_string(file_name);
    check_size(f->esp + 8, 4);
    lock_acquire(&file_lock);
    f->eax = filesys_create(*(char**)(f->esp + 4), *(unsigned*)(f->esp + 8));
    lock_release(&file_lock);

}

/* The remove system call */
void syscall_remove(struct intr_frame* f)
{
    check_size(f->esp + 4, 4);
    check_string(*(char**)(f->esp + 4));
    lock_acquire(&file_lock);
    f->eax = filesys_remove(*(char**)(f->esp + 4));
    lock_release(&file_lock);
}

/* The open system call */
void syscall_open(struct intr_frame* f)
{
    check_size(f->esp +  sizeof(char*), sizeof(char*));
    //printf("open\n");
    check_string(*(char**)(f->esp + 4));
    //printf("open2\n" );
    lock_acquire(&file_lock);
    struct file* file = filesys_open(*(char**)(f->esp + 4));
    lock_release(&file_lock);
    if(file == NULL)
    {
        f->eax = -1;
        return;
    }
    struct file_entry* file_entry = (struct file_entry*)malloc(sizeof(struct file_entry));
    file_entry->fd = thread_current()->fd++;
    file_entry->file = file;
    list_push_back(&thread_current()->files, &file_entry->e);
    f->eax = file_entry->fd;

    //free(file_entry);
}

/* The filesize system call */
void syscall_filesize(struct intr_frame* f)
{
    check_size(f->esp + 4, 4);
    lock_acquire(&file_lock);
    struct list_elem* e;
    struct file_entry* file_entry;
    for(e = list_begin(&thread_current()->files); e != list_end(&thread_current()->files); e = list_next(e)) //find the file
    {
        file_entry = list_entry(e, struct file_entry, e);
        if(file_entry->fd == *(int*)(f->esp + 4))
        {
            f->eax = file_length(file_entry->file);
            lock_release(&file_lock);
            return;
        }
    }
    lock_release(&file_lock);
    f->eax = -1;
}

static void * check_string_write( void *str, size_t size){
  if (!is_user_vaddr(str)){
    thread_current()->exit_status = -1;
    thread_exit();
  }

  for (size_t i = 0; i < size; i++){
    if( !put_user(str + i,0))
    {
      thread_current()->exit_status = -1;
      thread_exit();
    }
  }

  return str;
}



/* The read system call */
void syscall_read(struct intr_frame* f)
{
    check_size(f->esp + 4, 4);
    check_size(f->esp + 8, 4);
    check_size(f->esp + 12, 4);
    check_string_write(*(char**)(f->esp + 8), *(unsigned*)(f->esp + 12));
    int fd = *(int*)(f->esp + 4);
    void* buffer = (void*)*(int*)(f->esp + 8);
    unsigned size = *(unsigned*)(f->esp + 12);
    unsigned i;
    if(fd == 0) //stdin
    {
        
       


        for(i = 0; i < size; i++)
        {
            *((uint8_t*)buffer + i) = input_getc();
        }
        f->eax = size;
        return;
    }
    if (fd == 1)
    {
        thread_current()->exit_status = -1;
        thread_exit();
    }


    struct list_elem* e;
    struct file_entry* file_entry;
    for(e = list_begin(&thread_current()->files); e != list_end(&thread_current()->files); e = list_next(e)) //find the file
    {
        file_entry = list_entry(e, struct file_entry, e);
        if(file_entry->fd == fd)
        {
            lock_acquire(&file_lock);
            f->eax = file_read(file_entry->file, buffer, size);
            lock_release(&file_lock);
            return;
        }
    }
    f->eax = -1;
}


/* The seek system call */
void syscall_seek(struct intr_frame* f)
{
    check_address(((uint32_t*)(f->esp)) + 5);
    lock_acquire(&file_lock);
    struct list_elem* e;
    struct file_entry* file_entry;
    for(e = list_begin(&thread_current()->files); e != list_end(&thread_current()->files); e = list_next(e)) //find the file
    {
        file_entry = list_entry(e, struct file_entry, e);
        if(file_entry->fd == *(int*)(f->esp + 4))
        {
            file_seek(file_entry->file, *(unsigned*)(f->esp + 8));
            lock_release(&file_lock);
            return;
        }
    }
    lock_release(&file_lock);
}

/* The tell system call */
void syscall_tell(struct intr_frame* f)
{
    check_address(f->esp + 4);
    lock_acquire(&file_lock);
    struct list_elem* e;
    struct file_entry* file_entry;
    for(e = list_begin(&thread_current()->files); e != list_end(&thread_current()->files); e = list_next(e)) //find the file
    {
        file_entry = list_entry(e, struct file_entry, e);
        if(file_entry->fd == *(int*)(f->esp + 4))
        {
            f->eax = file_tell(file_entry->file);
            lock_release(&file_lock);
            return;
        }
    }
    lock_release(&file_lock);
    f->eax = -1;
}

/* The close system call */
void syscall_close(struct intr_frame* f)
{
    check_address(f->esp + 4);
    lock_acquire(&file_lock);
    struct list_elem* e;
    struct file_entry* file_entry;
    for(e = list_begin(&thread_current()->files); e != list_end(&thread_current()->files); e = list_next(e)) //find the file
    {
        file_entry = list_entry(e, struct file_entry, e);
        if(file_entry->fd == *(int*)(f->esp + 4))
        {
            file_close(file_entry->file);
            list_remove(&file_entry->e);
            free(file_entry);
            lock_release(&file_lock);
            return;
        }
    }
    lock_release(&file_lock);
}




int mmap(int fd, void* addr){

  struct mmap_entry *mmap_file;
  size_t offset = 0;

  if (pg_ofs(addr) != 0)
    return -1;
  if (!addr)
    return -1;
  if (!is_user_vaddr(addr))
    return -1;
  mmap_file = (struct mmap_file *)malloc (sizeof (struct mmap_entry));
  if (mmap_file == NULL)
    return -1;
  memset (mmap_file, 0, sizeof(struct mmap_entry));
  list_init (&mmap_file->spte_list);
  for (struct list_elem *e = list_begin (&thread_current ()->files); e != list_end (&thread_current ()->files); e = list_next (e))
  { // find the file
    if (list_entry (e, struct file_entry, e)->fd == fd)
    {
      struct file *file_ = list_entry (e, struct file_entry, e)->file;
      mmap_file->file = file_;
      break;
    }
  } 
  if (mmap_file->file == NULL)
    return -1;
  mmap_file->file = file_reopen (mmap_file->file);
  mmap_file->mapid = thread_current ()->mapid++;
  list_push_back (&thread_current ()->mmap_list, &mmap_file->elem);

  int len_file = file_length (mmap_file->file);
  while (len_file > 0) // write the file to the memory
    {
      if (find_spe (addr))
        return -1;

      struct spt_entry *spe = (struct spt_entry *)malloc (sizeof (struct spt_entry));
      memset (spe, 0, sizeof (struct spt_entry));
      spe->type = FILE;
      spe->writable = true;
      spe->vaddr = addr;
      spe->offset = offset;
      spe->read_bytes = len_file >= PGSIZE ? PGSIZE : len_file;
      spe->zero_bytes = PGSIZE - spe->read_bytes;
      spe->file = mmap_file->file;
      insert_spe (&thread_current ()->spt, spe);
      list_push_back (&mmap_file->spte_list, &spe->mmap_elem);
      addr += PGSIZE;
      offset += PGSIZE;
      len_file -= PGSIZE;
    }
  return mmap_file->mapid;
}



void syscall_mmap(struct intr_frame *f)
{
  check_address(f->esp + 4);
  check_address(f->esp + 8);
  f->eax = mmap(*(int *)(f->esp + 4), *(void **)(f->esp + 8));
}


void munmap(int mapid){
  struct mmap_entry *mmap_entry = NULL;
  for (struct list_elem *e = list_begin(&thread_current()->mmap_list); e != list_end(&thread_current()->mmap_list); e = list_next(e))
  { //iterate through the mmap_list, to find the mmap_entry
    mmap_entry = list_entry(e, struct mmap_entry, elem);
    if (mapid == -1)
    {
        for (struct list_elem *e = list_begin(&mmap_entry->spte_list); e != list_end(&mmap_entry->spte_list); e = list_next(e))
        { //iterate through the spte_list, to free the pages
            struct spt_entry *spe = list_entry(e, struct spt_entry, mmap_elem);
            if (spe->is_loaded)
            {
                if (pagedir_is_dirty(thread_current()->pagedir, spe->vaddr))
                {
                    lock_acquire(&file_lock);
                    file_write_at(spe->file, spe->vaddr, spe->read_bytes, spe->offset);
                    lock_release(&file_lock);
                    spe->is_loaded = false;
                }
                free_page(pagedir_get_page(thread_current()->pagedir, spe->vaddr));
                pagedir_clear_page(thread_current()->pagedir, spe->vaddr);
            

            }
            struct list_elem * tmp = list_prev(e);
            list_remove(e);
            e = tmp;
            remove_spe(&thread_current()->spt, spe);
        }
        file_close(mmap_entry->file);
        struct list_elem * tmp = list_prev(e);
        list_remove(e);
        e = tmp;
        free(mmap_entry);
        continue;
    }
    else if(mmap_entry->mapid == mapid)
    {
        for (struct list_elem* e = list_begin(&mmap_entry->spte_list); e != list_end(&mmap_entry->spte_list); e = list_next(e))
        { //iterate through the spte_list, to free the pages
            struct spt_entry *spe = list_entry(e, struct spt_entry, mmap_elem);
            if (spe->is_loaded)
            {
                if (pagedir_is_dirty(thread_current()->pagedir, spe->vaddr))
                {
                    lock_acquire(&file_lock);
                    file_write_at(spe->file, spe->vaddr, spe->read_bytes, spe->offset);
                    lock_release(&file_lock);
                    spe->is_loaded = false;
                }
                free_page(pagedir_get_page(thread_current()->pagedir, spe->vaddr));
                pagedir_clear_page(thread_current()->pagedir, spe->vaddr);
            }
            struct list_elem * tmp = list_prev(e);
            list_remove(e);
            e = tmp;
            remove_spe(&thread_current()->spt, spe);
        }
        file_close(mmap_entry->file);
        list_remove(&mmap_entry->elem);
        struct list_elem * tmp = list_prev(e);
        list_remove(e);
        e = tmp;
        free(mmap_entry);
        break;

      
    }
  
  }
}





void syscall_munmap(struct intr_frame *f)
{
  check_size(f->esp + 4, sizeof(int));
  munmap(*(int *)(f->esp + 4));
}