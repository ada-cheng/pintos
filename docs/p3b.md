# Project 3b: Virtual Memory

## Preliminaries

>Fill in your name and email address.

Xinle Cheng <adacheng@stu.pku.edu.cn>

>If you have any preliminary comments on your submission, notes for the TAs, please give them here.



>Please cite any offline or online sources you consulted while preparing your submission, other than the Pintos documentation, course text, lecture notes, and course staff.



## Stack Growth

#### ALGORITHMS

>A1: Explain your heuristic for deciding whether a page fault for an
>invalid virtual address should cause the stack to be extended into
>the page that faulted.

I use `if (is_stack_access(f->esp,fault_addr))` in `exception.c`.

```cpp
bool is_stack_access(int esp, int upage){
 return (upage < PHYS_BASE) && (upage >= esp - 32) && (upage >= STK_MAX);
 }
```



## Memory Mapped Files

#### DATA STRUCTURES

>B1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

```cpp
struct mmap_entry{
    int mapid;
    struct file* file;
    struct list_elem elem;
    struct list spte_list;
};
```



#### ALGORITHMS

>B2: Describe how memory mapped files integrate into your virtual
>memory subsystem.  Explain how the page fault and eviction
>processes differ between swap pages and other pages.



>B3: Explain how you determine whether a new file mapping overlaps
>any existing segment.



#### RATIONALE

>B4: Mappings created with "mmap" have similar semantics to those of
>data demand-paged from executables, except that "mmap" mappings are
>written back to their original files, not to swap.  This implies
>that much of their implementation can be shared.  Explain why your
>implementation either does or does not share much of the code for
>the two situations.