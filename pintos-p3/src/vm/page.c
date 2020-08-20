#include "vm/page.h"
#include <stdio.h>
#include <string.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

/* Destroys a page, which must be in the current process's
   page table.  Used as a callback for hash_destroy(). */
static void destroy_page (struct hash_elem *p_, void *aux)  {
  struct page * des_p = hash_entry(p_, struct page, hash_elem);
  frame_lock(des_p);
  if (des_p->frame != NULL) frame_free(des_p->frame);
  free(des_p);

  return;
}

/* Destroys the current process's page table. */
void page_exit (void)  {
  struct hash *table = thread_current()->page_table;
  if (table != NULL) hash_destroy(table, destroy_page);
  return;
}


/* Returns the page containing the given virtual ADDRESS,
   or a null pointer if no such page exists.
   Allocates stack pages as necessary. */
static struct page *page_for_addr (const void *address) {
  if (address >= PHYS_BASE) return NULL;
  struct page p;
  p.addr = pg_round_down(address);
  struct thread * t = thread_current();
  struct hash_elem * found = hash_find(t->page_table,&p.hash_elem);

  if (found == NULL &&  (t->esp - 32) <= address){
    // expand stack
    struct page* new_page = page_allocate(address, false);
    return new_page;
  }
  else {
    return hash_entry(found, struct page, hash_elem);
  }
  return NULL;
}


/* Locks a frame for page P and pages it in.
   Returns true if successful, false on failure. */
static bool do_page_in (struct page *p) {
  p->frame = frame_alloc_and_lock(p);
  if (p->frame == NULL) return false;

  if (p->sector != (block_sector_t)(-1))
  {
    if (!swap_in(p)) return false;
  }
  else if (p->file != NULL){
    off_t read_amt = file_read_at(p->file,p->frame->base,p->file_size,p->file_ofs);
    off_t left_amt = PGSIZE - read_amt;
    memset(p->frame->base + read_amt, 0, left_amt);
  }
  else
    memset (p->frame->base,0,PGSIZE);
  return true;
}


/* Faults in the page containing FAULT_ADDR.
   Returns true if successful, false on failure. */
bool page_in (void *fault_addr) {

  struct thread * t = thread_current();

  struct page* p = page_for_addr(fault_addr);
  if (p == NULL) return false;

  frame_lock(p);
  // swap in if no frame
  if (p->frame == NULL){
    if (!do_page_in(p)) return false;
  }

  bool flag = pagedir_set_page(t->pagedir, p->addr, p->frame->base,
      !p->read_only);
  frame_unlock(p->frame);
  return flag;
}


/* Evicts page P.
   P must have a locked frame.
   Return true if successful, false on failure. */
bool page_out (struct page *p) {

  if (p->frame == NULL) sys_exit(-1);

  if (!lock_held_by_current_thread(&p->frame->lock)) sys_exit(-1);
  bool flag = false;
  pagedir_clear_page(p->thread->pagedir, p->addr);
  if (pagedir_is_dirty(p->thread->pagedir, p->addr)){
    if (p->swap) flag = swap_out(p);
    else if (p->file != NULL){
      file_write_at(p->file, p->frame->base, p->file_size, p->file_ofs);
      flag = true;
    }
    p->frame = NULL;
    pagedir_set_dirty(p->thread->pagedir, p->addr, false);
  }

  return flag;
}
/* Returns true if page P's data has been accessed recently,
   false otherwise.
   P must have a frame locked into memory. */
bool page_accessed_recently (struct page *p) {

  if (p->frame == NULL) sys_exit(-1);
  if (!lock_held_by_current_thread(&p->frame->lock)) sys_exit(-1);

  if (pagedir_is_accessed(p->thread->pagedir, p->addr))
  {
    pagedir_set_accessed(p->thread->pagedir, p->addr, false);
    return true;
  }
  else return false;
}

/* Adds a mapping for user virtual address VADDR to the page hash
   table. Fails if VADDR is already mapped or if memory
   allocation fails. */
struct page * page_allocate (void *vaddr, bool read_only) {
  struct page *p = malloc (sizeof *p);
  if (p == NULL) return NULL;

  p->addr = pg_round_down (vaddr);
  p->frame = NULL;
  p->file = NULL;
  p->file_ofs = 0;
  p->file_size = 0;
  p->sector = (block_sector_t)(-1);

  p->swap = !read_only;
  p->read_only = read_only;

  struct thread * t = thread_current();
  p->thread = t;

  // try insert
  if (hash_insert(t->page_table, &p->hash_elem) != NULL){
    free(p);
    return NULL;
  }
  return p;
}



/* Evicts the page containing address VADDR
   and removes it from the page table. */
void page_deallocate (void *vaddr) {
  struct page *tar = page_for_addr(vaddr);

  if (tar == NULL) sys_exit(-1);
  if (tar->frame != NULL){
    frame_lock(tar);
    struct frame *f = tar->frame; //need this since page_out clears tar->frame
    if (!tar->swap && tar->file) page_out(tar);
    frame_free(f);
  }

  hash_delete(thread_current()->page_table, &tar->hash_elem);

  free(tar);

  return;
}



/* Returns a hash value for the page that E refers to. */
unsigned page_hash (const struct hash_elem *e, void *aux) {
  // copied from reference
  const struct page *p = hash_entry (e, struct page, hash_elem);
  return hash_bytes (&p->addr, sizeof p->addr);
}


/* Returns true if page A precedes page B. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux) {
  // copied from reference
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->addr < b->addr;
}


/* Tries to lock the page containing ADDR into physical memory.
   If WILL_WRITE is true, the page must be writeable;
   otherwise it may be read-only.
   Returns true if successful, false on failure. */
bool page_lock (const void *addr, bool will_write) {
  struct page *p = page_for_addr(addr);
  if (p == NULL) return false;
  if (p->read_only && will_write) return false;

  frame_lock(p);
  if (p->frame == NULL)
  {
    /* note do_page_in already locks the frame, so we don't need to frame lock it */
    if (!do_page_in(p)) return false;
    if (!pagedir_set_page (thread_current()->pagedir, p->addr,
                              p->frame->base, !p->read_only)) return false;
  }
  return true;
}


/* Unlocks a page locked with page_lock(). */
void page_unlock (const void *addr) {
  struct page *p = page_for_addr(addr);
  if (p == NULL) sys_exit(-1);
  frame_unlock(p->frame);
  return;
}
