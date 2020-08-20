#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
/*
Managing the frame table

The main job is to obtain a free frame to map a page to. To do so:

1. Easy situation is there is a free frame in frame table and it can be
obtained. If there is no free frame, you need to choose a frame to evict
using your page replacement algorithm based on setting accessed and dirty
bits for each page. See section 4.1.5.1 and A.7.3 to know details of
replacement algorithm(accessed and dirty bits) If no frame can be evicted
without allocating a swap slot and swap is full, you should panic the
kernel.

2. remove references from any page table that refers to.

3.write the page to file system or swap.

*/

// we just provide frame_init() for swap.c
// the rest is your responsibility


static struct frame *frames;

void
frame_init (void)
{
  void *base;

  lock_init (&scan_lock);

  frames = malloc (sizeof *frames * init_ram_pages);
  if (frames == NULL)
    PANIC ("out of memory allocating page frames");

  while ((base = palloc_get_page (PAL_USER)) != NULL)
    {
      struct frame *f = &frames[frame_cnt++];
      lock_init (&f->lock);
      f->base = base;
      f->page = NULL;
    }
}

/* Tries to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. */
 struct frame *try_frame_alloc_and_lock (struct page *page) {
   int i = 0;

   lock_acquire(&scan_lock);

   /* Use a simplified second chance algorithm.
      There are more for loops, but since frame_cnt is small
      the algorithm is still fast.*/

   /* first iterate to find empty frames */
   for (i = 0; i < frame_cnt; i++)
   {

    struct frame *f = &frames[i];

    if (!lock_try_acquire(&f->lock)) continue;

    if (f->page != NULL) {
      lock_release(&f->lock);
      continue;
    }

    // use the frame
    f->page = page;
    page->frame = f;
    lock_release(&scan_lock);
    return f;
   }

   /* If frames are all in use, for loop twice to find pages not recently accessed.
      We give second chance! */

   int j;
   for (j = 0; j < 2; j++)
    for (i = 0; i < frame_cnt; i++)
    {
      struct frame *f = &frames[i];
      if (!lock_try_acquire(&f->lock)) continue;
      if (page_accessed_recently(f->page))
      {
        lock_release(&f->lock);
        continue;
      }
      lock_release(&scan_lock); //release scan_lock to let other pages find frames
      if (page_out(f->page))
      {
        f->page = page;
        return f;
      }
      else
      {
        lock_release(&f->lock);
        lock_acquire(&scan_lock); //acquire scan_lock again and continue
        continue;
      }
    }
  /* release scan lock */
  lock_release(&scan_lock);
  return NULL;
}

/* Tries really hard to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. */
 struct frame *frame_alloc_and_lock (struct page *page) {

  /* try twice */
  struct frame *f;
  int i = 0;
  for (i = 0; i < 2; i++)
  {
    f = try_frame_alloc_and_lock(page);
    if (f != NULL) return f;
    //timer_msleep(100); // sleep a little bit and retry
  }
  return NULL;
}
/* Locks P's frame into memory, if it has one.
   Upon return, p->frame will not change until P is unlocked. */
void frame_lock (struct page *p) {
  struct frame *f = p->frame;
  if (f!= NULL){
    // DEBUG
    ASSERT (!lock_held_by_current_thread (&f->lock));
    lock_acquire(&f->lock);
    // check again the frame belongs to p, to account for asyncrhonous condition
    if (f != p->frame) lock_release(&f->lock);
  }
  return;
}
/* Releases frame F for use by another page.
   F must be locked for use by the current process.
   Any data in F is lost. */
void frame_free (struct frame *f) {
  if (!lock_held_by_current_thread(&f->lock)) sys_exit(-1);
  f->page = NULL;
  lock_release(&f->lock);
  return;
}
/* Unlocks frame F, allowing it to be evicted.
   F must be locked for use by the current process. */
void frame_unlock (struct frame *f) {
  if (!lock_held_by_current_thread(&f->lock)) sys_exit(-1);
  lock_release(&f->lock);
  return;
}
