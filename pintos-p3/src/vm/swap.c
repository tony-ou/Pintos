
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "userprog/syscall.h"

/*

Managing the swap table

You should handle picking an unused swap slot for evicting a page from its
frame to the swap partition. And handle freeing a swap slot which its page
is read back.

You can use the BLOCK_SWAP block device for swapping, obtaining the struct
block that represents it by calling block_get_role(). Also to attach a swap
disk, please see the documentation.

and to attach a swap disk for a single run, use this option ‘--swap-size=n’

*/

// we just provide swap_init() for swap.c
// the rest is your responsibility

/* Set up*/
void
swap_init (void)
{
  swap_device = block_get_role (BLOCK_SWAP);
  if (swap_device == NULL)
    {
      printf ("no swap device--swap disabled\n");
      swap_bitmap = bitmap_create (0);
    }
  else
    swap_bitmap = bitmap_create (block_size (swap_device)
                                 / PAGE_SECTORS);
  if (swap_bitmap == NULL)
    PANIC ("couldn't create swap bitmap");
  lock_init (&swap_lock);
}

/* Swaps in page P, which must have a locked frame
   (and be swapped out). */
bool swap_in (struct page *p)
{
    // might want to use these functions:
    // - lock_held_by_current_thread()

    if(!lock_held_by_current_thread(&p->frame->lock)) sys_exit(-1) ;

    // - block_read()
    int i;
    for (i = 0; i < PAGE_SECTORS; i++)
      block_read(swap_device, p->sector + i, p->frame->base + i * BLOCK_SECTOR_SIZE);

    // - bitmap_reset()
    lock_acquire(&swap_lock);
    bitmap_reset(swap_bitmap, p->sector / PAGE_SECTORS);

    /* Update to show this page has no mapped sector now */
    p->sector = (block_sector_t)-1;
    lock_release(&swap_lock);

    return true;
}

/* Swaps out page P, which must have a locked frame. */
bool swap_out (struct page *p)
{
  // might want to use these functions:
  // - lock_held_by_current_thread()

  if(!lock_held_by_current_thread(&p->frame->lock)) sys_exit(-1) ;

  // - bitmap_scan_and_flip()
  lock_acquire(&swap_lock);
  size_t dest_sector = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);

  if (dest_sector == BITMAP_ERROR) {
    lock_release(&swap_lock);
    return false;
  }

  /* update starting sector in page struct */
  p->sector = dest_sector * PAGE_SECTORS;
  lock_release(&swap_lock);

  /* write page content to sector */
  int i;
  for (i = 0; i < PAGE_SECTORS; i++)
  // - block_write()
    block_write(swap_device, p->sector + i, p->frame->base + i * BLOCK_SECTOR_SIZE);


  return true;
}
