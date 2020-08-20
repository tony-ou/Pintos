#include "filesys/cache.h"
#include <debug.h>
#include <string.h>
#include "filesys/filesys.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

#define INVALID_SECTOR ((block_sector_t) -1)


struct cache_block
  {
    struct lock block_lock;
    struct condition no_readers_or_writers;
    struct condition no_writers;
    int readers, read_waiters;
    int writers, write_waiters;
    block_sector_t sector;
    bool up_to_date;
    bool dirty;
    struct lock data_lock;
    uint8_t data[BLOCK_SECTOR_SIZE];
  };

/* Cache. */
#define CACHE_CNT 64
struct cache_block cache[CACHE_CNT];
struct lock cache_sync;
static int hand = 0;


static void flushd_init (void);
static void readaheadd_init (void);
static void readaheadd_submit (block_sector_t sector);


/* Initializes cache. */
void
cache_init (void)
{
  int i;

  lock_init(&cache_sync);
  for (i = 0; i < CACHE_CNT; i++)
  {
    lock_init(&cache[i].block_lock);
    cond_init(&cache[i].no_readers_or_writers);
    cond_init(&cache[i].no_writers);
    cache[i].readers = 0;
    cache[i].read_waiters = 0;
    cache[i].writers = 0;
    cache[i].write_waiters = 0;
    cache[i].sector = INVALID_SECTOR;
    cache[i].up_to_date = false;
    cache[i].dirty = false;
    lock_init(&cache[i].data_lock);
  }
  flushd_init();
  return;
}

/* Flushes cache to disk. */
void
cache_flush (void)
{
  int i;
  for (i = 0; i < CACHE_CNT; i++)
  {
    block_sector_t sector;
    lock_acquire(&cache[i].block_lock);
    sector = cache[i].sector;
    lock_release(&cache[i].block_lock);
    if (sector == INVALID_SECTOR) continue;

    struct cache_block *b = cache_lock(sector, EXCLUSIVE);
    if (b->dirty && b->up_to_date)
    {
      block_write(fs_device, b->sector, b->data);
      b->dirty = false;
    }
    cache_unlock(b);
  }
  return;

}

/* Locks the given SECTOR into the cache and returns the cache
   block.
   If TYPE is EXCLUSIVE, then the block returned will be locked
   only by the caller.  The calling thread must not already
   have any lock on the block.
   If TYPE is NON_EXCLUSIVE, then block returned may be locked by
   any number of other callers.  The calling thread may already
   have any number of non-exclusive locks on the block. */
struct cache_block *
cache_lock (block_sector_t sector, enum lock_type type)
{

  int i;
  struct cache_block *b;
  bool in_cache = false;

 try_again:
  lock_acquire(&cache_sync);

  /* Is the block already in-cache? */
  for (i = 0; i < CACHE_CNT; i++)
  {
    b = &cache[i];
    
    lock_acquire(&b->block_lock); //we don't use try_lock here in case the desired sector is being locked
    if (b->sector == sector)
    {
      lock_release(&cache_sync);
      in_cache = true;
      goto found_block;
    }
    lock_release(&b->block_lock);
  }
    
  /* Not in cache.  Find empty slot. */
  for (i = 0; i < CACHE_CNT; i++)
  {

    b = &cache[i];
    if (!lock_try_acquire(&b->block_lock)) continue;
   
    if (cache[i].sector == INVALID_SECTOR)
    {
      b->sector = sector;
      lock_release(&cache_sync);

      goto found_block;
    }
    lock_release(&b->block_lock);
  }

  /* No empty slots.  Evict something. */
  for (i = 0; i < CACHE_CNT; i++)
  {
    hand++;
    if (hand >= CACHE_CNT) hand -= CACHE_CNT;

    b = &cache[hand];
    if (!lock_try_acquire(&b->block_lock)) continue; //maybe need lock_acquire here?

    //evict the block?
    if (b->read_waiters || b->write_waiters || b->readers || b->writers)
    {
      lock_release(&b->block_lock);
      continue;
    }

    lock_release(&cache_sync); //we've found a victim block  so release cache sync

    if (b->dirty && b->up_to_date)
    {
      block_write(fs_device, b->sector, b->data);
    }
    b->sector = sector;
    goto found_block;
  }

  /* Wait for cache contention to die down. */

  // sometimes, you might get into a situation where you
  // cannot find a block to evict, or you cannot lock
  // the desired block. If that's the case there might
  // some contention. So the safest way to do this, is to
  // release the cache_sync lock, and sleep for 1 sec, and
  // try again the whole operation.

  lock_release (&cache_sync);
  timer_msleep (1000);
  goto try_again;

  //after we found a block for the sector
  found_block:
    ASSERT(b != NULL);
    ASSERT(lock_held_by_current_thread(&b->block_lock));

    if (!in_cache){
      b->dirty = false;
      b->up_to_date = false;
      b->readers = b->read_waiters = b->writers = b->write_waiters = 0;
    }

    if (type == EXCLUSIVE)
    {
      b->write_waiters++; //note we've held block_lock so these are protected
      if (b->readers > 0 || b->read_waiters > 0 || b->writers > 0)
        //prevent starving
        while (b->readers > 0 || b->writers > 0)
          cond_wait(&b->no_readers_or_writers, &b->block_lock);
      b->write_waiters--;
      b->writers++;
    }
    else
    {
      b->read_waiters++; //treat non-exclusive write as read??
      if (b->writers > 0 || b->write_waiters > 0)
        while (b->writers > 0)
          cond_wait(&b->no_writers, &b->block_lock);
      b->read_waiters--;
      b->readers++;
    }

    if (b->sector != sector) goto try_again; //in case our cache is evicted during waiting; possible?
    lock_release(&b->block_lock);

    return b;
}

/* Bring block B up-to-date, by reading it from disk if
   necessary, and return a pointer to its data.
   The caller must have an exclusive or non-exclusive lock on
   B. */
void *
cache_read (struct cache_block *b)
{
  ASSERT(b != NULL);

  if (b->up_to_date)
  {
    return b->data;
  }

  lock_acquire(&b->data_lock); // we don't need to hold block_lock since prereq that caller has lock on b
  block_read (fs_device, b->sector, b->data);
  b->up_to_date = true;
  b->dirty = false;
  lock_release(&b->data_lock);

  return b->data;
}

/* Zero out block B, without reading it from disk, and return a
   pointer to the zeroed data.
   The caller must have an exclusive lock on B. */
void *
cache_zero (struct cache_block *b)
{
  ASSERT(b != NULL);
  lock_acquire(&b->data_lock);
  memset (b->data, 0, BLOCK_SECTOR_SIZE);
  b->up_to_date = true;
  b->dirty = true;
  lock_release(&b->data_lock);
  return b->data;
}

/* Marks block B as dirty, so that it will be written back to
   disk before eviction.
   The caller must have a read or write lock on B,
   and B must be up-to-date. */
void
cache_dirty (struct cache_block *b)
{
  ASSERT(b != NULL);
  ASSERT(b->up_to_date);
  b->dirty = true;
}

/* Unlocks block B.
   If B is no longer locked by any thread, then it becomes a
   candidate for immediate eviction. */
void
cache_unlock (struct cache_block *b)
{
  ASSERT(b != NULL);
  lock_acquire(&b->block_lock);

  if (b->writers > 0)
  {
    //then it must be no reader and writer = 1
    //but reade_wait, write_waiter might be nonzero
    b->writers--;
    ASSERT(b->writers == 0);
    ASSERT(b->readers == 0);
    if (b->read_waiters)
      cond_broadcast(&b->no_writers, &b->block_lock); //can allow multiple readers
    else
      cond_signal(&b->no_readers_or_writers, &b->block_lock);
  }
  else if (b->readers > 0)
  {
    //then it must be reader nonzero (might be greater than 1), read_wait zero, writer zero
    //write_waiter might be nonzero
    ASSERT(b->writers == 0);
    b->readers--;
    if (b->readers == 0)
      cond_signal(&b->no_readers_or_writers, &b->block_lock);
  }
  lock_release(&b->block_lock);
}

/* If SECTOR is in the cache, evicts it immediately without
   writing it back to disk (even if dirty).
   The block must be entirely unused. */
void
cache_free (block_sector_t sector)
{
  int i = 0;
  lock_acquire(&cache_sync);
  struct cache_block *b;
  for (i = 0; i < CACHE_CNT; i++)
  {
    b = &cache[i];
    lock_acquire(&b->block_lock);
    if (b->sector != sector)
    {
      lock_release(&b->block_lock);
      continue;
    }
    lock_release(&cache_sync);
    b->sector = INVALID_SECTOR; // we zero-out the readers,etc when finding empty slot in cache_lock
    lock_release(&b->block_lock);
    return;
  }
  lock_release(&cache_sync);
    
}


/* Flush daemon. */

static void flushd (void *aux);

/* Initializes flush daemon. */
static void
flushd_init (void)
{
  thread_create ("flushd", PRI_MIN, flushd, NULL);
}

/* Flush daemon thread. */
static void
flushd (void *aux UNUSED)
{
  for (;;)
    {
      timer_msleep (30 * 1000);
      cache_flush ();
    }
}
