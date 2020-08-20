#include "filesys/inode.h"
#include <bitmap.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_CNT 123
#define INDIRECT_CNT 1
#define DBL_INDIRECT_CNT 1
#define SECTOR_CNT (DIRECT_CNT + INDIRECT_CNT + DBL_INDIRECT_CNT)

#define PTRS_PER_SECTOR ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))
#define INODE_SPAN ((DIRECT_CNT                                              \
                     + PTRS_PER_SECTOR * INDIRECT_CNT                        \
                     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT) \
                    * BLOCK_SECTOR_SIZE)

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t sectors[SECTOR_CNT]; /* Sectors. */
    enum inode_type type;               /* FILE_INODE or DIR_INODE. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    struct lock lock;                   /* Protects the inode. */

    /* Denying writes. */
    struct lock deny_write_lock;        /* Protects members below. */
    struct condition no_writers_cond;   /* Signaled when no writers. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    int writer_cnt;                     /* Number of writers. */
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Controls access to open_inodes list. */
static struct lock open_inodes_lock;

static void deallocate_inode (const struct inode *);

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
}

/* Initializes an inode of the given TYPE, writes the new inode
   to sector SECTOR on the file system device, and returns the
   inode thus created.  Returns a null pointer if unsuccessful,
   in which case SECTOR is released in the free map. */
struct inode *
inode_create (block_sector_t sector, enum inode_type type)
{

  // remember don't write to the disk ..
  // please write to buffer cache

  // get a cache block
  struct cache_block* cb = cache_lock(sector,EXCLUSIVE);

  // get disk inode
  struct inode_disk *in_d = cache_zero(cb);
  in_d->magic = INODE_MAGIC;
  in_d->type = type;
  in_d->length = 0;
  cache_dirty(cb);
  cache_unlock(cb);

  struct inode *in = inode_open(sector);
  if (in == NULL) free_map_release(sector);
  return in;

}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  // if the in is opened
  lock_acquire(&open_inodes_lock);
  struct list_elem *iter;
  for (iter = list_begin(&open_inodes); iter != list_end(&open_inodes);
    iter = list_next(iter)){
      struct inode *in = list_entry(iter, struct inode, elem);
      if (in->sector == sector){
        in->open_cnt++;
        lock_release(&open_inodes_lock);
        return in;
      }
  }

  // malloc inode
  struct inode *in = malloc(sizeof (struct inode));
  if (in == NULL) {
    lock_release(&open_inodes_lock);
    return NULL;

  }
  in->removed = false;
  in->open_cnt = 1;
  in->deny_write_cnt = 0;
  in->sector = sector;
  lock_init (&in->lock);
  lock_init (&in->deny_write_lock);
  cond_init (&in->no_writers_cond);

  list_push_back(&open_inodes, &in->elem);
  lock_release(&open_inodes_lock);

  return in;

}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    {
      lock_acquire (&open_inodes_lock);
      inode->open_cnt++;
      lock_release (&open_inodes_lock);
    }
  return inode;
}

/* Returns the type of INODE. */
enum inode_type
inode_get_type (const struct inode *inode)
{
  // read from cache ..

  struct cache_block *cb = cache_lock(inode->sector, NON_EXCLUSIVE);

  struct inode_disk * in_d = cache_read(cb);
  enum inode_type result = in_d->type;
  cache_unlock(cb);
  return result;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  // ...
  // deallocate inode

  if (inode == NULL) return;
  lock_acquire(&open_inodes_lock);
  inode->open_cnt --;
  if (inode->open_cnt == 0){
    list_remove(&inode->elem);

    if (inode->removed) deallocate_inode(inode);
    free (inode);
  }
  lock_release(&open_inodes_lock);
  return;

}

/* Deallocates SECTOR and anything it points to recursively.
   LEVEL is 2 if SECTOR is doubly indirect,
   or 1 if SECTOR is indirect,
   or 0 if SECTOR is a data sector. */
static void
deallocate_recursive (block_sector_t sector, int level)
{
  // cache_Read, deallocate_recursive, .....
  if (level == 0) {
    cache_free (sector);
    free_map_release(sector);
    return;
  }

  struct cache_block * cb = cache_lock (sector, EXCLUSIVE);
  block_sector_t *sec_pts = cache_read(cb);
  int i;
  for (i = 0; i < PTRS_PER_SECTOR; i++){
    if (sec_pts[i] != 0) deallocate_recursive(sec_pts[i], level-1);
  }
  cache_unlock(cb);

  cache_free (sector);
  free_map_release(sector);
  return;
}

/* Deallocates the blocks allocated for INODE. */
static void
deallocate_inode (const struct inode *inode)
{
  // deallocate recursive ..
  struct cache_block * cb = cache_lock(inode->sector, EXCLUSIVE);
  struct inode_disk * in_d = cache_read(cb);
  int i;
  for (i = 0; i < SECTOR_CNT; i++){
    if (in_d->sectors[i] != NULL){
      int level = 0;
      if (i >= DIRECT_CNT) level = 1;
      if (i >= DIRECT_CNT + INDIRECT_CNT) level = 2;
      deallocate_recursive(in_d->sectors[i],level);
    }
  }
  cache_unlock(cb);
  deallocate_recursive(inode->sector, 0);
  return;
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Translates SECTOR_IDX into a sequence of block indexes in
   OFFSETS and sets *OFFSET_CNT to the number of offsets. */
static void
calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt)
{
  /* Handle direct blocks. */

  if (sector_idx < DIRECT_CNT){
    *offset_cnt = 1;
    offsets[0] = sector_idx;
    return;
  }

  /* Handle indirect blocks. */
  if (sector_idx < PTRS_PER_SECTOR*INDIRECT_CNT + DIRECT_CNT){
    *offset_cnt = 2;
    offsets[0] = DIRECT_CNT + (sector_idx-DIRECT_CNT)/PTRS_PER_SECTOR;
    offsets[1] = (sector_idx - DIRECT_CNT) % PTRS_PER_SECTOR;
    return;
  }

  /* Handle doubly indirect blocks. */
  off_t left = sector_idx - DIRECT_CNT - PTRS_PER_SECTOR*INDIRECT_CNT;
  if (left < PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT){
    *offset_cnt = 3;
    offsets[0] = DIRECT_CNT + INDIRECT_CNT + left/(PTRS_PER_SECTOR * PTRS_PER_SECTOR);
    offsets[1] = left / PTRS_PER_SECTOR;
    offsets[2] = left * PTRS_PER_SECTOR;
    return;
  }

  // out of limit
  sys_exit(-1);
  return;
}

/* Retrieves the data block for the given byte OFFSET in INODE,
   setting *DATA_BLOCK to the block.
   Returns true if successful, false on failure.
   If ALLOCATE is false, then missing blocks will be successful
   with *DATA_BLOCk set to a null pointer.
   If ALLOCATE is true, then missing blocks will be allocated.
   The block returned will be locked, normally non-exclusively,
   but a newly allocated block will have an exclusive lock. */
static bool
get_data_block (struct inode *inode, off_t offset, bool allocate,
                struct cache_block **data_block)
{

  //calculate indices
  size_t offsets[3];
  size_t offset_cnt;
  calculate_indices(offset/BLOCK_SECTOR_SIZE, offsets, &offset_cnt);

  // get data
  int level = 0;
  block_sector_t cur_s = inode->sector;
  while(1)
    {
      struct cache_block *cur_b = cache_lock(cur_s,NON_EXCLUSIVE);
      uint32_t *cur_data = cache_read(cur_b);

      // there is data, get or advance
      if (cur_data[offsets[level]])
        {
          cur_s = cur_data[offsets[level]];
          level ++;

          //get data
          if (level == offset_cnt)
            {
              *data_block = cache_lock(cur_s, NON_EXCLUSIVE);
              cache_unlock (cur_b);
              return true;
            }
          else {
            cache_unlock(cur_b);
            continue;
          }

        }

      // no data
      if (!allocate)
        {
          *data_block = NULL;
          cache_unlock(cur_b);
          return true;
        }
      else {
        cache_unlock(cur_b);
        cur_b = cache_lock(cur_s, EXCLUSIVE);
        cur_data = cache_read(cur_b);

        // synchronize check
        if (cur_data[offsets[level]])
          {
            cache_unlock(cur_b);
            continue;
          }

        // fill 0
        bool alloc_flag = free_map_allocate(&cur_data[offsets[level]]);
        if (alloc_flag){
          cache_dirty (cur_b);
          block_sector_t zero_s = cur_data[offsets[level]];
          struct cache_block* zero_block = cache_lock(zero_s,EXCLUSIVE);
          cache_zero (zero_block);
          cache_unlock (cur_b);

          if (level + 1 < offset_cnt){
            cache_unlock(zero_block);
            continue;
          } else {
            *data_block = zero_block;
            return true;
          }
        }
        else {
          *data_block = NULL;
          cache_unlock(cur_b);
          return false;
        }
      }
    }
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  while (size > 0)
    {
      /* Sector to read, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      struct cache_block *block;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0 || !get_data_block (inode, offset, false, &block))
        break;

      if (block == NULL)
        memset (buffer + bytes_read, 0, chunk_size);
      else
        {
          const uint8_t *sector_data = cache_read (block);
          memcpy (buffer + bytes_read, sector_data + sector_ofs, chunk_size);
          cache_unlock (block);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Extends INODE to be at least LENGTH bytes long. */
static void
extend_file (struct inode *inode, off_t length)
{
  if (length <= inode_length(inode)) return;

  struct cache_block * cb = cache_lock(inode->sector,EXCLUSIVE);
  struct inode_disk *in_d = cache_read(cb);
  if (in_d->length < length){
    in_d ->length = length;
    cache_dirty(cb);
  }
  cache_unlock(cb);
  return;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  /* Don't write if writes are denied. */
  lock_acquire (&inode->deny_write_lock);
  if (inode->deny_write_cnt)
    {
      lock_release (&inode->deny_write_lock);
      return 0;
    }
  inode->writer_cnt++;
  lock_release (&inode->deny_write_lock);


  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      struct cache_block *block;
      uint8_t *sector_data;

      /* Bytes to max inode size, bytes left in sector, lesser of the two. */
      off_t inode_left = INODE_SPAN - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;

      if (chunk_size <= 0 || !get_data_block (inode, offset, true, &block))
        break;

      sector_data = cache_read (block);
      memcpy (sector_data + sector_ofs, buffer + bytes_written, chunk_size);
      cache_dirty (block);
      cache_unlock (block);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  extend_file (inode, offset);

  lock_acquire (&inode->deny_write_lock);
  if (--inode->writer_cnt == 0)
    cond_signal (&inode->no_writers_cond, &inode->deny_write_lock);
  lock_release (&inode->deny_write_lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  lock_acquire(&inode->deny_write_lock);
  while (inode->writer_cnt > 0){
    cond_wait(&inode->no_writers_cond, &inode->deny_write_lock);
  }
  inode->deny_write_cnt++;

  lock_release(&inode->deny_write_lock);
  return;
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  lock_acquire(&inode->deny_write_lock);
  if (inode->deny_write_cnt <= 0) sys_exit(-1);
  inode->deny_write_cnt--;
  lock_release(&inode->deny_write_lock);
  return;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct cache_block * cb = cache_lock (inode->sector, NON_EXCLUSIVE);
  struct inode_disk * in_d = cache_read(cb);
  off_t result = in_d->length;
  cache_unlock(cb);
  return result;
}

/* Returns the number of openers. */
int
inode_open_cnt (const struct inode *inode)
{
  int open_cnt;

  lock_acquire (&open_inodes_lock);
  open_cnt = inode->open_cnt;
  lock_release (&open_inodes_lock);

  return open_cnt;
}

/* Locks INODE. */
void
inode_lock (struct inode *inode)
{
  lock_acquire (&inode->lock);
}

/* Releases INODE's lock. */
void
inode_unlock (struct inode *inode)
{
  lock_release (&inode->lock);
}
