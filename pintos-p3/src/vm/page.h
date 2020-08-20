#include <hash.h>
#include <stdbool.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#define STACK_MAX (1024 * 1024)

static struct page
{
	void *addr; //user virtual address, always with page offset 0
	struct frame *frame; //mapped frame
	struct thread *thread; //the thread that owns this page
	bool read_only; //whether or not read only

	struct hash_elem hash_elem; // Hash table element

	struct file *file;          // corresponding file
	off_t file_ofs;          // file offset
	off_t file_size;

	block_sector_t sector;       /* Start sector for swap slot; -1 if not having a swap slot. */

	bool swap;  // true is swap, false is file
};


static void destroy_page (struct hash_elem *p_, void *aux);
void page_exit (void);
static struct page *page_for_addr (const void *address);
static bool do_page_in (struct page *p);
bool page_in (void *fault_addr);
bool page_out (struct page *p);
bool page_accessed_recently (struct page *p);
struct page * page_allocate (void *vaddr, bool read_only);
void page_deallocate (void *vaddr);
unsigned page_hash (const struct hash_elem *e, void *aux);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
bool page_lock (const void *addr, bool will_write);
void page_unlock (const void *addr);
