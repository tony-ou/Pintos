#include "threads/synch.h"

/*
Just prototypes. See frame.c for more detail.
*/

/* frame structure */
static struct frame 
{
	void *base; //kernel vir address
	struct page *page; //corresponding process page
	struct lock lock; // lock the frame
};

static size_t frame_cnt;
static struct lock scan_lock;
static size_t hand;


void frame_init (void);
 struct frame *try_frame_alloc_and_lock (struct page *page);
 struct frame *frame_alloc_and_lock (struct page *page);
void frame_lock (struct page *p);
void frame_free (struct frame *f);
void frame_unlock (struct frame *f);


