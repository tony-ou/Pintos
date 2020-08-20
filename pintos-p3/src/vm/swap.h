/*
Just prototypes. See swap.c for more details.
*/
#include<stdio.h>
#include <stdbool.h>
/* The swap device. */
static struct block *swap_device;

/* Used swap pages. */
static struct bitmap *swap_bitmap;

/* Protects swap_bitmap. */
static struct lock swap_lock;

/* Number of sectors per page. */
#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init (void);
bool swap_in (struct page *p);
bool swap_out (struct page *p);
