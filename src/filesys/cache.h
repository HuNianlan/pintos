#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include <stdbool.h>

#define BUF_CACHE_SIZE 64 
typedef int cache_id;

void cache_init (void);
void cache_close (void);
void cache_read (block_sector_t sector, void *buffer);
void cache_write (block_sector_t sector, void *buffer);

#endif