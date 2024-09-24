#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include <stdbool.h>

void cache_init (void);
void cache_close (void);
void cache_read (block_sector_t sector, void *buffer, off_t size, off_t ofs);
void cache_write (block_sector_t sector, void *buffer, off_t size, off_t ofs);

#endif