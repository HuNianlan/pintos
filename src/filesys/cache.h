#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

void cache_init (void);
void cache_close (void);
void cache_read (block_sector_t sector, const void *buffer, off_t size,
                 off_t ofs);
void cache_write (block_sector_t sector, const void *buffer, off_t size,
                  off_t ofs);
void cache_backto_disk (void);

#endif