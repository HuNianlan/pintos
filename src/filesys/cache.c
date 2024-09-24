#include "filesys/cache.h"
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>

/* limited to a cache no greater than 64 sectors in size.*/
#define BLOCK_SECTOR_NUM 64
#define BLOCK_SECTOR_SIZE 512

struct cache_line
{
  // the occupied bit and dirty bit, initialized to 0
  bool occupied;
  bool dirty;

  block_sector_t block_sector;
  // last access timestamp
  // update to `get_timestamp()` on access, initialized to 0
  uint64_t last_access;
  // the data bytes in this cache line, initialized to 0
  uint8_t data[BLOCK_SECTOR_SIZE];
};

static struct cache_line cache[BLOCK_SECTOR_NUM];
static struct lock cache_lock;
static bool cache_shutdown = false;

/* Create another thread for periodic write:
 Because write-behind makes your file system more fragile in the face of
 crashes, in addition you should periodically write all dirty, cached blocks
 back to disk.*/
static void periodic_cache_write (void *aux UNUSED);
static unsigned get_timestamp (void);
static struct cache_line *cache_lookup (block_sector_t sector);
static struct cache_line *cache_find_empty (void);
static struct cache_line *cache_evict (void);
static void cache_backto_disk (void);

unsigned
get_timestamp ()
{
  static unsigned ts = 1;
  return ++ts;
}

void
cache_init (void)
{
  cache_shutdown = false;
  lock_init (&cache_lock);
  for (unsigned i = 0; i < BLOCK_SECTOR_NUM; i++)
    {
      memset (&cache[i], 0, sizeof (struct cache_line));
    }
  thread_create ("periodic_cache_write", PRI_DEFAULT, periodic_cache_write,
                 NULL);
}

/* traverse the cache
  return the corresponding *cache_line to block_sector if cache hit，
  return NULL if cache miss.
 */
static struct cache_line *
cache_lookup (block_sector_t sector)
{

  for (unsigned i = 0; i < BLOCK_SECTOR_NUM; i++)
    {
      if (cache[i].occupied && cache[i].block_sector == sector)
        {
          // cache hit.
          return &(cache[i]);
        }
    }
  return NULL; // cache miss
}

/* return the first empty(not occupied) cacheline*/
static struct cache_line *
cache_find_empty (void)
{
  for (unsigned i = 0; i < BLOCK_SECTOR_NUM; i++)
    {
      if (!cache[i].occupied)
        {
          return &(cache[i]);
        }
    }
  return NULL;
}

/* evict a cacheline by LRU*/
static struct cache_line *
cache_evict (void)
{
  struct cache_line *victim_line = NULL;
  uint64_t min_access = UINT64_MAX;

  for (unsigned i = 0; i < BLOCK_SECTOR_NUM; i++)
    {
      if (cache[i].last_access < min_access)
        {
          min_access = cache[i].last_access;
          victim_line = &cache[i];
        }
    }

  if (victim_line->dirty) // write back before evicting if dirty
    {
      block_write (fs_device, victim_line->block_sector, victim_line->data);
      memset (victim_line->data, 0, sizeof (victim_line->data));
    }
  return victim_line;
}

/* 1. read a disk and load into a cache list
 * 2. copy appropriate amount of cache into a buffer
 */
void
cache_read (block_sector_t pos, void *buffer, off_t size, off_t ofs)
{
  lock_acquire (&cache_lock);
  struct cache_line *sector = cache_lookup (pos);

  // cache miss
  if (sector == NULL)
    {
      sector = cache_find_empty ();

      // cache full, first evict then write.
      if (sector == NULL)
        {
          sector = cache_evict ();
        }
      // empty cacheline exist, write in that empty cacheline.
      block_read (fs_device, pos, sector->data);
      sector->block_sector = pos;
      sector->dirty = false;
      sector->occupied = true;
    }
  // cache hit
  memcpy (buffer, sector->data + ofs, size); // read data
  sector->last_access = get_timestamp();
  lock_release(&cache_lock);
}

/**
 * Writes SECTOR_SIZE bytes of data into the disk sector
 * specified by 'sector', from `source` (user memory address).
 */
void
cache_write (block_sector_t pos, void *buffer, off_t size, off_t ofs)
{
  lock_acquire (&cache_lock);
  struct cache_line *sector = cache_lookup (pos);

  // cache miss
  if (sector == NULL)
    {
      sector = cache_find_empty ();

      // cache full, first evict then write.
      if (sector == NULL)
        {
          sector = cache_evict ();
        }
      // empty cacheline exist, write in that empty cacheline.
      // if (ofs > 0 || size < DISK_SECTOR_SIZE - ofs) // why?
      block_read (fs_device, pos, sector->data);
      sector->block_sector = pos;
      sector->occupied = true;
    }
  // cache hit
  memcpy (sector->data + ofs, buffer, size); // write data
  sector->last_access = get_timestamp();
  sector->dirty = true;
  lock_release (&cache_lock);
}

void
cache_close (void)
{
  lock_acquire (&cache_lock);
  cache_shutdown = true;  // stop periodic_cache_write()
  cache_backto_disk();
  lock_release (&cache_lock);
}

/*
 * Writes all dirty cache blocks to disk and sets dirty false.
 *
 * Called in periodic_cache_write() to periodically flushes dirty blocks to
 * prevent data loss in case of a crash. 
 * 
 * Also called in filesys_done() to
 * ensure cache is written back before system shutdown.
 */
void
cache_backto_disk (void)
{
  for (unsigned i = 0; i < BLOCK_SECTOR_NUM; i++)
    {
      if (cache[i].dirty)
        {
          block_write (fs_device, cache[i].block_sector, cache[i].data);
          cache[i].dirty = false;
        }
    }
}

static void
periodic_cache_write (void *aux UNUSED)
{
  while (!cache_shutdown)
    {
      timer_sleep (1024);   // maybe any number not too big is avaliable
      cache_backto_disk (); // write all dirty cache to disk
    }
}