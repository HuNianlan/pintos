#include "filesys/cache.h"
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"

/* limited to a cache no greater than 64 sectors in size.*/
#define BLOCK_SECTOR_NUM 64
#define BLOCK_SECTOR_SIZE 512

struct cache_line
{
  // the occupied bit and dirty bit, initialized to 0
  bool occupied;
  bool dirty;

  block_sector_t block_sector; // which sector this cacheline correspond to
  // last access timestamp
  // update to `get_timestamp()` on access, initialized to 0
  uint64_t last_access;
  // the data bytes in this cache line, initialized to 0
  uint8_t data[BLOCK_SECTOR_SIZE];
  struct lock cache_line_lock; // Lock for each cache line.
};

struct read_ahead
{
  block_sector_t next_pos;          // the position that need to be read ahead by the read_ahead thread
  struct list_elem read_ahead_elem; // element in read_ahead_list
};

static struct cache_line cache[BLOCK_SECTOR_NUM]; // Cache array holding cached data blocks.
static struct lock cache_lock;                    // Synchronizes access to the cache.
static bool cache_shutdown = false;               // Flag to indicate if cache shutdown is triggered.
static struct lock read_ahead_lock;               // Synchronizes access to the read-ahead list.
static struct list read_ahead_list;               // Stores pending read-ahead requests.
static struct condition read_ahead_cond;          // Signals read-ahead threads to proceed.

static unsigned get_timestamp (void);
static struct cache_line *cache_lookup (block_sector_t sector);
static struct cache_line *cache_find_empty (void);
static struct cache_line *cache_evict (void);
static void cache_backto_disk (void);
static void periodic_cache_write (void *aux UNUSED);
static void read_ahead (void *aux UNUSED);
bool is_valid_pos (block_sector_t pos);

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
  lock_init (&read_ahead_lock);
  list_init (&read_ahead_list);
  cond_init (&read_ahead_cond);
  for (unsigned i = 0; i < BLOCK_SECTOR_NUM; i++)
    {
      memset (&cache[i], 0, sizeof (struct cache_line));
      lock_init (&cache[i].cache_line_lock);
    }
  thread_create ("periodic_cache_write_thread", PRI_DEFAULT, periodic_cache_write, NULL);
  thread_create ("read_ahead_thread", PRI_DEFAULT, read_ahead, NULL); 
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

  lock_acquire (&victim_line->cache_line_lock);
  if (victim_line->dirty) // write back before evicting if dirty
    {
      block_write (fs_device, victim_line->block_sector, victim_line->data);
    }

  memset (victim_line->data, 0, sizeof (victim_line->data));
  lock_release (&victim_line->cache_line_lock); 

  return victim_line;
}

/* 1. read a disk and load into a cache list
 * 2. copy appropriate amount of cache into a buffer
 */
void
cache_read (block_sector_t pos, void *buffer)
{
  /* read head */
  lock_acquire (&read_ahead_lock);

  struct read_ahead *read_ahead = malloc (sizeof (struct read_ahead));
  if (read_ahead && is_valid_pos (pos + 1))
    {
      read_ahead->next_pos = pos + 1;

      list_push_back (&read_ahead_list, &read_ahead->read_ahead_elem);
      cond_broadcast (&read_ahead_cond, &read_ahead_lock);
    }
  else
      free (read_ahead);
    
  lock_release (&read_ahead_lock);

  // lock_acquire (&cache_lock);
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
  lock_acquire (&sector->cache_line_lock);
  memcpy (buffer, sector->data, BLOCK_SECTOR_SIZE); // read data
  sector->last_access = get_timestamp();
  lock_release (&sector->cache_line_lock);

  // lock_release(&cache_lock);
}

/**
 * Writes SECTOR_SIZE bytes of data into the disk sector
 * specified by 'sector', from `source` (user memory address).
 */
void
cache_write (block_sector_t pos, void *buffer)
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
      sector->occupied = true;
    }
  // cache hit
  lock_acquire (&sector->cache_line_lock);
  memcpy (sector->data, buffer, BLOCK_SECTOR_SIZE); // write data
  sector->last_access = get_timestamp();
  sector->dirty = true;
  lock_release (&sector->cache_line_lock);
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

/* Create another thread for periodic write:
 Because write-behind makes your file system more fragile in the face of
 crashes, in addition you should periodically write all dirty, cached blocks
 back to disk.*/
static void
periodic_cache_write (void *aux UNUSED)
{
  while (!cache_shutdown)
    {
      timer_msleep (30000);   
      cache_backto_disk (); // write all dirty cache to disk
    }
}

/*  automatically fetch the next block of a file into the cache when one block
 * of a file is read, in case that block is about to be read. Read-ahead is
 * only really useful when done asynchronously. That means, if a process
 * requests disk block 1 from the file, it should block until disk block 1 is
 * read in, but once that read is complete, control should return to the
 * process immediately. The read-ahead request for disk block 2 should be
 * handled asynchronously, in the background*/
void
read_ahead (void *aux UNUSED)
{

  while (true)
    {
      lock_acquire (&read_ahead_lock);

      while (list_empty (&read_ahead_list))
        cond_wait (&read_ahead_cond, &read_ahead_lock);

      lock_release (&read_ahead_lock);

      struct read_ahead *ra = list_entry (list_pop_front (&read_ahead_list),
                                          struct read_ahead, read_ahead_elem);

      block_sector_t pos = ra->next_pos;

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

      free (ra);
    }
}



bool
is_valid_pos (block_sector_t pos)
{
  struct block *block = block_get_role (BLOCK_FILESYS);
  // Check if the position is valid, i.e., within the block size.
  if (pos >= block_size (block))
    return false;
  return false;
}