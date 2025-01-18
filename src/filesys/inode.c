#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCKS_COUNT 100
#define INDIRECT_BLOCKS_COUNT 20
#define DOUBLY_INDIRECT_BLOCKS_COUNT 5
#define INDIRECT_BLOCKS_PER_SECTOR 128
#define DOUBLY_INDIRECT_BLOCKS_PER_SECTOR INDIRECT_BLOCKS_PER_SECTOR * INDIRECT_BLOCKS_PER_SECTOR

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  /** Data sectors */
  block_sector_t direct_blocks[DIRECT_BLOCKS_COUNT];                   // Direct blocks
  block_sector_t indirect_blocks[INDIRECT_BLOCKS_COUNT];               // Indirect blocks
  block_sector_t doubly_indirect_blocks[DOUBLY_INDIRECT_BLOCKS_COUNT]; // Doubly indirect blocks

  bool is_dir;    /* whether the inode represent a directory or a file*/
  off_t length;   /* File size in bytes. */
  unsigned magic; /* Magic number. */
};


static struct lock file_extend_lock;      // lock to prevent race conditions when extending a file.
static struct condition file_extend_cond; // condition variable to signal when a file extension operation can proceed or wait for completion.

static bool inode_allocate (struct inode_disk *disk_inode, off_t length);
static bool inode_deallocate (struct inode *inode);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

static inline size_t
min (size_t a, size_t b)
{
  return a < b ? a : b;
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the sector corresponding to the given block index in the inode.
   Returns -1 if the index is out of range. */
static block_sector_t
index_to_sector (const struct inode_disk *idisk, off_t index)
{
    block_sector_t sector;

    // direct blocks
    if (index < DIRECT_BLOCKS_COUNT)
      {
        return idisk->direct_blocks[index];
      }

    // single indirect blocks
    if (index < DIRECT_BLOCKS_COUNT + INDIRECT_BLOCKS_COUNT * INDIRECT_BLOCKS_PER_SECTOR)
      {
        index -= DIRECT_BLOCKS_COUNT;
        size_t indirect_block_index = index / INDIRECT_BLOCKS_PER_SECTOR;

        block_sector_t indirect_blocks[INDIRECT_BLOCKS_PER_SECTOR];
        cache_read (idisk->indirect_blocks[indirect_block_index], indirect_blocks);

        sector = indirect_blocks[index % INDIRECT_BLOCKS_PER_SECTOR];

        return sector;
      }

    // doubly indirect blocks
    if (index < DIRECT_BLOCKS_COUNT + INDIRECT_BLOCKS_COUNT * INDIRECT_BLOCKS_PER_SECTOR
                    + DOUBLY_INDIRECT_BLOCKS_COUNT * DOUBLY_INDIRECT_BLOCKS_PER_SECTOR)
      {
        index -= INDIRECT_BLOCKS_COUNT * INDIRECT_BLOCKS_PER_SECTOR;
        size_t first_level_index = index / (DOUBLY_INDIRECT_BLOCKS_PER_SECTOR);
        index = index % (DOUBLY_INDIRECT_BLOCKS_PER_SECTOR);

        // first and second level block indices
        off_t second_level_index = index / INDIRECT_BLOCKS_PER_SECTOR;
        off_t final_block_index = index % INDIRECT_BLOCKS_PER_SECTOR;

        // fetch two indirect block sectors
        block_sector_t indirect_blocks[INDIRECT_BLOCKS_PER_SECTOR];

        cache_read (idisk->doubly_indirect_blocks[first_level_index], indirect_blocks);
        cache_read (indirect_blocks[second_level_index], indirect_blocks);
        sector = indirect_blocks[final_block_index];

        return sector;
      }

    // error
    return -1;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length) {
    // sector index
    off_t index = pos / BLOCK_SECTOR_SIZE;
    return index_to_sector (&inode->data, index);
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&file_extend_lock);
  cond_init(&file_extend_cond); 
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      if (inode_allocate (disk_inode, disk_inode->length))
        {
          cache_write (sector, disk_inode);
          success = true;
        }
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  cache_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
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
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          inode_deallocate (inode);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  // A read starting from a position past EOF returns no bytes.
  if (inode_length (inode) < offset + size)
      return 0;

  /* If write lock is held, wait until it is released */
  if (lock_held_by_current_thread (&file_extend_lock))
    {
      cond_wait (&file_extend_cond, &file_extend_lock);
    }

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode).
   growth implemented.
   */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  // beyond the EOF: extend the file to offset + size
  // allocate and write real zero data blocks for implicitly zeroed blocks
  if (inode_length(inode) < offset + size)
    {
      lock_acquire (&file_extend_lock);
      bool success = inode_allocate (&inode->data, offset + size);
      if (!success)
        {
          lock_release (&file_extend_lock);
          return 0;
        }

      // write back extended file size
      inode->data.length = offset + size;
      cache_write (inode->sector, &inode->data);
    }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);
  if (lock_held_by_current_thread (&file_extend_lock))
    {
      cond_signal (&file_extend_cond, &file_extend_lock);
      lock_release (&file_extend_lock);
    }
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool
inode_is_dir (struct inode *inode)
{
  if (inode == NULL)
      return false;
  return inode->data.is_dir;
}

/* Allocates indirect blocks for the inode.  */
static bool
inode_allocate_indirect (block_sector_t *entry_sector, size_t remaining_sectors, int level)
{
  static char zeros[BLOCK_SECTOR_SIZE];

  if (level == 0)
  {  // if not alocated, directly allocate a sector and clear
    if (*entry_sector == 0)
    {
      if (!free_map_allocate (1, entry_sector))
        return false;
      cache_write (*entry_sector, zeros);
    }
    return true;
  }

  // If the indirect block is not allocated, allocate and clear it
  if (*entry_sector == 0)
  {
    if (!free_map_allocate (1, entry_sector))
      return false;
    cache_write (*entry_sector, zeros);
  }

  block_sector_t indirect_blocks[INDIRECT_BLOCKS_PER_SECTOR];
  cache_read (*entry_sector, &indirect_blocks);

  // each entry in the indirect block points to a data block directly
  if (level == 1)
    {
      size_t num_entries = remaining_sectors;
      for (size_t i = 0; i < num_entries; ++i)
        {
          if (!inode_allocate_indirect (&indirect_blocks[i], 1, level - 1))
            return false;
          remaining_sectors -= 1;
        }
    }
  // each entry points to a block that contains more entries (i.e., another level of indirect blocks)
  else if (level == 2)
    {
      size_t num_entries = DIV_ROUND_UP (remaining_sectors, INDIRECT_BLOCKS_PER_SECTOR);
      for (size_t i = 0; i < num_entries; ++i)
        {
          size_t blocks_to_allocate = min (remaining_sectors, INDIRECT_BLOCKS_PER_SECTOR);
          if (!inode_allocate_indirect (&indirect_blocks[i], blocks_to_allocate, level - 1))
            return false;
          remaining_sectors -= blocks_to_allocate;
        }
    }

  ASSERT (remaining_sectors == 0);

  // Write back the updated indirect block
  cache_write (*entry_sector, &indirect_blocks);
  return true;
}

/* Allocates enough blocks for the inode to hold `length` bytes. */
static bool
inode_allocate (struct inode_disk *disk_inode, off_t length)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  if (length < 0)
    return false;

  // (remaining) number of sectors, occupied by this file.
  size_t remaining_sectors = bytes_to_sectors (length);

  // direct blocks
  size_t direct_blocks = min (remaining_sectors, DIRECT_BLOCKS_COUNT);
  for (size_t i = 0; i < direct_blocks; ++i)
    {
      if (disk_inode->direct_blocks[i] == 0)
        { // unoccupied
          if (!free_map_allocate (1, &disk_inode->direct_blocks[i]))
            return false;
          cache_write (disk_inode->direct_blocks[i], zeros);
        }
    }
  remaining_sectors -= direct_blocks;
  if (remaining_sectors == 0)
    return true;

  // indirect blocks
  size_t indirect_blocks = DIV_ROUND_UP (remaining_sectors, INDIRECT_BLOCKS_PER_SECTOR);
  indirect_blocks = min (indirect_blocks, INDIRECT_BLOCKS_COUNT);
  for (size_t i = 0; i < indirect_blocks; ++i)
    {
      size_t blocks_to_allocate = min (INDIRECT_BLOCKS_PER_SECTOR, remaining_sectors);
      if (!inode_allocate_indirect (&disk_inode->indirect_blocks[i], blocks_to_allocate, 1))
        return false;
      remaining_sectors -= blocks_to_allocate;
    }
  if (remaining_sectors == 0)
    return true;

  // doubly indirect blocks
  size_t doubly_indirect_blocks = DIV_ROUND_UP (remaining_sectors, DOUBLY_INDIRECT_BLOCKS_PER_SECTOR);
  doubly_indirect_blocks = min (doubly_indirect_blocks, DOUBLY_INDIRECT_BLOCKS_COUNT);
  for (size_t i = 0; i < doubly_indirect_blocks; ++i)
    {
      size_t blocks_to_allocate = min (DOUBLY_INDIRECT_BLOCKS_PER_SECTOR, remaining_sectors);
      if (!inode_allocate_indirect (&disk_inode->doubly_indirect_blocks[i], blocks_to_allocate, 2))
        return false;
      remaining_sectors -= blocks_to_allocate;
    }

  if (remaining_sectors == 0)
    return true;

  ASSERT (remaining_sectors == 0);
  return false;
}

/* 
 * Deallocates indirect blocks for the inode.
 * Recursively frees blocks for single or doubly indirect blocks based on the level.
 * Supports 2-level indirect block scheme (level 0 and level 1).
 */
static void
inode_deallocate_indirect (block_sector_t entry, size_t remaining_sectors, int level)
{
  if (level == 0)
    {
      free_map_release (entry, 1);
      return;
    }

  block_sector_t indirect_blocks[INDIRECT_BLOCKS_PER_SECTOR];
  cache_read (entry, &indirect_blocks);

  if (level == 1)
    {
      for (size_t i = 0; 1 < remaining_sectors; ++i)
        {
          inode_deallocate_indirect (indirect_blocks[i], 1, level - 1);
          remaining_sectors -= 1;
        }
    }
  else if (level == 2)
    {
      size_t num_entries = DIV_ROUND_UP (remaining_sectors, INDIRECT_BLOCKS_PER_SECTOR);
      for (size_t i = 0; i < num_entries; ++i)
        {
          size_t blocks_to_deallocate = min (remaining_sectors, INDIRECT_BLOCKS_PER_SECTOR);
          inode_deallocate_indirect (indirect_blocks[i], blocks_to_deallocate, level - 1);
          remaining_sectors -= blocks_to_deallocate;
        }
    }

  ASSERT (remaining_sectors == 0);
  free_map_release (entry, 1);
}

/*
 * Deallocates blocks for the inode, freeing sectors based on the file's length.
 * It deallocates direct, indirect, and doubly indirect blocks as needed.
 */
static bool
inode_deallocate (struct inode *inode)
{
  off_t file_length = inode->data.length; // bytes
  if (file_length < 0)
    return false;

  // (remaining) number of sectors, occupied by this file.
  size_t remaining_sectors = bytes_to_sectors (file_length);

  // direct blocks
  size_t direct_blocks = min (remaining_sectors, DIRECT_BLOCKS_COUNT);
  for (size_t i = 0; i < direct_blocks; ++i)
    {
      free_map_release (inode->data.direct_blocks[i], 1);
    }
  remaining_sectors -= direct_blocks;
  if (remaining_sectors == 0)
    return true;

  // indirect blocks
  size_t indirect_blocks = DIV_ROUND_UP (remaining_sectors, INDIRECT_BLOCKS_PER_SECTOR);
  indirect_blocks = min (indirect_blocks, INDIRECT_BLOCKS_COUNT);
  for (size_t i = 0; i < indirect_blocks; ++i)
    {
      size_t blocks_to_deallocate = min (INDIRECT_BLOCKS_PER_SECTOR, remaining_sectors);
      inode_deallocate_indirect (inode->data.indirect_blocks[i], blocks_to_deallocate, 1);
      remaining_sectors -= blocks_to_deallocate;
    }
  if (remaining_sectors == 0)
    return true;

  // doubly indirect blocks
  size_t doubly_indirect_blocks = DIV_ROUND_UP (remaining_sectors, DOUBLY_INDIRECT_BLOCKS_PER_SECTOR);
  doubly_indirect_blocks = min (doubly_indirect_blocks, DOUBLY_INDIRECT_BLOCKS_COUNT);
  for (size_t i = 0; i < doubly_indirect_blocks; ++i)
    {
      size_t blocks_to_deallocate = min (DOUBLY_INDIRECT_BLOCKS_PER_SECTOR, remaining_sectors);
      inode_allocate_indirect (inode->data.doubly_indirect_blocks[i], blocks_to_deallocate, 2);
      remaining_sectors -= blocks_to_deallocate;
    }

  ASSERT (remaining_sectors == 0);
  return true;
}
