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

#define DIRECT_BLOCKS 123 // 128-type-length-magic-indirect-doubly=123
#define INDIRECT_BLOCKS 1
#define DOUBLE_INDIRECT_BLOCKS 1



/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  { 
    // block_sector_t start;               /* First data sector. */
    block_sector_t direct_blocks[DIRECT_BLOCKS];
    block_sector_t indirect_block;
    block_sector_t doubly_indirect_block;

    enum inode_type type; /* File type: regular or directory. */
    off_t length;         /* File size in bytes. */
    unsigned magic;       /* Magic number. */
    // uint32_t unused[125]; /* Not used. */
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
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

// static bool inode_allocate (size_t sectors, struct inode_disk *disk_inode);
static size_t direct_allocate (size_t sectors, block_sector_t *indirect_block);
static size_t indirect_allocate (size_t sectors, block_sector_t *indirect_block);
static size_t double_indirect_allocate (size_t sectors,
                                     block_sector_t *double_indirect_block);
static block_sector_t index_to_sector (const struct inode_disk *idisk,
                                       off_t sector_idx);

/* allocate sectors amount memory, use block indexing
  sectors: number of sectors need to be allocated*/
// static bool inode_allocate (size_t sectors, struct inode_disk *disk_inode);
static bool inode_allocate(size_t sectors, struct inode_disk *disk_inode)
{
    // size_t allocated_sectors = 0;

    // Step 1: Allocate direct blocks.
    size_t direct_sectors = sectors < DIRECT_BLOCKS ? sectors : DIRECT_BLOCKS;
    if (direct_allocate(direct_sectors, disk_inode->direct_blocks) != direct_sectors)
        return false;
    // allocated_sectors += direct_sectors;
    sectors -= direct_sectors;

    // Step 2: Allocate indirect block.
    if (sectors > 0)
    {
        if (!free_map_allocate(1, &disk_inode->indirect_block))
            return false;
        size_t indirect_sectors = sectors < INDIRECT_BLOCKS ? sectors : INDIRECT_BLOCKS;
        if (indirect_allocate(indirect_sectors, (block_sector_t)disk_inode->indirect_block) != indirect_sectors)
            return false;
        // allocated_sectors += indirect_sectors;
        sectors -= indirect_sectors;
    }

    // Step 3: Allocate double indirect block.
    if (sectors > 0)
    {
        if (!free_map_allocate(1, &disk_inode->doubly_indirect_block))
            return false;
        size_t double_indirect_sectors = sectors < DOUBLE_INDIRECT_BLOCKS ? sectors : DOUBLE_INDIRECT_BLOCKS;
        if (double_indirect_allocate(double_indirect_sectors, disk_inode->doubly_indirect_block) != double_indirect_sectors)
            return false;
        sectors -= double_indirect_sectors;
    }

    if (sectors > 0)
    {
      PANIC ("Memory full!");
    }

    return true;
}

static size_t
direct_allocate (size_t sectors, block_sector_t *direct_blocks)
{
  size_t i;
  for (i = 0; i < sectors; i++)
    {
      if (!free_map_allocate (1, &direct_blocks[i]))
        {
          // If allocation fails, release previously allocated blocks.
          for (size_t j = 0; j < i; j++)
            free_map_release (direct_blocks[j], 1);
          return i;
        }
    }
  return sectors; // Successfully allocated all sectors.
}

static size_t
indirect_allocate (size_t sectors, block_sector_t *indirect_block)
{
  block_sector_t *indirect_blocks = calloc(BLOCK_SECTOR_SIZE / sizeof(block_sector_t), sizeof(block_sector_t));
  if (indirect_blocks == NULL)
    {
      return 0;
    }
  size_t allocated_sectors = direct_allocate (sectors, indirect_blocks);
  if (allocated_sectors > 0)
    {
      // Write the indirect block to disk.
      block_write (fs_device, &indirect_block, indirect_blocks);
    }
  free (indirect_blocks);
  return allocated_sectors;
}

static size_t
double_indirect_allocate (size_t sectors, block_sector_t *double_indirect_block)
{
  // Allocate memory for storing the double indirect block pointers
  block_sector_t *indirect_blocks = calloc(BLOCK_SECTOR_SIZE / sizeof(block_sector_t), sizeof(block_sector_t));
  if (indirect_blocks == NULL)
    return 0;

  // If the double indirect block has not been allocated, allocate it.
  if (!free_map_allocate(1, &double_indirect_block))
  {
    free(indirect_blocks);
    return 0;
  }

  size_t total_allocated = 0;  // Total number of sectors allocated.

  // For each indirect block in the double indirect block
  for (size_t i = 0; i < BLOCK_SECTOR_SIZE / sizeof(block_sector_t); i++)
  {
    if (sectors == 0)  // If all required sectors have been allocated, stop.
      break;

    // Allocate an indirect block if needed.
    if (!free_map_allocate(1, &indirect_blocks[i]))
    {
      // Free previously allocated indirect blocks and sectors in case of failure
      for (size_t j = 0; j < i; j++)
      {
        free_map_release(indirect_blocks[j], 1);
      }
      free(indirect_blocks);
      return total_allocated;  // Return how much has been allocated so far.
    }

    // Allocate the direct blocks through the indirect block
    size_t indirect_allocated = indirect_allocate(sectors, indirect_blocks[i]);

    // Update the number of sectors left to allocate and the total allocated so far.
    total_allocated += indirect_allocated;
    sectors -= indirect_allocated;
  }

  // Write the double indirect block to disk
  block_write(fs_device, double_indirect_block, indirect_blocks);
  free(indirect_blocks);
  
  return total_allocated;  // Return the total number of sectors allocated.
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    {
      off_t index = pos / BLOCK_SECTOR_SIZE;
      return index_to_sector (&inode->data, index);
    }
  else
    return -1;
}

static block_sector_t
index_to_sector (const struct inode_disk *idisk, off_t sector_idx)
{
  // Step 1: Check if the sector is in the direct blocks.
  if (sector_idx < DIRECT_BLOCKS)
    return idisk->direct_blocks[sector_idx];

  // Step 2: Check if the sector is in the indirect block.
  sector_idx -= DIRECT_BLOCKS;
  if (sector_idx < BLOCK_SECTOR_SIZE / sizeof(block_sector_t))
    {
      block_sector_t *indirect_blocks = malloc(BLOCK_SECTOR_SIZE);
      if (indirect_blocks == NULL)
        return -1;
      block_read(fs_device, idisk->indirect_block, indirect_blocks);
      block_sector_t result = indirect_blocks[sector_idx];
      free(indirect_blocks);
      return result;
    }

  // Step 3: Check if the sector is in the doubly indirect block.
  sector_idx -= BLOCK_SECTOR_SIZE / sizeof(block_sector_t);
  if (sector_idx < (BLOCK_SECTOR_SIZE / sizeof(block_sector_t)) * (BLOCK_SECTOR_SIZE / sizeof(block_sector_t)))
    {
      block_sector_t *double_indirect_blocks = malloc(BLOCK_SECTOR_SIZE);
      if (double_indirect_blocks == NULL)
        return -1;
      block_read(fs_device, idisk->doubly_indirect_block, double_indirect_blocks);

      size_t indirect_idx = sector_idx / (BLOCK_SECTOR_SIZE / sizeof(block_sector_t));
      size_t block_idx = sector_idx % (BLOCK_SECTOR_SIZE / sizeof(block_sector_t));

      block_sector_t *indirect_blocks = malloc(BLOCK_SECTOR_SIZE);
      if (indirect_blocks == NULL)
        {
          free(double_indirect_blocks);
          return -1;
        }
      block_read(fs_device, double_indirect_blocks[indirect_idx], indirect_blocks);
      block_sector_t result = indirect_blocks[block_idx];

      free(double_indirect_blocks);
      free(indirect_blocks);
      return result;
    }

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
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, enum inode_type type)
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
      size_t sectors = bytes_to_sectors (length);
      memset (disk_inode->direct_blocks, 0,
              sizeof (disk_inode->direct_blocks));
      disk_inode->indirect_block = 0;
      disk_inode->doubly_indirect_block = 0;
      disk_inode->type = type;
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      // if (free_map_allocate (sectors, &disk_inode->start)) 
      //   {
      //     block_write (fs_device, sector, disk_inode);
      //     if (sectors > 0) 
      //       {
      //         static char zeros[BLOCK_SECTOR_SIZE];
      //         size_t i;
              
      //         for (i = 0; i < sectors; i++) 
      //           block_write (fs_device, disk_inode->start + i, zeros);
      //       }
      //     success = true; 
      //   }
      if (inode_allocate (sectors, disk_inode))
        {
          block_write (fs_device, sector, disk_inode);
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
  block_read (fs_device, inode->sector, &inode->data);
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
          // free_map_release (inode->data.start,
          //                   bytes_to_sectors (inode->data.length)); 
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

      // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
      //   {
      //     /* Read full sector directly into caller's buffer. */
      //     block_read (fs_device, sector_idx, buffer + bytes_read);
      //   }
      // else 
      //   {
      //     /* Read sector into bounce buffer, then partially copy
      //        into caller's buffer. */
      //     if (bounce == NULL) 
      //       {
      //         bounce = malloc (BLOCK_SECTOR_SIZE);
      //         if (bounce == NULL)
      //           break;
      //       }
      //     block_read (fs_device, sector_idx, bounce);
      //     memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
      //   }
         cache_read (sector_idx, buffer + bytes_read, chunk_size, sector_ofs);

      
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
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

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

      // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
      //   {
      //     /* Write full sector directly to disk. */
      //     block_write (fs_device, sector_idx, buffer + bytes_written);
      //   }
      // else 
      //   {
      //     /* We need a bounce buffer. */
      //     if (bounce == NULL) 
      //       {
      //         bounce = malloc (BLOCK_SECTOR_SIZE);
      //         if (bounce == NULL)
      //           break;
      //       }

      //     /* If the sector contains data before or after the chunk
      //        we're writing, then we need to read in the sector
      //        first.  Otherwise we start with a sector of all zeros. */
      //     if (sector_ofs > 0 || chunk_size < sector_left)
      //       block_read (fs_device, sector_idx, bounce);
      //     else
      //       memset (bounce, 0, BLOCK_SECTOR_SIZE);
      //     memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
      //     block_write (fs_device, sector_idx, bounce);
      //   }
      cache_write (sector_idx, buffer + bytes_written, chunk_size, sector_ofs);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

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
