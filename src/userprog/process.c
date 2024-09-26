#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/string.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"



static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void push_arguments (void **esp, int argc, char *argv[], int cmdlength);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /*Parse command line and get program(thread) name*/
  char *save_ptr;
  char *thread_name = malloc (strlen (file_name) + 1);
  strlcpy (thread_name, file_name, PGSIZE);

  thread_name = strtok_r (thread_name, " ", &save_ptr);
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);

  struct thread *t = get_thread_by_tid (tid);
  sema_down (&t->wait);
  if (t->exit_status == -1)
    {
      tid = TID_ERROR;
      process_wait (t->tid);
    }

  if (t->status == THREAD_BLOCKED)
    thread_unblock (t);

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  free (thread_name);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  char *argv[70];
  int argc = 0;
  int cmdlength = 0;

  /*parse argv(including the filename)*/
  char *token, *save_ptr;
  for (token = strtok_r (file_name, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      argv[argc] = token;
      cmdlength += strlen (token);
      argc++;
    }

  struct thread *t = thread_current ();

  /* Initialize the set of vm_entries.e.g. hash tabble */
  t->vm = (struct hash*)malloc(sizeof(struct hash));
  vm_init(t->vm);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (file_name, &if_.eip, &if_.esp);

  struct file *file = filesys_open (file_name);
  if (file == NULL)
    {
      success = false;
    }

  /* If load failed, quit. */
  if (!success)
    {
      t->exit_status = -1;
      process_exit(); // first exit, then go to wait
      sema_up (&t->wait);
      intr_disable ();
      thread_block ();
      intr_enable ();
      thread_exit ();
    }

  /* If load succeed, push arguments. */
  else
    {
      push_arguments (&if_.esp, argc, argv, cmdlength + argc);

      file_deny_write (file);
      t->exec_file = file;

      sema_up (&t->wait);
      intr_disable ();
      thread_block ();
      intr_enable ();
    }

  palloc_free_page (file_name);


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED)
{
  struct thread *t;
  int ret;

  ret = -1;
  t = get_thread_by_tid (child_tid);
  if (t->status == THREAD_DYING || t->exit_status == RET_STATUS_INVALID)
    goto done;
  if (t->exit_status != RET_STATUS_DEFAULT
      && t->exit_status != RET_STATUS_INVALID)
    {
      ret = t->exit_status;
      goto done;
    }

  sema_down (&t->wait);
  ret = t->exit_status;

  while (t->status == THREAD_BLOCKED)
    thread_unblock (t);

done:
  t->exit_status = RET_STATUS_INVALID;
  return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  printf ("%s: exit(%d)\n", cur->name, cur->exit_status);

  while (!list_empty (&cur->wait.waiters))
    sema_up (&cur->wait);
  // printf ("Process exit and sema_up(child thread)\n");
  
  /*add vm_entry delete function*/
  vm_destroy(cur->vm);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
    
    if (cur->exec_file)
    {
      file_close (cur->exec_file);
      cur->exec_file = NULL;
    }

  // if (cur->parent)
  //   {
      intr_disable ();
      thread_block ();
      intr_enable ();
    // }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);

  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2
      || ehdr.e_machine != 3 || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *)mem_page, read_bytes,
                                 zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /*Create vm_entry*/
      struct vm_entry* vme = (struct vm_entry*)malloc(sizeof(struct vm_entry));
      if(vme == NULL){
        free(vme);
        return false;
      }

      /*Setting vm_entry members, offset and size of file to read when virtual page is required, zero byte to pad at the end ...*/
      vme->type = VM_BIN;
      vme->vaddr = upage;
      // printf("load seg %u\n",(vme->vaddr));
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      vme->offset = ofs;
      vme->file = file;
      vme->writable = writable;
      vme->swap_index = -1;
      vme->is_loaded = false;

      /*Add vm_entry to hash table by insert_vme*/
      bool result = insert_vme(thread_current()->vm,vme);
      if(result == false){
        free(vme);
        return false;
      }

      // /* Get a page of memory. */
      // uint8_t *kpage = palloc_get_page (PAL_USER);
      // if (kpage == NULL)
      //   return false;

      // /* Load this page. */
      // if (file_read (file, kpage, page_read_bytes) != (int)page_read_bytes)
      //   {
      //     palloc_free_page (kpage);
      //     return false;
      //   }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable))
      //   {
      //     palloc_free_page (kpage);
      //     return false;
      //   }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      
      ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;
  
  struct vm_entry *vme = (struct vm_entry *) malloc(sizeof(struct vm_entry));
      
  if (vme == NULL)
  {
    free(vme);
    return false;
  }
  // Initialize the vm_entry members
  vme->type = VM_ANON;          // Indicates this is a stack page, not a file-backed page
  vme->vaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;
  // printf("set up stack%u ",vme->vaddr);

  vme->read_bytes = 0;          // No file to read from
  vme->zero_bytes = PGSIZE;     // All bytes are zeroed
  vme->offset = 0;              // No file offset
  vme->writable = true;         // The stack should be writable
  vme->swap_index = -1;
  vme->is_loaded = false;
  // Insert vm_entry into the process's vm hash table
  if (!insert_vme(thread_current()->vm, vme))
  {
    free(vme);
    return false;
  }
  
  kpage = frame_alloc(vme, PAL_USER | PAL_ZERO);

  // kpage = palloc_get_page (PAL_USER | PAL_ZERO);

  if (kpage != NULL)
    {
      success = install_page (((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        frame_free (kpage);
    }


  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/*push arguments, this function would be move to setup_stack function*/
void
push_arguments (void **esp, int argc, char *argv[], int cmdlength)
{
  *esp = PHYS_BASE;
  int i;
  int paddinglength = (((uint32_t)*esp - cmdlength) % 4);
  uint32_t *agrument_address
      = *esp - (paddinglength + cmdlength + 4); /*store agrument address*/

  /*push argument and address*/
  for (i = argc - 1; i >= 0; i--)
    {
      *esp -= (strlen (argv[i]) + 1);
      strlcpy (*esp, argv[i], strlen (argv[i]) + 1);
      agrument_address -= 1;
      *agrument_address = (uint32_t)*esp;
    }

  /*padding*/
  for (i = 0; i < paddinglength; i++)
    {
      *esp -= 1;
      *(uint8_t *)*esp = 0;
    }

  *esp -= (argc + 2) * 4;
  /*argv and argc*/
  *(uint32_t *)*esp = (uint32_t)*esp + 4;

  *esp -= 4;
  *(uint32_t *)*esp = argc;

  /*return address*/
  *esp -= 4;
  *(uint32_t *)*esp = 0;
}



bool 
handle_mm_fault(struct vm_entry* vme){
  if(vme == NULL)
    return false;
  bool success = false;
  /* Get a page of memory. */
  // uint8_t *kpage = palloc_get_page (PAL_USER);
  // printf("%u\n",vme->vaddr);
  uint8_t *kpage = frame_alloc(vme,PAL_USER);
  
  if (kpage == NULL){
    frame_free (kpage);
    return false;
    }
  
  /*check the vme type*/
  switch (vme->type)
  {
/* Load file from disk to memory. */

  case VM_BIN:
    success = load_file(kpage,vme);
    break;
  case VM_FILE:
    success = load_file(kpage,vme);
  case VM_ANON:
    if(vme->swap_index != -1){
      swap_in(vme->swap_index,kpage);
      vme->swap_index = -1;
      success = true;
    }
    break;
  
  default:
    success = false;
    break;
  }

  if(success) vme->is_loaded = true;


  if(success == false){
    frame_free (kpage);
    return false;
  }

  /* update associated page table entry after loading into physical memory. */
  if (!install_page (vme->vaddr, kpage, vme->writable))
    {
      frame_free (kpage);
      return false;
    }
  
  return success;
}


bool grow_stack (void* fault_addr)
{
  bool success = false;
  void *upage = pg_round_down(fault_addr);
  struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
  if (vme == NULL){
    free(vme);
    return false;
  }
  vme->type = VM_ANON;  // This is a stack page, not a file-backed page
  vme->vaddr = upage;
  // printf("grow stack %u",vme->vaddr);

  vme->read_bytes = PGSIZE;
  vme->zero_bytes = 0;
  vme->offset = 0;
  vme->file = NULL;
  vme->writable = true;
  vme->swap_index = -1;
  vme->is_loaded = true;
  
  // Insert vm_entry into the process's vm hash table
  if (!insert_vme(thread_current()->vm, vme))
  {
    free(vme);
    return false;
  }
  // printf("grow stack f");
  uint8_t *kpage = frame_alloc(vme,PAL_USER|PAL_ZERO);
  
  if (kpage == NULL){
    frame_free (kpage);
    return false;
  }

  // /* update associated page table entry after loading into physical memory. */
  // if (!install_page (vme->vaddr, kpage, vme->writable))
  //   {
  //     frame_free (kpage);
  //     return false;
  //   }
  
  // return true;
      /* Add the page to the process's address space. */
  if (!pagedir_set_page (thread_current()->pagedir, upage, kpage, true))
	{
	  frame_free (kpage);
    return false;
	}
  return true;
}

void remove_mmap(struct mmap_file* mmap_file){
  struct thread* curr = thread_current();
  while (!list_empty(&mmap_file->vm_entries)) {
    struct list_elem *velem = list_pop_front(&mmap_file->vm_entries);
    struct vm_entry *vme = list_entry(velem, struct vm_entry, mmap_elem);

    if (vme->is_loaded && pagedir_is_dirty(curr->pagedir, vme->vaddr)) {
        file_write_at(mmap_file->file, vme->vaddr, vme->read_bytes, vme->offset);
    }
    vme->is_loaded = false;
    // printf("remove mmf\n");
    frame_free(pagedir_get_page(curr->pagedir, vme->vaddr));
    pagedir_clear_page(curr->pagedir, vme->vaddr);

    delete_vme(curr->vm, vme);
    // free(vme);
  }
}