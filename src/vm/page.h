#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <stdbool.h>
#include <inttypes.h>
#include"filesys/off_t.h"
#include <hash.h>

/* States in a thread's life cycle. */
enum page_type
  {
    VM_BIN,
    VM_FILE,
    VM_ANON
  };


struct vm_entry{
    enum page_type type;
    void* vaddr;
    uint32_t zero_bytes;
    uint32_t read_bytes;
    off_t offset;
    struct file* file;
    bool writable;


    struct hash_elem elem;

};

void vm_init(struct hash* vm);
void vm_destroy(struct hash* vm);
struct vm_entry* find_vme(void* vaddr);
bool insert_vme(struct hash* vm,struct vm_entry* vme);
bool delete_vme(struct hash* vm,struct vm_entry* vme);
bool load_file(void* kaddr,struct vm_entry *vme);

#endif /* vm/page.h */