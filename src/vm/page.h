#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <stdbool.h>
#include <inttypes.h>
#include"filesys/off_t.h"
#include <hash.h>

struct vm_entry{
    bool VM_BIN;
    void* vaddr;
    uint32_t zero_bytes;
    uint32_t read_bytes;
    off_t offset;
    struct file* file;

};

void vm_init(struct hash* vm);
void vm_destroy(struct hash* vm);
struct vm_entry* find_vme(void* vaddr);
bool insert_vme(struct hash* vm,struct vm_entry* vme);
bool delete_vme(struct hash* vm,struct vm_entry* vme);
#endif /* vm/page.h */