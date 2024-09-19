#include"vm/page.h"
#include<stdbool.h>
#include <debug.h>
#include"lib/kernel/hash.h"
#include <hash.h>
#include"threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

/*calculate where to put the vm_entry into the hash table*/
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED);

/*compare address values of two entered hash_elem*/
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
/*remove memory of vm_entry*/
static void vm_destroy_func(struct hash_elem* e,void *aux UNUSED);

/*initialize vm in struct thread */
void vm_init(struct hash* vm){
/*hash table initialization*/
    hash_init(vm,vm_hash_func,vm_less_func,NULL);
}

/*destroy vm and delocate its memory*/
void vm_destroy(struct hash* vm){
/*hash table delete*/
    hash_destroy(vm,vm_destroy_func);
    free(vm);// vm is allocate by malloc
}


/*Search vm_entry corresponding to vaddr in the address space of the current process*/
struct vm_entry* find_vme(void* vaddr) {
    struct hash* vm = thread_current()->vm;
    struct vm_entry vme;
    struct hash_elem *e;
    vme.vaddr = vaddr;
    e = hash_find(vm, &vme.elem);
    return e != NULL ? hash_entry(e, struct vm_entry, elem) : NULL;
}

/* Insert a vm_entry into the hash table */
bool insert_vme(struct hash *vm, struct vm_entry *vme) {
    struct hash_elem *result = hash_insert(vm, &vme->elem);
    // return true;
    return result == NULL;
}

/* Delete a vm_entry from the hash table */
bool delete_vme(struct hash *vm, struct vm_entry *vme) {
    struct hash_elem *result = hash_delete(vm, &vme->elem);
    if (result != NULL) {
        free(hash_entry(result, struct vm_entry, elem));
    }
    return result != NULL;
}


/* Calculate the hash value for a vm_entry */
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
    return hash_bytes(&vme->vaddr, sizeof(vme->vaddr));
}

/* Compare two vm_entry addresses */
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct vm_entry *vme_a = hash_entry(a, struct vm_entry, elem);
    struct vm_entry *vme_b = hash_entry(b, struct vm_entry, elem);
    return vme_a->vaddr < vme_b->vaddr;
}

/* Clean up memory of vm_entry */
static void vm_destroy_func(struct hash_elem* e, void *aux UNUSED) {
    struct vm_entry* vme = hash_entry(e, struct vm_entry, elem);
    free(vme);
}



bool 
load_file(void* kaddr,struct vm_entry *vme){
    /*file_read_at*/
    if( file_read_at(vme->file,kaddr,vme->read_bytes,vme->offset)!= (int)vme->read_bytes)
    {
        // printf("111\n");
        palloc_free_page (kaddr);
        return false;
    }
    memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
    return true;
}