#include"vm/page.h"
#include<stdbool.h>
#include <debug.h>
#include <hash.h>

/*calculate where to put the vm_entry into the hash table*/
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED);

/*compare address values of two entered hash_elem*/
static bool vm_less_function(const struct hash_elem* e);

/*remove memory of vm_entry*/
static void vm_destroy_func(struct hash_elem* e,void *aux UNUSED);


void vm_init(struct hash* vm){}
void vm_destroy(struct hash* vm);
struct vm_entry* find_vme(void* vaddr);
bool insert_vme(struct hash* vm,struct vm_entry* vme);
bool delete_vme(struct hash* vm,struct vm_entry* vme);