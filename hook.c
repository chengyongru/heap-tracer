#define _GNU_SOURCE

#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define RESET "\x1b[0m"

#include <bsd/sys/tree.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <inttypes.h>
#include <malloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/cdefs.h>
#include <unistd.h>

/* 配置参数 */
#define MAX_STACK_FRAMES 16 // 最大堆栈深度
#define SKIP_FRAMES 3       // 跳过的堆栈层数

typedef struct allocation {
  size_t alloc_size;
  size_t real_size;
  void *addr;                    // 分配地址
  unsigned long id;              // 唯一ID
  void *stack[MAX_STACK_FRAMES]; // 调用堆栈
  int stack_depth;               // 有效堆栈深度
  RB_ENTRY(allocation) entry;    // 红黑树节点
} allocation;

/* 红黑树定义 */
RB_HEAD(alloc_tree, allocation);
static struct alloc_tree allocations = RB_INITIALIZER(&allocations);
static pthread_mutex_t tree_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 红黑树比较函数 */
int alloc_cmp(struct allocation *a, struct allocation *b) {
  return (a->addr < b->addr) ? -1 : (a->addr > b->addr);
}

/* 生成红黑树操作函数 */
RB_GENERATE(alloc_tree, allocation, entry, alloc_cmp);

static atomic_ulong malloc_counter = 0;

void *(*real_malloc)(size_t size);
void (*real_free)(void *ptr);
void *(*real_realloc)(void *ptr, size_t size);

void push(allocation *entity) {
  pthread_mutex_lock(&tree_mutex);
  size_t real_size = malloc_usable_size(entity->addr);
  entity->real_size = real_size;
  RB_INSERT(alloc_tree, &allocations, entity);
  printf(GREEN "[malloc] id=%lu, rea_size=%lu, alloc_size=%lu, [%p-%p]",
         entity->id, real_size, entity->alloc_size, entity->addr,
         (char *)entity->addr + real_size);
  for (int i = 0; i < entity->stack_depth;
       i++) { // TODO store and print stack info
    printf("[%p]", entity->stack[i]);
  }
  printf("\n" RESET);
  pthread_mutex_unlock(&tree_mutex);
}

void pop(allocation *entity) {
  pthread_mutex_lock(&tree_mutex);

  if (!entity)
    return;
  struct allocation *found = RB_FIND(alloc_tree, &allocations, entity);

  if (!found)
    return;

  RB_REMOVE(alloc_tree, &allocations, found);
  printf(YELLOW "[ free ] id=%lu\n" RESET, found->id);
  real_free(found);

  pthread_mutex_unlock(&tree_mutex);
}

void *malloc(size_t size) {
  static __thread int reentrant_guard = 0;
  if (reentrant_guard)
    return NULL;
  reentrant_guard = 1;

  if (!real_malloc)
    real_malloc =
        dlsym(RTLD_NEXT, "malloc"); // FIXME dlsym sometimes will call malloc

  void *chunk = real_malloc(size);

  if (chunk) {
    unsigned long id =
        atomic_fetch_add_explicit(&malloc_counter, 1, memory_order_relaxed);
    size_t s = malloc_usable_size(chunk);
    struct allocation *alloc = real_malloc(sizeof(struct allocation));
    alloc->alloc_size = size;
    alloc->id = id;
    alloc->addr = chunk;
    alloc->stack_depth = 0;
    /* 插入红黑树 */
    push(alloc);
  }
  reentrant_guard = 0;
  return chunk;
}

void free(void *ptr) {
  static __thread int reentrant_guard = 0;
  if (reentrant_guard)
    return;
  reentrant_guard = 1;

  if (!real_free)
    real_free = dlsym(RTLD_NEXT, "free");

  if (ptr) {
    struct allocation key = {.addr = ptr};
    pop(&key);
    real_free(ptr);
  }

  reentrant_guard = 0;
}

void *realloc(void *ptr, size_t size) {

  if (!real_realloc)
    real_realloc = dlsym(RTLD_NEXT, "realloc");

  if (ptr) {
    void *old_chunk = ptr;
    struct allocation key = {.addr = old_chunk};
    pop(&key);
  }
  void *chunk = real_realloc(ptr, size);
  if (chunk) {
    struct allocation *alloc = real_malloc(sizeof(struct allocation));
    unsigned long id =
        atomic_fetch_add_explicit(&malloc_counter, 1, memory_order_relaxed);
    alloc->alloc_size = size;
    alloc->id = id;
    alloc->addr = chunk;
    push(alloc);
  }
  return chunk;
}
