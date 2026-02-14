/*
 * Klee - Userspace bwrap translation layer
 * Intrusive doubly-linked list macros (Linux kernel style)
 */
#ifndef KLEE_LIST_H
#define KLEE_LIST_H

#include <stddef.h>

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

typedef struct klee_list_head {
    struct klee_list_head *next, *prev;
} KleeListHead;

#define KLEE_LIST_HEAD_INIT(name) { &(name), &(name) }

#define KLEE_LIST_HEAD(name) \
    KleeListHead name = KLEE_LIST_HEAD_INIT(name)

static inline void klee_list_init(KleeListHead *head)
{
    head->next = head;
    head->prev = head;
}

static inline void klee_list_add(KleeListHead *new_node, KleeListHead *head)
{
    new_node->next = head->next;
    new_node->prev = head;
    head->next->prev = new_node;
    head->next = new_node;
}

static inline void klee_list_add_tail(KleeListHead *new_node, KleeListHead *head)
{
    new_node->next = head;
    new_node->prev = head->prev;
    head->prev->next = new_node;
    head->prev = new_node;
}

static inline void klee_list_del(KleeListHead *entry)
{
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    entry->next = NULL;
    entry->prev = NULL;
}

static inline int klee_list_empty(const KleeListHead *head)
{
    return head->next == head;
}

#define klee_list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define klee_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define klee_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)

#define klee_list_for_each_entry(pos, head, member) \
    for (pos = klee_list_entry((head)->next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = klee_list_entry(pos->member.next, __typeof__(*pos), member))

#define klee_list_for_each_entry_safe(pos, n, head, member) \
    for (pos = klee_list_entry((head)->next, __typeof__(*pos), member), \
         n = klee_list_entry(pos->member.next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = n, n = klee_list_entry(n->member.next, __typeof__(*pos), member))

#endif /* KLEE_LIST_H */
