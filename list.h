/* list.h by Jan Bobrowski. Inspired by list.h from Linux */

#ifndef LIST_H
#define LIST_H
#include <stddef.h>

typedef struct list {
	struct list *next, *prev;
} list_t;

static inline void list_init(struct list *a)
{
	a->next = a->prev = a;
}

static inline int list_is_empty(struct list *head)
{
	return head->next == head;
}

static inline void list_del(struct list *item)
{
	struct list *next = item->next;
	struct list *prev = item->prev;
	next->prev = prev;
	prev->next = next;
#ifndef NDEBUG
	item->next = item->prev = (void*)0xaa;
#endif
}

static inline void list_insert_after(struct list *prev, struct list *item)
{
	struct list *next = prev->next;
	prev->next = item;
	item->prev = prev;
	item->next = next;
	next->prev = item;
}

static inline void list_insert_before(struct list *next, struct list *item)
{
	struct list *prev = next->prev;
	next->prev = item;
	item->next = next;
	item->prev = prev;
	prev->next = item;
}

#define list_append(H, I) list_insert_before((H), (I))

#define list_item(L, T, M) ((T*)((char*)(1 ? (L) : (struct list *)0) - offsetof(T,M)))

#endif
