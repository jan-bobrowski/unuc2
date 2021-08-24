/* list.h by Jan Bobrowski. Inspired by list.h from Linux */

#ifndef LIST_H
#define LIST_H
#include <stddef.h>

typedef struct list {
	struct list *next, *prev;
} list_t;

#define list_item(L, T, M) ((T*)((char*)(1 ? (L) : (struct list *)0) - offsetof(T,M)))

static inline void list_link(struct list *prev, struct list *next)
{
	prev->next = next;
	next->prev = prev;
}

static inline void list_init(struct list *item)
{
	list_link(item, item);
}

static inline void list_add_after(struct list *prev, struct list *item)
{
	struct list *next = prev->next;
	list_link(prev, item);
	list_link(item, next);
}
#define list_prepend(H,L) list_add_after(H,L)
#define list_add(H,L) list_add_after(H,L)

static inline void list_add_before(struct list *next, struct list *item)
{
	struct list *prev = next->prev;
	list_link(item, next);
	list_link(prev, item);
}
#define list_append(H,L) list_add_before(H,L)
#define list_add_end(H,L) list_add_before(H,L)

static inline list_t *list_del(struct list *item)
{
	struct list *prev = item->prev, *next = item->next;
	list_link(prev, next);
	return next;
}

static inline void list_del_init(struct list *item)
{
	struct list *prev = item->prev, *next = item->next;
	list_link(item, item);
	list_link(prev, next);
}

static inline int list_is_empty(struct list *head)
{
	return head->next == head;
}

/* remove first element and return it */
static inline struct list *list_get(struct list *head)
{
	struct list *item = head->next;
	struct list *next = item->next;
	list_link(head, next);
	return item;
}

/* remove first element, initialize and return it */
static inline struct list *list_get_init(struct list *head)
{
	struct list *item = head->next;
	struct list *next = item->next;
	list_link(item, item);
	list_link(head, next);
	return item;
}

#endif
