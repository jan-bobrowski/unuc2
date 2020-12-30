#ifndef LIBUNUC2_H
#define LIBUNUC2_H

/* API
 uc2_identify - check UC2 magic
 uc2_open - initialize
 uc2_scan - read dir entry
 uc2_extract - decompress file
 uc2_message - get error message
 uc2_label - get archive label
 uc2_close - free resources
*/

struct uc2_io;  // User callbacks.
struct uc2_entry;
struct uc2_context;
typedef struct uc2_context *uc2_handle;

int uc2_identify(void *magic, unsigned magic_size /* 4..21 */);
uc2_handle uc2_open(struct uc2_io *io, void *io_ctx);
uc2_handle uc2_close(uc2_handle);

typedef int (*uc2_tag_callback)(char tag[16], const void *data, unsigned size, struct uc2_entry *);

/* Get cdir entry. Returns 0 when no more. Negative value indicates an error.
   Directories come before content. Duplicates: older first. */
int uc2_scan(
	uc2_handle,
	struct uc2_entry *e, // Entry to fill. Pass NULL to finish early.
	uc2_tag_callback // May be null.
);

int uc2_extract(
	uc2_handle,
	struct uc2_entry *e,
	int (*write)(void *context, unsigned pos, const void *ptr, unsigned len),
	void *context
);

const char *uc2_message(uc2_handle, int ret);
const char *uc2_label(uc2_handle);

struct uc2_io {
	/* Read len bytes from the archive at offset pos into buf.
	   Return number of bytes read, or less if eof. Negative value indicates an error. */
	int (*read)(void *io_ctx, unsigned pos, void *buf, unsigned len);

	/* Allocate memory. Return NULL on error */
	void *(*alloc)(void *io_ctx, unsigned size);
	void (*free)(void *io_ctx, void *ptr);

	void (*warn)(void *io_ctx, char *fmt, ...);
};

enum {
	UC2_UserFault = -2, // User callback refused to cooperate.
	UC2_BadState = -3, // uc2_scan() should return 0 first.
	UC2_Damaged = -4,
	UC2_Truncated = -5,
	UC2_Unimplemented = -6,
	UC2_InternalError = -7
};

struct uc2_entry {
	unsigned dirid; // Directory it belongs to. Root is 0.
	unsigned id; // dir only
	unsigned char attr;
	unsigned size;  // file only
	unsigned csize; // file only
	unsigned dos_time;
	unsigned char is_dir:1;
	unsigned char has_tags:1;
	unsigned char dos_name[11]; // not terminated
	unsigned short name_len;
	char name[300];

	unsigned offset, master; // for decompression
	unsigned short csum, method;
};

enum {
	UC2_Attr_R = 1,
	UC2_Attr_H = 2,
	UC2_Attr_S = 4,
	UC2_Attr_D = 16,
	UC2_Attr_A = 32
};

#endif // LIBUNUC2_H
