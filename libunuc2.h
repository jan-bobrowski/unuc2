#ifndef LIBUNUC2_H
#define LIBUNUC2_H
#ifndef UC2_API
#define UC2_API
#endif

/* API
 uc2_identify - check UC2 magic
 uc2_open - initialize
 uc2_read_cdir - read dir entry
 uc2_get_tag_header - read tag header of the entry
 uc2_get_tag_data - read tag data
 uc2_finish_cdir - get archive label
 uc2_extract - decompress file
 uc2_message - get error message
 uc2_close - free resources

 uc2_open
 repeat {
  uc2_read_cdir
  if UC2_End
   optionally uc2_cdir_finish
  else while UC2_TaggedEntry
   uc2_get_tag_header
   uc2_get_tag_data if not skipped
 }
 uc2_close
*/

struct uc2_io;     // User callbacks
struct uc2_xinfo;  // Extraction info
struct uc2_entry;  // CDir entry
struct uc2_context;
typedef struct uc2_context *uc2_handle;

UC2_API int uc2_identify(void *magic, unsigned magic_size /* 4..21 */);
UC2_API uc2_handle uc2_open(struct uc2_io *io, void *io_ctx);
UC2_API uc2_handle uc2_close(uc2_handle);

/* Get cdir entry. Pass NULL to skip the rest. Returns:
     UC2_End: The end, entry not filled,
     UC2_BareEntry: New entry filled, no tags,
     UC2_TaggedEntry: New entry filled, has tags (must call uc2_get_tag_header),
     Negative value on error.
   Directories come before content. Duplicates: older first. */
UC2_API int uc2_read_cdir(
	uc2_handle,
	struct uc2_entry * // Entry to fill. Pass NULL to finish early.
);

/* Returns size of tag data to read, or negative on error */
UC2_API int uc2_get_tag_header(
	uc2_handle,
	struct uc2_entry *, // to fill name, if skipping tags
	char tag[16] // to fill, pass NULL to skip tags
);

/* If there are more tags returns UC2_TaggedEntry, else UC2_End, or an error */
UC2_API int uc2_get_tag_data(
	uc2_handle,
	struct uc2_entry *, // to fill name
	void *data // to fill, not NULL
);

UC2_API int uc2_cdir_finish(
	uc2_handle,
	char label[12]
);

/* Allowed only after whole cdir has been read.
   write() should return <0 on error. */
UC2_API int uc2_extract(
	uc2_handle,
	struct uc2_xinfo *,
	unsigned size,
	int (*write)(void *context, const void *ptr, unsigned len),
	void *context
);

UC2_API int uc2_finish_cdir(uc2_handle, char label[12]);
UC2_API const char *uc2_message(uc2_handle, int ret);

struct uc2_io {
	/* Read len bytes from the archive at offset pos into buf.
	   Return number of bytes read, or less if eof.
	   Negative value indicates an error. */
	int (*read)(void *io_ctx, unsigned pos, void *buf, unsigned len);

	/* Allocate memory. Return NULL on error */
	void *(*alloc)(void *io_ctx, unsigned size);
	void (*free)(void *io_ctx, void *ptr);

	/* Optional */
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

enum {
	UC2_End = 0,
	UC2_BareEntry = 1,
	UC2_TaggedEntry = 3
};

struct uc2_xinfo {
	unsigned offset, master;
	unsigned short csum, method;
};

struct uc2_entry {
	unsigned dirid; // Directory it belongs to. Root is 0.
	unsigned id; // dir only
	struct uc2_xinfo xi;
	unsigned size;  // file only
	unsigned csize; // file only
	unsigned dos_time;
	unsigned char is_dir:1;
	unsigned char has_tags:1;
	unsigned char attr;
	unsigned char dos_name[11]; // not terminated
	unsigned short name_len;
	char name[300]; // ready after tags have been read
};

enum {
	UC2_Attr_R = 1,
	UC2_Attr_H = 2,
	UC2_Attr_S = 4,
	UC2_Attr_D = 16,
	UC2_Attr_A = 32
};

#endif // LIBUNUC2_H
