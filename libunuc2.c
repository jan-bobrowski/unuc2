/* UltraCompressor II decompression library.
   Copyright © Jan Bobrowski 2020
   torinak.com/~jb/unuc2/

   This program is free software; you can redistribute it and
   modify it under the terms of the GNU Lesser General Public
   License version 3 as published by the Free Software Foundation.

   Original source by Nico de Vries, AIP used as a reference.
*/

#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "libunuc2.h"

#ifndef NDEBUG
#include <stdio.h>
static int midl;
static void diag(char *fnm, int lin, char *fmt, ...)
{
	if (!midl)
		fprintf(stdout, "%s:%d: ", fnm, lin);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	midl = fmt[strlen(fmt)-1] != '\n';
}
#define diag(...) diag(__FILE__,__LINE__,__VA_ARGS__)
#else
static inline void diag(char *f, ...) {}
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

static u32 get32(const u8 p[4]) {return p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24;}
static u32 get16(const u8 p[2]) {return p[0] | p[1]<<8;}

/* records */

#define REC(R) struct R

REC(FHEAD) {
 u8 head[4];		// UC2^Z
 u8 componentLength[4];	// length of component contents
 u8 componentLength2[4];
 u8 damageProtected;
};

REC(LOCATION) {
 u8 volume[4];
 u8 offset[4];
};

REC(XHEAD) {
 REC(LOCATION) cdir;
 u8 fletch[2];
 u8 busy;
 u8 versionMadeBy[2];	// e.g. 200 means 2.00
 u8 versionNeededToExtract[2];
 u8 dummy;
};

REC(COMPRESS) {
 u8 compressedLength[4];
 u8 method[2];
 u8 masterPrefix[4];
};

REC(OHEAD) {
 u8 type;
};

enum {
	DirEntry = 1,
	FileEntry = 2,
	MasterEntry = 3,
	EndOfCdir = 4
};

REC(OSMETA) {
 u8 parent[4];	// parent directory index
 u8 attrib;	// file attributes (MSDOS)
 u8 time[4];	// time last modified (MSDOS)
 u8 name[11];	// MS-DOS compatible name
 u8 hidden;	// 0 = plain visual, 1 = completely hidden
 u8 tag;	// has tags?
};

REC(FILEMETA) {
 u8 length[4];	// file length
 u8 fletch[2];	// fletcher checksum of raw data
};

REC(DIRMETA) {
 u8 index[4];	// directory index for referencing
};

REC(EXTMETA) {
 u8 tag[16];	// zero terminated
 u8 size[4];	// size of object
 u8 next;	// more tags?
};

#define TAG_LONGNAME "AIP:Win95 LongN"

REC(MASMETA) {
 u8 index[4];	// master index
 u8 key[4];	// master hash key
 u8 refLen[4];	// total size of refering data
 u8 refCtr[4];	// total number of refering files
 u8 length[2];	// master length
 u8 fletch[2];	// (Garbage 0xDEDE) fletcher checksum of raw data
};

REC(XTAIL) {
 u8 beta;	// archive made with beta test version
 u8 lock;	// locked archive
 u8 serial[4];	// special serial number (0 = none)
 u8 label[11];	// (MS-DOS) volume label
};

#include "list.h"
#define elemof(T) (sizeof T/sizeof*T)
#define endof(T) (T+elemof(T))

int uc2_identify(void *magic, unsigned magic_size)
{
	struct {
		REC(FHEAD) fhead;
		REC(XHEAD) xhead;
	} *h = magic;

#define NEED(M) ((u8*)&h->M - (u8*)h + sizeof h->M)

	if (magic_size < NEED(fhead.head))
		return -1;

	const u32 MAGIC = 0x1a324355;
	if (get32(h->fhead.head) != MAGIC)
		return 0;

	if (magic_size < NEED(fhead.componentLength2))
		return 1;

	const u32 AMAG = 0x01b2c3d4;
	u32 len = get32(h->fhead.componentLength);
	if (len != (u32)(get32(h->fhead.componentLength2) - AMAG))
		return 0;
	len += sizeof h->fhead;

	if (magic_size < NEED(xhead.cdir))
		return 1;

	if (get32(h->xhead.cdir.volume) != 1)
		return 0;

	if (get32(h->xhead.cdir.offset) >= len)
		return 0;
#undef NEED
	return 1;
}

struct uc2_context {
	char *message;
	struct uc2_io *io;
	void *io_ctx;

	unsigned cdir_offset;
	u16 cdir_csum;

	u8 *supermaster;
	struct list masters;

	struct fifo {
		struct list list;
		unsigned free; // free in first
		unsigned used; // used in last
	} cdir_buf;

	char label[12];

	u8 scanning:1;
	u8 scanned:1;
};

/* callback */

static int u_read(struct uc2_context *uc2, unsigned pos, void *buf, unsigned len)
{
	return uc2->io->read(uc2->io_ctx, pos, buf, len);
}

static int u_read_all(struct uc2_context *uc2, unsigned pos, void *buf, unsigned len)
{
	int r = u_read(uc2, pos, buf, len);
	if (r >= 0 && r != len)
		r = UC2_Truncated;
	return r;
}

static void *u_alloc(struct uc2_context *uc2, unsigned size)
{
	return uc2->io->alloc(uc2->io_ctx, size);
}

static void *u_free(struct uc2_context *uc2, void *ptr)
{
	uc2->io->free(uc2->io_ctx, ptr);
	return 0;
}

#define u_warn(U, ...) ((U)->io->warn ? ((U)->io->warn((U)->io_ctx, __VA_ARGS__),1) : 0)

/* rw */

struct reader {
	void *context;
	int (*read)(void *context, void *buffer, unsigned size);
};

struct writer {
	void *context;
	int (*write)(void *context, const void *buffer, unsigned size); // ret: -1 or 0
};

struct archive_ctx {
	unsigned offset;
	struct uc2_context *uc2;
};

static int archive_read(void *context, void *buffer, unsigned size)
{
	struct archive_ctx *ctx = context;
	int r = u_read(ctx->uc2, ctx->offset, buffer, size);
	if (r > 0)
		ctx->offset += r;
	return r;
}

struct range {
	u8 *ptr, *end;
};

static int buf_read(void *context, void *ptr, unsigned size)
{
	struct range *br = context;
	unsigned have = br->end - br->ptr;
	if (have < size) {
		if (!have)
			return -1;
		size = have;
	}
	memcpy(ptr, br->ptr, size);
	br->ptr += size;
	return size;
}

static int buf_write(void *context, const void *ptr, unsigned size)
{
	struct range *bw = context;
	unsigned free = bw->end - bw->ptr;
	if (free < size)
		return UC2_Damaged;
	memcpy(bw->ptr, ptr, size);
	bw->ptr += size;
	return size;
}

static int read_all(struct reader *rd, void *ptr, unsigned len)
{
	int r = rd->read(rd->context, ptr, len);
	if (r >= 0 && r != len)
		r = UC2_Truncated;
	return r;
}

struct user_write_ctx {
	unsigned pos;
	int (*write)(void *context, unsigned pos, const void *ptr, unsigned len);
	void *context;
};

static int user_write(void *context, const void *buffer, unsigned size)
{
	struct user_write_ctx *uc = context;
	int r = uc->write(uc->context, uc->pos, buffer, size);
	uc->pos += size;
	return r;
}

/* bits */

struct bits {
	u32 bits;
	unsigned have_bits;
	unsigned head, tail;
	struct reader *rd;
	u8 buffer[4 << 10];
};

static int bits_init(struct bits *bi, struct reader *rd)
{
	bi->head = 0;
	bi->tail = 0;
	bi->bits = 0;
	bi->have_bits = 0;
	bi->rd = rd;
	return 0;
}

static void bits_skip(struct bits *bi, unsigned n)
{
	assert(bi->have_bits >= n);
	bi->have_bits -= n;
}

static int bits_feed(struct bits *bi, unsigned n)
{
	assert(n <= 16);
	if (bi->have_bits < n) {
		if (bi->head + 1 >= bi->tail) {
			if (bi->tail > bi->head)
				bi->buffer[0] = bi->buffer[bi->tail - 1];
			bi->tail -= bi->head;
			int r = bi->rd->read(bi->rd->context, bi->buffer + bi->tail, sizeof bi->buffer - bi->tail);
			if (r <= 0)
				return r ? r : UC2_Truncated;
			bi->head = 0;
			bi->tail += r;
		}
		bi->bits = bi->bits<<16 | get16(bi->buffer + bi->head);
		bi->head += 2;
		bi->have_bits += 16;
	}
	return 0;
}

static int bits_peek(struct bits *bi, unsigned n)
{
	int r = bits_feed(bi, n);
	if (r < 0)
		return r;
	return bi->bits >> (bi->have_bits - n) & ((1 << n) - 1);
}

static int bits_get(struct bits *bi, unsigned n)
{
	int r = bits_peek(bi, n);
	if (r >= 0) bits_skip(bi, n);
	return r;
}

static void bits_destroy(struct bits *bi) {}

/* csum */

struct csum {
	u32 value;
};

static void csum_init(struct csum *cs)
{
	cs->value = 0xA55A;
}

static void csum_update(struct csum *cs, const u8 *p, unsigned n)
{
	if (!n)
		return;
	u32 v = cs->value;
	const u8 *e = p + n - 1;
	if (v > 0xffff)
		v ^= *p++ << 8;
	while (p < e) {
		v ^= get16(p);
		p += 2;
	}
	v &= 0xffff;
	if (p == e)
		v ^= *p | 0x10000;
	cs->value = v;
}

static u16 csum_get(struct csum *fr)
{
	return (u16)fr->value;
}

/* fifo */

#define FIFO_BUFSZ (1<<14)

struct fifo_entry {
	struct list list;
	u8 buffer[FIFO_BUFSZ];
};

static void fifo_init(struct fifo *fifo)
{
	list_init(&fifo->list);
	fifo->free = fifo->used = 0;
}

static void cdir_fifo_destroy(struct uc2_context *uc2)
{
	struct fifo *fifo = &uc2->cdir_buf;
	while (!list_empty(&fifo->list)) {
		struct fifo_entry *fe = list_get_item(&fifo->list, struct fifo_entry, list);
		list_del(&fe->list);
		u_free(uc2, fe);
	}
	fifo->free = fifo->used = 0;
}

static int fifo_write(void *context, const void *buffer, unsigned size)
{
	struct uc2_context *uc2 = context;
	struct fifo *fifo = &uc2->cdir_buf;
	const u8 *ptr = buffer;
	while (size) {
		if (!list_empty(&fifo->list)) {
			struct fifo_entry *fe;
			int free = sizeof fe->buffer - fifo->used;
			if (free) {
				fe = list_last(&fifo->list, struct fifo_entry, list);
				unsigned n = free < size ? free : size;
				memcpy(fe->buffer + fifo->used, ptr, n);
				fifo->used += n;
				size -= n;
				if (!size)
					break;
				ptr += n;
			}
		}
		struct fifo_entry *fe = u_alloc(uc2, sizeof *fe);
		if (!fe)
			return UC2_UserFault;
		list_add_end(&fifo->list, &fe->list);
		fifo->used = 0;
	}
	return 0;
}

static int fifo_read(void *context, void *buffer, unsigned size)
{
	struct uc2_context *uc2 = context;
	struct fifo *fifo = &uc2->cdir_buf;
	u8 *ptr = buffer;
	while (size && !list_empty(&fifo->list)) {
		struct fifo_entry *fe = list_item(fifo->list.next, struct fifo_entry, list);
		unsigned have = &fe->list == fifo->list.prev ? fifo->used : sizeof fe->buffer;
		have -= fifo->free;
		unsigned n = have < size ? have : size;
		assert(n);
		u8 *src = fe->buffer + fifo->free;
		fifo->free += n;
		memcpy(ptr, src, n);
		ptr += n;
		size -= n;
		if (n == have) {
			list_del(&fe->list);
			u_free(uc2, fe);
			fifo->free = 0;
		}
	}
	return ptr - (u8*)buffer;
}

/* names */

static u16 cp850[] = {
	0x00c7,0x00fc,0x00e9,0x00e2,0x00e4,0x00e0,0x00e5,0x00e7, 0x00ea,0x00eb,0x00e8,0x00ef,0x00ee,0x00ec,0x00c4,0x00c5,
	0x00c9,0x00e6,0x00c6,0x00f4,0x00f6,0x00f2,0x00fb,0x00f9, 0x00ff,0x00d6,0x00dc,0x00f8,0x00a3,0x00d8,0x00d7,0x0192,
	0x00e1,0x00ed,0x00f3,0x00fa,0x00f1,0x00d1,0x00aa,0x00ba, 0x00bf,0x00ae,0x00ac,0x00bd,0x00bc,0x00a1,0x00ab,0x00bb,
	0x2591,0x2592,0x2593,0x2502,0x2524,0x00c1,0x00c2,0x00c0, 0x00a9,0x2563,0x2551,0x2557,0x255d,0x00a2,0x00a5,0x2510,
	0x2514,0x2534,0x252c,0x251c,0x2500,0x253c,0x00e3,0x00c3, 0x255a,0x2554,0x2569,0x2566,0x2560,0x2550,0x256c,0x00a4,
	0x00f0,0x00d0,0x00ca,0x00cb,0x00c8,0x0131,0x00cd,0x00ce, 0x00cf,0x2518,0x250c,0x2588,0x2584,0x00a6,0x00cc,0x2580,
	0x00d3,0x00df,0x00d4,0x00d2,0x00f5,0x00d5,0x00b5,0x00fe, 0x00de,0x00da,0x00db,0x00d9,0x00fd,0x00dd,0x00af,0x00b4,
	0x00ad,0x00b1,0x2017,0x00be,0x00b6,0x00a7,0x00f7,0x00b8, 0x00b0,0x00a8,0x00b7,0x00b9,0x00b3,0x00b2,0x25a0,0x00a0
};

static u16 cp850_tolower[] = {
	0x00e7,0x00fc,0x00e9,0x00e2,0x00e4,0x00e0,0x00e5,0x00e7, 0x00ea,0x00eb,0x00e8,0x00ef,0x00ee,0x00ec,0x00e4,0x00e5,
	0x00e9,0x00e6,0x00e6,0x00f4,0x00f6,0x00f2,0x00fb,0x00f9, 0x00ff,0x00f6,0x00fc,0x00f8,0x00a3,0x00f8,0x00d7,0x0192,
	0x00e1,0x00ed,0x00f3,0x00fa,0x00f1,0x00f1,0x00aa,0x00ba, 0x00bf,0x00ae,0x00ac,0x00bd,0x00bc,0x00a1,0x00ab,0x00bb,
	0x2591,0x2592,0x2593,0x2502,0x2524,0x00e1,0x00e2,0x00e0, 0x00a9,0x2563,0x2551,0x2557,0x255d,0x00a2,0x00a5,0x2510,
	0x2514,0x2534,0x252c,0x251c,0x2500,0x253c,0x00e3,0x00e3, 0x255a,0x2554,0x2569,0x2566,0x2560,0x2550,0x256c,0x00a4,
	0x00f0,0x00f0,0x00ea,0x00eb,0x00e8,0x0131,0x00ed,0x00ee, 0x00ef,0x2518,0x250c,0x2588,0x2584,0x00a6,0x00ec,0x2580,
	0x00f3,0x00df,0x00f4,0x00f2,0x00f5,0x00f5,0x00b5,0x00fe, 0x00fe,0x00fa,0x00fb,0x00f9,0x00fd,0x00fd,0x00af,0x00b4,
	0x00ad,0x00b1,0x2017,0x00be,0x00b6,0x00a7,0x00f7,0x00b8, 0x00b0,0x00a8,0x00b7,0x00b9,0x00b3,0x00b2,0x25a0,0x00a0
};

enum casechg {KeepCase, LowerCase};

static u8 *put_utf8(u8 *d, u8 *e, enum casechg cc, u8 c)
{
	if (c < 128) {
		if (d+1 > e) return 0;
		if (cc == LowerCase && c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
	} else {
		if (d+2 > e) return 0;
		u16 u = (cc==LowerCase ? cp850_tolower : cp850)[c - 128];
		c = 0xC0;
		if (u >= 0x800) {
			if (d+3 > e) return 0;
			*d++ = u >> 12 | 0xE0;
			c = 0x80;
		}
		*d++ = (u >> 6 & 0x3F) | c;
		c = (u & 0x3F) | 0x80;
	}
	*d++ = c;
	assert(d <= e);
	return d;
}

static void copy_long_name(struct uc2_entry *e, u8 *s, u8 *se)
{
	u8 *d = (u8*)e->name;
	u8 *de = d + sizeof e->name - 1;
	do {
		u8 c = *s++;
		if (!c)
			break;
		if (d == de)
			return;
		d = put_utf8(d, de, KeepCase, c);
		if (!d)
			return;
	} while (s < se);
	*d = 0;
	e->name_len = (unsigned short)(d - (u8*)e->name);
}

static void assemble_name(struct uc2_entry *e)
{
	u8 *d = (u8*)e->name;
	u8 *s = e->dos_name;
	u8 *z = s + 8;
	for (;;) {
		while (z > s) {
			if (z[-1] != ' ')
				break;
			z--;
		}
		if (s > e->dos_name) {
			if (s == z)
				break;
			*d++ = '.';
		}
		while (s < z) {
			u8 c = *s++;
			d = put_utf8(d, (u8*)e->name + sizeof e->name, LowerCase, c);
			assert(d);
		}
		s = e->dos_name + 8;
		if (s < z)
			break;
		z = s + 3;
	}
	*d = 0;
	e->name_len = (unsigned short)(d - (u8*)e->name);
}

/* master */

static int decompressor(struct uc2_context *uc2, int method, struct reader *rd, struct writer *wr, unsigned master, unsigned len, u16 *csum);

struct compress {
	u32 csize;
	u16 method;
	u32 master;
};

enum {
	SuperMaster = 0,
	NoMaster = 1,
	FirstMaster = 2
};

struct master_info {
	u32 id;
	u16 size;
	unsigned offset;
	struct compress com;
	struct list list;
	u8 *data;
};

static struct master_info *find_master(struct uc2_context *uc2, unsigned id)
{
	for (struct list *l = uc2->masters.next; l != &uc2->masters; l = l->next) {
		struct master_info *mi = list_item(l, struct master_info, list);
		if (mi->id == id)
			return mi;
	}
	return 0;
}

static int resolve_master(struct uc2_context *uc2, unsigned master)
{
	struct master_info *stack[16];
	unsigned sp = 0;
	int r;

	while (master >= FirstMaster) {
		struct master_info *mi = find_master(uc2, master);
		if (!mi) {
			diag("Master %X missing\n", master);
			return UC2_Damaged;
		}
		if (mi->data)
			break;
		for (int i=0; i<sp; i++)
			if (stack[i] == mi)
				return UC2_Damaged;
		if (sp >= elemof(stack))
			return UC2_InternalError;
		stack[sp++] = mi;
		master = mi->com.master;
	}

	if (!uc2->supermaster) {
		uc2->supermaster = u_alloc(uc2, 49152);
		if (!uc2->supermaster)
			return UC2_UserFault;

		extern u8 uc2_supermaster_compressed[], uc2_supermaster_compressed_end[];
		struct range br = {.ptr = uc2_supermaster_compressed, .end = uc2_supermaster_compressed_end};
		struct range bw = {.ptr = uc2->supermaster, .end = uc2->supermaster + 49152};
		struct reader rd = {.read = buf_read, .context = &br};
		struct writer wr = {.write = buf_write, .context = &bw};
		u16 csum;
		r = decompressor(uc2, 4, &rd, &wr, NoMaster, 49152, &csum);
		if (r < 0)
			return r;
		if (csum != 0x1E55)
			return UC2_InternalError;
	}

	while (sp--) {
		struct master_info *mi = stack[sp];
		diag("Decompressing master %X size:%u master:%X method:%u\n", mi->id, mi->size, mi->com.master, mi->com.method);
		mi->data = u_alloc(uc2, mi->size);
		struct archive_ctx ar = {.offset = mi->offset, .uc2 = uc2};
		struct reader rd = {.read = archive_read, .context = &ar};
		struct range bw = {.ptr = mi->data, .end = mi->data + mi->size};
		struct writer wr = {.write = buf_write, .context = &bw};
		r = decompressor(uc2, mi->com.method, &rd, &wr, mi->com.master, mi->size, 0);
		diag("Decompressed master %u left:%d\n", mi->id, (int)(bw.end-bw.ptr));
		if (r < 0)
			return r;
	}
	return 0;
}

static int use_master(struct uc2_context *uc2, u8 buffer[49152], u32 id)
{
	int size;

	switch (id) {
	case SuperMaster:
		diag("Using supermaster\n");
		size = 49152;
		if (buffer)
			memcpy (buffer, uc2->supermaster, size);
		break;
	case NoMaster:
		diag("No master\n");
		size = 512;
		if (buffer)
			memset(buffer, 0, size);
		break;
	default:
		diag("Using master %d\n", id);
		struct master_info *mi = find_master(uc2, id);
		assert(mi);
		size = mi->size;
		if (buffer)
			memcpy(buffer, mi->data, size);
	}

	diag("Result master len:%u\n", size);
	return size;
}

/* cdir */

static int scan_start(struct uc2_context *uc2);
static int read_entry(struct uc2_context *uc2, struct uc2_entry *e, u8 type, uc2_tag_callback new_tag);
static void copy_dos_name(u8 *dos_name, u8 *s);
static int cdir_damaged(struct uc2_context *uc2);

int uc2_scan(struct uc2_context *uc2, struct uc2_entry *e, uc2_tag_callback new_tag)
{
	int ret;

	if (!e && uc2->scanned)
		return 0;

	if (!uc2->scanning) {
		fifo_init(&uc2->cdir_buf);
		ret = scan_start(uc2);
		if (ret < 0)
			return ret;
		uc2->scanning = 1;
	}

	struct reader rd = {.read = fifo_read, .context = uc2};

	for (;;) {
		REC(OHEAD) oh;
		ret = read_all(&rd, &oh, sizeof oh);
		if (ret < 0)
			goto ret;
		if (oh.type == EndOfCdir)
			break;
		switch(oh.type) {
		case FileEntry:
		case DirEntry:
			ret = read_entry(uc2, e, oh.type, new_tag);
			if (ret < 0)
				goto ret;
			if (e)
				return 1;
			break;

		case MasterEntry:;
			struct {
				REC(MASMETA) m;
				REC(COMPRESS) c;
				REC(LOCATION) l;
			} m;
			ret = read_all(&rd, &m, sizeof m);
			if (ret < 0)
				goto ret;
			if (uc2->scanned)
				break;

			struct master_info *mi = u_alloc(uc2, sizeof *mi);
			if (!mi) {
				ret = UC2_UserFault;
				goto ret;
			}
			mi->id = get32(m.m.index);
			mi->size = get16(m.m.length);
			if (get32(m.l.volume) != 1) {
				ret = UC2_Unimplemented;
				goto ret;
			}
			mi->offset = get32(m.l.offset);
			mi->com.csize = get32(m.c.compressedLength);
			mi->com.method = get16(m.c.method);
			mi->com.master = get32(m.c.masterPrefix);
//			assert(get16(m.m.fletch) == 0xdede);
			diag("master %X sz:%u csize:%u loc:%u csum:%04X master:%X\n", mi->id, mi->size, mi->com.csize, mi->offset, get16(m.m.fletch), mi->com.master);
			if (mi->com.master == 0xdededede)
				mi->com.master = SuperMaster;
			mi->data = 0;
			list_add(&uc2->masters, &mi->list);
			break;

		default:
			ret = cdir_damaged(uc2);
			goto ret;
		}
	}

	{
		REC(XTAIL) xt;
		ret = read_all(&rd, &xt, sizeof xt);
		if (ret < 0)
			goto ret;
		u8 * p = memchr(xt.label, 0, 11);
		if (!p) p = xt.label + 11;
		while (p > xt.label && p[-1] == ' ') p--;
		memcpy(uc2->label, xt.label, p - xt.label);
		uc2->label[p - xt.label] = 0;
	}

	uc2->scanned = 1;
	ret = 0;
ret:
	cdir_fifo_destroy(uc2);
	uc2->scanning = 0;
	return ret;
}

static int scan_start(struct uc2_context *uc2)
{
	int ret = 0;
	struct {
		REC(FHEAD) fhead;
		REC(XHEAD) xhead;
	} h;
	ret = u_read_all(uc2, 0, &h, sizeof h);
	if (ret < 0)
		return ret;

	if (!uc2_identify(&h, sizeof h)) {
		uc2->message = "Not an UC2 archive";
		return UC2_Damaged;
	}
	uc2->cdir_offset = get32(h.xhead.cdir.offset);
	uc2->cdir_csum = get16(h.xhead.fletch);
	u16 version_made = get16(h.xhead.versionMadeBy);
	u16 version_need = get16(h.xhead.versionNeededToExtract);

	diag("Cdir offset:%u made:%d need:%d\n", uc2->cdir_offset, version_made, version_need);

	{
		REC(COMPRESS) c;
		u32 offset;
		u16 method;

		offset = uc2->cdir_offset;
		ret = u_read_all(uc2, offset, &c, sizeof c);
		if (ret < 0)
			return ret;
		offset += sizeof c;

		u32 master = get32(c.masterPrefix);
		if (master != NoMaster)
			return cdir_damaged(uc2);
		method = get16(c.method);

		struct archive_ctx ar = {.offset=offset, .uc2 = uc2};
		struct reader rd = {.read = archive_read, .context = &ar};
		struct writer wr = {.write = fifo_write, .context = uc2};
		u16 csum;
		ret = decompressor(uc2, method, &rd, &wr, NoMaster, 100000000, &csum);
		if (ret < 0)
			return ret;

		if (uc2->cdir_csum != csum)
			return cdir_damaged(uc2);
	}

	return ret;
}

static int read_entry(struct uc2_context *uc2, struct uc2_entry *e, u8 type, uc2_tag_callback new_tag)
{
	struct {
		REC(OSMETA) m;
		union {
			struct {
				REC(FILEMETA) m;
				REC(COMPRESS) c;
				REC(LOCATION) l;
			} f;
			struct {
				REC(DIRMETA) m;
			} d;
		};
	} rc;

	struct reader rd = {.read = fifo_read, .context = uc2};
	unsigned sz = sizeof rc.m + (type == FileEntry ? sizeof rc.f : sizeof rc.d);
	int ret = read_all(&rd, &rc, sz);
	if (ret < 0)
		return ret;

	diag("%X %08X [%.11s] ", type, get32(rc.m.parent), rc.m.name);
	if (type == FileEntry) diag("(C:%-3u M:%-2u O:%-5X) %7d %7d\n",
	 get16(rc.f.c.method), get32(rc.f.c.masterPrefix), get32(rc.f.l.offset),
	 get32(rc.f.m.length), get32(rc.f.c.compressedLength));
	else diag("%08X\n", get32(rc.d.m.index));

	if (e) {
		e->dirid = get32(rc.m.parent);
		e->dos_time = get32(rc.m.time);
		e->attr = rc.m.attrib;
		if (type == FileEntry) {
			e->id = 0;
			e->size = get32(rc.f.m.length);
			e->csum = get32(rc.f.m.fletch);
			e->csize = get32(rc.f.c.compressedLength);
			if (get32(rc.f.l.volume) != 1)
				return UC2_Unimplemented;
			e->offset = get32(rc.f.l.offset);
			e->method = get16(rc.f.c.method);
			e->master = get32(rc.f.c.masterPrefix);
			e->is_dir = 0;
		} else {
			e->id = get32(rc.d.m.index);
			e->size = e->csize = 0;
			e->offset = e->method = e->master = 0;
			e->is_dir = 1;
		}
		e->has_tags = !!rc.m.tag;
		copy_dos_name(e->dos_name, rc.m.name);
		e->name_len = 0;
	}

	if (rc.m.tag) for (;;) {
		REC(EXTMETA) x;
		ret = read_all(&rd, &x, sizeof x);
		if (ret < 0)
			return ret;
		unsigned tagsz = get32(x.size);
		if (tagsz > 1000000)
			return cdir_damaged(uc2);
		u8 *p = u_alloc(uc2, tagsz);
		if (!p)
			return UC2_UserFault;
		ret = read_all(&rd, p, tagsz);
		int free = 1;
		if (ret >= 0 && e) {
			if (memcmp(x.tag, TAG_LONGNAME, sizeof TAG_LONGNAME) == 0) {
				u8 *z = memchr(p, 0, tagsz);
				if (!z) z = p + tagsz;
				copy_long_name(e, p, z);
			}
			if (new_tag) {
				int r = new_tag((char*)x.tag, p, tagsz, e);
				if (r > 0)
					free = 0;
			}
		}
		if (free)
			u_free(uc2, p);
		if (ret < 0)
			return ret;
		if (!x.next)
			break;
	}

	if (e) {
		if (!e->name_len)
			assemble_name(e);
	}
	return 0;
}

static void copy_dos_name(u8 *dos_name, u8 *s)
{
	u8 *d = dos_name;
	u8 *z = d + 8;
	for (;;) {
		do {
			u8 c = *s++;
			if (!c) {
				do {
					*d++ = ' ';
				} while (d < z);
				break;
			}
			*d++ = c;
		} while (d < z);
		d = dos_name + 8;
		if (d < z)
			break;
		z = d + 3;
	}
}

static int cdir_damaged(struct uc2_context *uc2)
{
	uc2->message = "Central directory is damaged";
	return UC2_Damaged;
}

/* delta */

struct delta {
	u8 size;
	u8 index;
	u8 val[8];
};

static void delta_init(struct delta *db, u8 type)
{
	struct delta d = {.size = type};
	*db = d;
}

static void delta_apply(struct delta *db, u8 *p, unsigned size)
{
	struct delta d = *db;
	while (size--) {
		u8 v = *p;
		*p++ = v - d.val[d.index];
		d.val[d.index] = v;
		if (++d.index == d.size)
			d.index = 0;
	}
	*db = d;
}

static void delta_revert(struct delta *db, u8 *dst, const u8 *src, unsigned size)
{
	struct delta d = *db;
	while (size--) {
		u8 v = *src++ + d.val[d.index];
		d.val[d.index] = *dst++ = v;
		if (++d.index == d.size)
			d.index = 0;
	}
	*db = d;
}

#define DELTA_WRITER_BUFSZ 65536
struct delta_writer_ctx {
	struct writer *old_wr;
	struct delta delta;
	u8 *buf;
};

static int delta_writer_init(struct uc2_context *uc2, struct delta_writer_ctx *dw, struct writer *wr, unsigned delta)
{
	dw->buf = u_alloc(uc2, DELTA_WRITER_BUFSZ);
	if (!dw->buf) return UC2_UserFault;
	dw->old_wr = wr;
	delta_init(&dw->delta, delta);
	return 0;
}

static void delta_writer_destroy(struct uc2_context *uc2, struct delta_writer_ctx *dw)
{
	dw->buf = u_free(uc2, dw->buf);
}

static int delta_write(void *context, const void *buffer, unsigned size)
{
	if (!size) return 0;
	struct delta_writer_ctx *dw = context;
	if (size > DELTA_WRITER_BUFSZ)
		return UC2_InternalError;
	delta_revert(&dw->delta, dw->buf, buffer, size);
	return dw->old_wr->write(dw->old_wr->context, dw->buf, size);
}

/* extract */

int uc2_extract(
	struct uc2_context *uc2,
	struct uc2_entry *e,
	int (*write)(void *context, unsigned pos, const void *ptr, unsigned len),
	void *context)
{
	int ret;

	diag("Extracting %s %u bytes\n", e->name, e->size);
	if (!uc2->scanned)
		return UC2_BadState;
	ret = resolve_master(uc2, e->master);
	if (ret < 0)
		return ret;

	struct archive_ctx ar = {.offset=e->offset, .uc2 = uc2};
	struct reader rd = {.read = archive_read, .context = &ar};
	struct user_write_ctx uw_ctx = {.pos=0, .write=write, .context=context};
	struct writer wr = {.write = user_write, .context = &uw_ctx};
	u16 csum;
	ret = decompressor(uc2, e->method, &rd, &wr, e->master, e->size, &csum);
	diag("decompressor ret:%d csum:%04X (expected:%04X)\n", ret, csum, e->csum);
	if (ret >= 0 && csum != e->csum)
		ret = UC2_Damaged;
	return ret;
}

/* decompress */

static int decompressor_ultra(struct uc2_context *uc2, unsigned master, unsigned delta, struct reader *rd, struct writer *wr, unsigned limit, u16 *csum);

static int decompressor(struct uc2_context *uc2, int method, struct reader *rd, struct writer *wr, unsigned master, unsigned len, u16 *csum)
{
	unsigned delta;
	int ret = UC2_Damaged;

	diag("Decompressor method:%d master:%X\n", method, master);
	if (method >= 1 && method <= 9) {
		ret = decompressor_ultra(uc2, master, 0, rd, wr, len, csum);
	} else if (method >= 30 && method <= 39) {
		delta = method - 29;
		goto delta;
	} else if (method >= 40 && method <= 49) {
		delta = method - 39;
		goto delta;
	} else if (method >= 21 && method <= 29) {
		delta = 1;
		goto delta;
	} else if (method == 80) {
		uc2->message = "Turbo compression not implemented";
		ret = UC2_Unimplemented;
	}
	diag("Decompressor end\n");
	return ret;

delta:;
	struct delta_writer_ctx dw_context;
	delta_writer_init(uc2, &dw_context, wr, delta);
	struct writer delta_wr = {.write = delta_write, .context = &dw_context};
	ret = decompressor_ultra(uc2, master, delta, rd, &delta_wr, len, csum);
	delta_writer_destroy(uc2, &dw_context);
	diag("Decompressor end\n");
	return ret;
}

/* cbuf */

struct cbuffer {
	u16 head, tail;
	unsigned limit;
	struct csum csum;
	u8 data[0x10000];
};

static int cbuf_have(struct cbuffer *cb)
{
	return (u16)(cb->tail - cb->head);
}

static int cbuf_space(struct cbuffer *cb)
{
	return 0x10000 - cbuf_have(cb) - 1;
}

static int cbuf_flush(struct writer *wr, struct cbuffer *cb)
{
	for (;;) {
		int n = cbuf_have(cb);
		if (!n) return 0;
		int u = 0x10000 - cb->head;
		if (n > u) n = u;
		if (cb->limit < n) {
			diag("cbuf_write %u < %u\a\n", cb->limit, n);
			n = cb->limit;
		}
		u8 *p = cb->data + cb->head;
		csum_update(&cb->csum, p, n);
		int r = wr->write(wr->context, p, n);
		if (r < 0)
			return r;
		cb->head += n;
		cb->limit -= n;
		if (!cb->limit)
			break;
	}
	return 0;
}

/* huffman */

enum {
	MaxCodeBits = 13,
	LookupSize = 1 << MaxCodeBits
};

static int huff(u32 table[LookupSize], struct bits *bi)
{
	int b = bits_peek(bi, 13);
	if (b < 0)
		return b;
	u32 c = table[b];
	bits_skip(bi, c >> 24);
	return c & 0xffffff;
}

enum {
	NumByteSym = 256,
	NumDistSym = 60,
	NumLenSym = 28,
	NumSymbols = NumByteSym + NumDistSym + NumLenSym,

	NumLoAsciiSym = 28,
	NumHiByteSym = 128
};

struct dcinfo {
	u8 symprev[NumSymbols];
};

static void dc_init(struct dcinfo *dc);
static int ht_dec(u8 lengths[NumSymbols], struct dcinfo *dc, struct bits *bi, u32 table[LookupSize]);
static int ht_mktree(u32 table[LookupSize], const u8 *lengths, int nlit, int ncodes, const u32 *codes);

enum {
	NumDeltaCodes = MaxCodeBits + 1,
	NumExtraCodes = 1,
	NumLenCodes = NumDeltaCodes + NumExtraCodes,
};

const u8 vval[NumDeltaCodes][NumDeltaCodes] = {
	{ 0,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13, 0},
	{ 2, 1, 3, 4, 5, 6, 7, 8, 9,10,11,12,13, 0},
	{ 3, 2, 4, 1, 5, 6, 7, 8, 9,10,11,12,13, 0},
	{ 4, 3, 5, 2, 6, 1, 7, 8, 9,10,11,12,13, 0},
	{ 5, 4, 6, 3, 7, 2, 8, 1, 9,10,11,12,13, 0},
	{ 6, 5, 7, 4, 8, 3, 9, 2,10, 1,11,12,13, 0},
	{ 7, 6, 8, 5, 9, 4,10, 3,11, 2,12, 1,13, 0},
	{ 8, 7, 9, 6,10, 5,11, 4,12, 3,13, 2, 0, 1},
	{ 9, 8,10, 7,11, 6,12, 5,13, 4, 0, 3, 2, 1},
	{10, 9,11, 8,12, 7,13, 6, 0, 5, 4, 3, 2, 1},
	{11,10,12, 9,13, 8, 0, 7, 6, 5, 4, 3, 2, 1},
	{12,11,13,10, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	{13,12, 0,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
};

static void default_lengths(u8 d[NumSymbols])
{
	static const u8 rle[] = {
		10,9, 1,7, 1,9, 1,7, 19,9, 1,7, 13,8, 1,7, 11,8, 1,7, 33,8, 1,7, 35,8, 128,10, 16,6, 12,7, 6,8, 10,9, 16,10, 9,4, 9,5, 10,6, 0
	};
	const u8 *s = rle;
	u8 n = s[0];
	do {
		u8 v = s[1];
		s += 2;
		do {
			*d++ = v;
		} while (--n);
		n = *s;
	} while (n);
}

static void dc_init(struct dcinfo *dc)
{
	default_lengths(dc->symprev);
}

enum {
	RepeatCode = MaxCodeBits + 1,
	MinRepeat = 6
};

static int ht_dec(u8 lengths[NumSymbols], struct dcinfo *dc, struct bits *bi, u32 table[LookupSize])
{
	int t = bits_get(bi, 1);
	if (t <= 0) {
		if (t == 0) {
			default_lengths(dc->symprev);
			default_lengths(lengths);
		}
		return t;
	}

	diag("New tree\n");
	t = bits_get(bi, 2);
	if (t < 0)
		return t;

	u8 tlengths[NumLenCodes];
	for (int i = 0; i < NumLenCodes; i++) {
		int b = bits_get(bi, 3);
		if (b < 0)
			return b;
		tlengths[i] = (u8)b;
	}

	ht_mktree(table, tlengths, NumLenCodes, 0, 0);

	u8 stream[NumSymbols];
	u8 *symp = stream;
	u8 *syme = stream + NumSymbols - NumLoAsciiSym - NumHiByteSym;
	if (t & 1)
		syme += NumLoAsciiSym;
	if (t & 2)
		syme += NumHiByteSym;

	u8 val = 0;
	do {
		int c = huff(table, bi);
		if (c < 0)
			return c;
		if (c == RepeatCode) {
			c = huff(table, bi);
			if (c < 0)
				return c;
			int n = c + MinRepeat - 1;
			for(; n > 0; n--)
				*symp++ = val;
		} else {
			val = c;
			*symp++ = c;
		}
	} while (symp < syme);

	static const u16 rle[][8] = {
		{0x009, 0x202, 0x1, 0x202, 0x12, 0x260, 0x80, 0x258},
		{0x280, 0x80, 0x258},
		{0x009, 0x202, 0x1, 0x202, 0x12, 0x338},
		{0x358}
	};
	const u16 *p = rle[t];
	int i = 0;
	symp = stream;
	do {
		u16 v = *p++;
		int e = i + (v & 0x1ff);
		do {
			lengths[i] = v & 0x200 ? vval[dc->symprev[i]][*symp++] : 0;
		} while (++i < e);
	} while (symp < syme);

	for (int i = 0; i < NumSymbols; i++) {
		assert(lengths[i] <= 13);
		dc->symprev[i] = lengths[i];
	}

	return 0;
}


static int ht_mktree(u32 table[LookupSize], const u8 *lengths, int nlit, int ncodes, const u32 *codes)
{
	int nsym = nlit + ncodes;
	u32 *p = table;
	u32 *e = table + LookupSize;

	for (int l = 1; l <= MaxCodeBits; l++) {
		for (int i = 0; i < nsym; i++) {
			if (lengths[i] == l) {
				int n = 1 << (MaxCodeBits - l);
				if (p + n > e)
					return UC2_Damaged;
				u32 c = i < nlit ? i : codes[i - nlit];
				c |= l << 24;
				do {
					*p++ = c;
				} while (--n);
			}
		}
	}

//	if (p != e)
//		return UC2_Damaged;
	while (p < e)
		*p++ = 1<<24;

	return 0;
}

/* ultra */

struct ultra {
	struct uc2_context *uc2;
	struct bits bi;
	struct dcinfo dc;
	struct cbuffer cb;

	u32 bd_table[LookupSize];
	u32 l_table[LookupSize];
};

static int decode_ht(struct ultra *ultra);
static int decompress_block(struct ultra *ultra, struct writer *wr);

static int decompressor_ultra(struct uc2_context *uc2, unsigned master, unsigned delta, struct reader *rd, struct writer *wr, unsigned limit, u16 *csum)
{
	diag("decompressor_ultra master:%X limit:%u\n", master, limit);

	int ret;

	struct ultra *ultra = u_alloc(uc2, sizeof *ultra);
	if (!ultra)
		return UC2_UserFault;
	ultra->uc2 = uc2;

	ret = use_master(uc2, ultra->cb.data, master);
	if (ret < 0)
		goto ret;
	ultra->cb.limit = limit;
	ultra->cb.head = ultra->cb.tail = ret;
	csum_init(&ultra->cb.csum);

	if (delta && master != SuperMaster) {
		struct delta db;
		diag("applying delta %d\n", delta);
		delta_init(&db, delta);
		delta_apply(&db, ultra->cb.data, ultra->cb.tail);
	}


	ret = bits_init(&ultra->bi, rd);
	if (ret < 0)
		goto ret;

	dc_init(&ultra->dc);
	for (;;) {
		ret = decode_ht(ultra);
		if (ret <= 0)
			break;
		ret = decompress_block(ultra, wr);
		if (ret)
			break;
	}
	ret = cbuf_flush(wr, &ultra->cb);
	bits_destroy(&ultra->bi);
	if (csum)
		*csum = csum_get(&ultra->cb.csum);
ret:
	u_free(uc2, ultra);
	return ret;
}

static int decode_ht(struct ultra *ultra)
{
	int ret = bits_get(&ultra->bi, 1);
	if (ret > 0) {
		u8 lengths[NumSymbols];
		u32 *tmp = ultra->bd_table;
		ret = ht_dec(lengths, &ultra->dc, &ultra->bi, tmp);
		if (ret < 0)
			return ret;

		#define D(V,B) ((B)<<20|1<<16|(V))
		static const u32 d_codes[NumDistSym] = {
			D(1,0),     D(2,0),     D(3,0),     D(4,0),     D(5,0),     D(6,0),     D(7,0),     D(8,0),
			D(9,0),     D(10,0),    D(11,0),    D(12,0),    D(13,0),    D(14,0),    D(15,0),    D(16,4),
			D(32,4),    D(48,4),    D(64,4),    D(80,4),    D(96,4),    D(112,4),   D(128,4),   D(144,4),
			D(160,4),   D(176,4),   D(192,4),   D(208,4),   D(224,4),   D(240,4),   D(256,8),   D(512,8),
			D(768,8),   D(1024,8),  D(1280,8),  D(1536,8),  D(1792,8),  D(2048,8),  D(2304,8),  D(2560,8),
			D(2816,8),  D(3072,8),  D(3328,8),  D(3584,8),  D(3840,8),  D(4096,12), D(8192,12), D(12288,12),
			D(16384,12),D(20480,12),D(24576,12),D(28672,12),D(32768,12),D(36864,12),D(40960,12),D(45056,12),
			D(49152,12),D(53248,12),D(57344,12),D(61440,12)
		};
		#undef D
		ret = ht_mktree(ultra->bd_table, lengths, NumByteSym, NumDistSym, d_codes);
		if (ret < 0)
			return ret;

		#define L(V,B) ((B)<<20|(V))
		static const u32 l_codes[NumLenSym] = {
			L(3,0),     L(4,0),     L(5,0),     L(6,0),     L(7,0),     L(8,0),     L(9,0),     L(10,0),
			L(11,1),    L(13,1),    L(15,1),    L(17,1),    L(19,1),    L(21,1),    L(23,1),    L(25,1),
			L(27,3),    L(35,3),    L(43,3),    L(51,3),    L(59,3),    L(67,3),    L(75,3),    L(83,3),
			L(91,6),    L(155,9),   L(667,11),  L(2715,15)
		};
		#undef L
		ret = ht_mktree(ultra->l_table, lengths + NumByteSym + NumDistSym, 0, NumLenSym, l_codes);
		if (ret < 0)
			return ret;
		ret = 1;
	}
	return ret;
}

static int decompress_block(struct ultra *ultra, struct writer *wr)
{
	const unsigned EOB_MARK = 125*512+1;

	for (;;) {
		int c = huff(ultra->bd_table, &ultra->bi);
		if (c < 0)
			return c;
		if (!(c & 1<<16))
			ultra->cb.data[ultra->cb.tail++] = (u8)c;
		else {
			unsigned dist = c & 0xffff;
			c = c >> 20 & 0xf;
			if (c)
				dist += bits_get(&ultra->bi, c);

			c = huff(ultra->l_table, &ultra->bi);
			if (c < 0)
				return c;

			if (dist == EOB_MARK) {
				diag("EOB_MARK\n");
				break;
			}

			unsigned len = c & 0xffff;
			c = c >> 20 & 0xf;
			if (c)
				len += bits_get(&ultra->bi, c);
			do {
				ultra->cb.data[ultra->cb.tail] = ultra->cb.data[(u16)(ultra->cb.tail - dist)];
				ultra->cb.tail++;
			} while (--len);
		}

		if (cbuf_space(&ultra->cb) < 35482) {
			int ret = cbuf_flush(wr, &ultra->cb);
			if (ret) return ret;
		}
	}
	return 0;
}

/* public */

struct uc2_context *uc2_open(struct uc2_io *io, void *io_ctx)
{
	struct uc2_context *uc2 = io->alloc(io_ctx, sizeof *uc2);
	if (uc2) {
		uc2->message = 0;
		uc2->io = io;
		uc2->io_ctx = io_ctx;
		uc2->supermaster = 0;
		uc2->label[0] = 0;
		uc2->scanning = 0;
		uc2->scanned = 0;
		list_init(&uc2->masters);
	}
	return uc2;
}

struct uc2_context *uc2_close(struct uc2_context *uc2)
{
	if (uc2) {
		struct list *l = uc2->masters.next;
		while (l != &uc2->masters) {
			struct master_info *mi = list_item(l, struct master_info, list);
			l = l->next;
			if (mi->data)
				u_free(uc2, mi->data);
			u_free(uc2, mi);
		}
		if (uc2->supermaster)
			u_free(uc2, uc2->supermaster);
		uc2 = u_free(uc2, uc2);
	}
	return uc2;
}

const char *uc2_label(struct uc2_context *uc2)
{
	return *uc2->label ? uc2->label : 0;
}

const char *uc2_message(struct uc2_context *uc2, int ret)
{
	const char *s = uc2->message;
	uc2->message = 0;
	if (!s) {
		static const char *tab[] = {
			[~UC2_UserFault] = "Callback fault",
			[~UC2_BadState] = "Bad state",
			[~UC2_Damaged] = "Archive damaged",
			[~UC2_Truncated] = "Truncated",
			[~UC2_Unimplemented] = "Unimplemented",
			[~UC2_InternalError] = "Internal Error"
		};
		if (~ret >= 0) {
			if (~ret < elemof(tab))
				s = tab[~ret];
			if (!s)
				s = "Error";
		}
	}
	return s;
}
