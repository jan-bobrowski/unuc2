/* UltraCompressor II decompression library.
   Copyright © Jan Bobrowski 2020–2022
   torinak.com/~jb/unuc2/

   This program is free software; you can redistribute it and
   modify it under the terms of the GNU Lesser General Public
   License version 3 as published by the Free Software Foundation.

   Original source by Nico de Vries, AIP used as a reference.
   nicodevries.com/professional/
*/

#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "libunuc2.h"

#if !defined NDEBUG && !defined NDIAG
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

/* records */

typedef struct u16le {u8 b[2];} u16le;
typedef struct u32le {u8 b[4];} u32le;

static u16 get16(u16le v) {return (u16)v.b[0] | (u16)v.b[1]<<8;}
static u32 get32(u32le v) {return (u32)v.b[0] | (u32)v.b[1]<<8 | (u32)v.b[2]<<16 | (u32)v.b[3]<<24;}

#define REC(R) struct R

REC(FHEAD) {
 u32le head;		// UC2^Z
 u32le componentLength;	// length of component contents
 u32le componentLength2;
 u8 damageProtected;
};

REC(LOCATION) {
 u32le volume;
 u32le offset;
};

REC(XHEAD) {
 REC(LOCATION) cdir;
 u16le fletch;
 u8 busy;
 u16le versionMadeBy;	// e.g. 200 means 2.00
 u16le versionNeededToExtract;
 u8 dummy;
};

REC(COMPRESS) {
 u32le compressedLength;
 u16le method;
 u32le masterPrefix;
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
 u32le parent;	// parent directory index
 u8 attrib;	// file attributes (MSDOS)
 u32le time;	// time last modified (MSDOS)
 u8 name[11];	// MS-DOS compatible name
 u8 hidden;	// 0 = plain visual, 1 = completely hidden
 u8 tag;	// has tags?
};

REC(FILEMETA) {
 u32le length;	// file length
 u16le fletch;	// fletcher checksum of raw data
};

REC(DIRMETA) {
 u32le index;	// directory index for referencing
};

REC(EXTMETA) {
 u8 tag[16];	// zero terminated
 u32le size;	// size of object
 u8 next;	// more tags?
};

#define TAG_LONGNAME "AIP:Win95 LongN"

REC(MASMETA) {
 u32le index;	// master index
 u32le key;	// master hash key
 u32le refLen;	// total size of refering data
 u32le refCtr;	// total number of refering files
 u16le length;	// master length
 u16le fletch;	// (Garbage 0xDEDE) fletcher checksum of raw data
};

REC(XTAIL) {
 u8 beta;	// archive made with beta test version
 u8 lock;	// locked archive
 u32le serial;	// special serial number (0 = none)
 u8 label[11];	// MS-DOS volume label
};

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

struct range {
	u8 *ptr, *end;
};

static unsigned range_len(struct range *r) {return (unsigned)(r->end - r->ptr);}

struct master_info;

struct uc2_context {
	char *message;
	struct uc2_io *io;
	void *io_ctx;

	u8 *supermaster;
	struct master_info *masters;

	u8 *cdir_buf;
	struct range cdir_range;

	enum {
		Start,
		AtEntry,
		AtTag,
		AtTail
	} cdir_state;

	u8 scanned:1;
	u8 pcp:1;
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
	if (ptr)
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

static int buf_read(void *context, void *ptr, unsigned size)
{
	struct range *br = context;
	unsigned have = range_len(br);
	if (have < size) {
		if (!have)
			return 0;
		size = have;
	}
	memcpy(ptr, br->ptr, size);
	br->ptr += size;
	return size;
}

static int buf_write(void *context, const void *ptr, unsigned size)
{
	struct range *bw = context;
	unsigned free = range_len(bw);
	if (free < size) {
		if (free == 0)
			return 0;
		size = free;
	}
	memcpy(bw->ptr, ptr, size);
	bw->ptr += size;
	return 0;
}

struct user_write_ctx {
	int (*write)(void *context, const void *ptr, unsigned len);
	void *context;
};

static int user_write(void *context, const void *buffer, unsigned size)
{
	struct user_write_ctx *uc = context;
	return uc->write(uc->context, buffer, size) < 0 ? UC2_UserFault : 0;
}

static void *range_get(struct range *r, unsigned n)
{
	unsigned l = range_len(r);
	if (l < n)
		return 0;
	u8 *p = r->ptr;
	r->ptr += n;
	return p;
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
		unsigned have = bi->tail - bi->head;
		if (have <= 1) {
			if (have == 1)
				bi->buffer[0] = bi->buffer[bi->tail - 1];
			bi->tail = have;
			int r = bi->rd->read(bi->rd->context, bi->buffer + have, sizeof bi->buffer - have);
			if (r <= 0)
				return r ? r : UC2_Truncated;
			bi->head = 0;
			bi->tail += r;
		}
		bi->bits = bi->bits << 16 | bi->buffer[bi->head] | bi->buffer[bi->head + 1] << 8;
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
		v ^= p[0] | p[1]<<8;
		p += 2;
	}
	v &= 0xffff;
	if (p == e)
		v ^= *p | 0x10000;
	cs->value = v;
}

static u16 csum_get(struct csum *cs)
{
	return (u16)cs->value;
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
		if (d + 1 > e) return 0;
		if (cc == LowerCase && c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
	} else {
		if (d+2 > e) return 0;
		u16 u = (cc == LowerCase ? cp850_tolower : cp850)[c - 128];
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
	u8 *d = (u8 *)e->name;
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
	e->name_len = (unsigned short)(d - (u8 *)e->name);
}

static void assemble_name(struct uc2_entry *e)
{
	u8 *d = (u8 *)e->name;
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
			d = put_utf8(d, (u8 *)e->name + sizeof e->name, LowerCase, c);
			assert(d);
		}
		s = e->dos_name + 8;
		if (s < z)
			break;
		z = s + 3;
	}
	*d = 0;
	e->name_len = (unsigned short)(d - (u8 *)e->name);
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
	struct master_info *next;
	struct master_info *needed_by; // in resolve_master()
	u8 *data;
};

static struct master_info *find_master(struct uc2_context *uc2, unsigned id)
{
	for (struct master_info *mi = uc2->masters; mi; mi = mi->next) {
		if (mi->id == id)
			return mi;
	}
	return 0;
}

static const u8 supermaster_compressed[] = {
#include SUPER_INC
};

static int resolve_master(struct uc2_context *uc2, unsigned master)
{
	if (uc2->pcp) {
		uc2->message = "PCP not implemented";
		return UC2_Unimplemented;
	}

	if (!uc2->supermaster) {
		uc2->supermaster = u_alloc(uc2, 49152);
		if (!uc2->supermaster)
			return UC2_UserFault;

		struct range br = {.ptr = (u8 *)supermaster_compressed, .end = (u8 *)supermaster_compressed + sizeof supermaster_compressed};
		struct range bw = {.ptr = uc2->supermaster, .end = uc2->supermaster + 49152};
		struct reader rd = {.read = buf_read, .context = &br};
		struct writer wr = {.write = buf_write, .context = &bw};
		u16 csum;
		int r = decompressor(uc2, 4, &rd, &wr, NoMaster, 49152, &csum);
		if (r < 0)
			return r;
		if (csum != 0x1E55)
			return UC2_InternalError;
	}

	if (master < FirstMaster)
		return 0;

	struct master_info *mi = 0;
	do {
		struct master_info *m = find_master(uc2, master);
		if (!m) {
			diag("Master %X missing\n", master);
			return UC2_Damaged;
		}
		if (m->size > 0xffff)
			return UC2_Damaged;
		if (m->needed_by) {
			diag("%X: Circular dependency\n", master);
			return UC2_Damaged;
		}
		if (m->data)
			break;
		if (mi)
			m->needed_by = mi;
		mi = m;
		master = m->com.master;
	} while (master >= FirstMaster);

	while (mi) {
		diag("Decompressing master %X size:%u master:%X method:%u\n", mi->id, mi->size, mi->com.master, mi->com.method);
		mi->data = u_alloc(uc2, mi->size);
		if (!mi->data)
			return UC2_UserFault;
		struct archive_ctx ar = {.offset = mi->offset, .uc2 = uc2};
		struct reader rd = {.read = archive_read, .context = &ar};
		struct range bw = {.ptr = mi->data, .end = mi->data + mi->size};
		struct writer wr = {.write = buf_write, .context = &bw};
		int r = decompressor(uc2, mi->com.method, &rd, &wr, mi->com.master, mi->size, 0);
		diag("Decompressed master %u left:%u\n", mi->id, range_len(&bw));
		if (r < 0)
			return r;
		struct master_info *m = mi;
		mi = mi->needed_by;
		m->needed_by = 0;
	}

	return 0;
}

static int use_master(struct uc2_context *uc2, u8 buffer[65535], u32 id)
{
	int size;

	switch (id) {
	case SuperMaster:
		diag("Using supermaster\n");
		size = 49152;
		if (buffer)
			memcpy(buffer, uc2->supermaster, size);
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
		assert(mi); // Wev'e fetched it already
		assert(mi->data);
		assert(mi->size <= 65535);
		size = mi->size;
		if (buffer)
			memcpy(buffer, mi->data, size);
	}

	diag("Master %d len:%u\n", id, size);
	return size;
}

/* cdir */

static int cdir_damaged(struct uc2_context *uc2);

static int decompress_cdir(struct uc2_context *uc2, u32 offset, u16 csum)
{
	assert(!uc2->cdir_buf);

	REC(COMPRESS) c;

	int ret = u_read_all(uc2, offset, &c, sizeof c);
	if (ret < 0)
		return ret;
	offset += sizeof c;

	u32 master = get32(c.masterPrefix);
	if (master != NoMaster)
		return cdir_damaged(uc2);

	enum {
		Prealloc = 0x4000
	};

	unsigned size = Prealloc;
	for (;;) {
		uc2->cdir_buf = u_alloc(uc2, size);
		if (!uc2->cdir_buf)
			return UC2_UserFault;

		struct archive_ctx ar = {.offset = offset, .uc2 = uc2};
		struct reader rd = {.read = archive_read, .context = &ar};
		struct range wrctx = {.ptr = uc2->cdir_buf, .end = uc2->cdir_buf + size};
		struct writer wr = {.write = buf_write, .context = &wrctx};
		u16 cs;
		ret = decompressor(uc2, get16(c.method), &rd, &wr, NoMaster, 100000000, &cs);
		if (ret < 0)
			return ret;

		if (cs != csum)
			return cdir_damaged(uc2);

		if ((unsigned)ret <= size)
			break;

		diag("Decompressing Cdir again (size:%u < %d)\n", size, ret);
		size = ret;
		uc2->cdir_buf = u_free(uc2, uc2->cdir_buf);
	}

	uc2->cdir_range.end = uc2->cdir_buf + size;
	return 0;
}

static int start_read(struct uc2_context *uc2);
static int read_entry(struct uc2_context *uc2, struct uc2_entry *e, u8 type);
static void copy_dos_name(u8 *dos_name, u8 *s);

int uc2_read_cdir(struct uc2_context *uc2, struct uc2_entry *e)
{
	int ret;

	if (uc2->cdir_state == Start) {
		if (!uc2->cdir_buf) {
			ret = start_read(uc2);
			if (ret < 0)
				return ret;
		}

		uc2->cdir_range.ptr = uc2->cdir_buf;
		uc2->cdir_state = AtEntry;
	}

	for (;;) {
		REC(OHEAD) *oh = range_get(&uc2->cdir_range, sizeof *oh);
		if (!oh)
			return UC2_Truncated;
		switch (oh->type) {
		case FileEntry:
		case DirEntry:
			ret = read_entry(uc2, e, oh->type);
			if (ret < 0)
				return ret;
			if (ret > UC2_BareEntry)
				uc2->cdir_state = AtTag;
			if (e)
				return ret;

			ret = uc2_get_tag(uc2, 0, 0, 0, 0); // Skip tags
			if (ret < 0)
				return ret;
			break;

		case MasterEntry:;
			struct {
				REC(MASMETA) m;
				REC(COMPRESS) c;
				REC(LOCATION) l;
			} *m = range_get(&uc2->cdir_range, sizeof *m);
			if (!m)
				return UC2_Truncated;
			if (uc2->scanned)
				break;
			if (get32(m->l.volume) != 1)
				return UC2_Unimplemented;

			struct master_info *mi = u_alloc(uc2, sizeof *mi);
			if (!mi)
				return UC2_UserFault;
			mi->id = get32(m->m.index);
			mi->size = get16(m->m.length);
			mi->offset = get32(m->l.offset);
			mi->com.csize = get32(m->c.compressedLength);
			mi->com.method = get16(m->c.method);
			mi->com.master = get32(m->c.masterPrefix);
//			assert(get16(m.m.fletch) == 0xdede);
			diag("master %X sz:%u csize:%u loc:%u csum:%04X master:%X\n", mi->id, mi->size, mi->com.csize, mi->offset, get16(m->m.fletch), mi->com.master);
			if (mi->com.master == 0xdededede)
				mi->com.master = SuperMaster;
			mi->needed_by = 0;
			mi->data = 0;
			mi->next = uc2->masters;
			uc2->masters = mi;
			break;

		case EndOfCdir:
			uc2->cdir_state = AtTail;
			uc2->scanned = 1;
			return UC2_End;

		default:
			return cdir_damaged(uc2);
		}
	}
}

static int read_entry(struct uc2_context *uc2, struct uc2_entry *e, u8 type)
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
		} u;
	} *rc;

	unsigned sz = sizeof rc->m + (type == FileEntry ? sizeof rc->u.f : sizeof rc->u.d);
	rc = range_get(&uc2->cdir_range, sz);
	if (!rc)
		return UC2_Truncated;

	diag("%X %08X [%.11s] ", type, get32(rc->m.parent), rc->m.name);
	if (type == FileEntry) diag("(C:%-3u M:%-2u O:%-5X) %7d %7d\n",
	 get16(rc->u.f.c.method), get32(rc->u.f.c.masterPrefix), get32(rc->u.f.l.offset),
	 get32(rc->u.f.m.length), get32(rc->u.f.c.compressedLength));
	else diag("%08X\n", get32(rc->u.d.m.index));

	if (e) {
		e->dirid = get32(rc->m.parent);
		e->dos_time = get32(rc->m.time);
		e->attr = rc->m.attrib;
		if (type == FileEntry) {
			e->id = 0;
			e->size = get32(rc->u.f.m.length);
			e->csize = get32(rc->u.f.c.compressedLength);
			if (get32(rc->u.f.l.volume) != 1)
				return UC2_Unimplemented;
			e->xi.offset = get32(rc->u.f.l.offset);
			e->xi.master = get32(rc->u.f.c.masterPrefix);
			e->xi.csum = get16(rc->u.f.m.fletch);
			e->xi.method = get16(rc->u.f.c.method);
			e->is_dir = 0;
		} else {
			e->id = get32(rc->u.d.m.index);
			e->size = e->csize = 0;
			e->xi = (struct uc2_xinfo){0};
			e->is_dir = 1;
		}
		e->has_tags = !!rc->m.tag;
		copy_dos_name(e->dos_name, rc->m.name);
		e->name_len = 0; // we'll fill the name later
		if (!e->has_tags)
			assemble_name(e);
	}
	return rc->m.tag ? UC2_TaggedEntry : UC2_BareEntry;
}

int uc2_get_tag(struct uc2_context *uc2, struct uc2_entry *e, char **tag, void **data, unsigned *len)
{
	if (uc2->cdir_state != AtTag)
		return UC2_UserFault;

	for (;;) {
		REC(EXTMETA) *x = range_get(&uc2->cdir_range, sizeof *x);
		if (!x)
			return cdir_damaged(uc2);
		unsigned size = get32(x->size);
		u8 *p = range_get(&uc2->cdir_range, size);
		if (!p)
			return cdir_damaged(uc2);
		diag(" \"%.16s\" %u\n", x->tag, size);

		if (e && memcmp(x->tag, TAG_LONGNAME, sizeof TAG_LONGNAME) == 0) {
			u8 *z = memchr(p, 0, size);
			if (!z) z = p + size;
			copy_long_name(e, p, z);
		}

		uc2->cdir_state = x->next ? AtTag : AtEntry;
		if (tag) {
			*tag = (char*)x->tag;
			if (data)
				*data = p;
			if (len)
				*len = size;
		}
		if (!x->next)
			break;
		if (tag)
			return x->next ? UC2_TaggedEntry : UC2_End;
	}
	if (e && e->name_len == 0)
		assemble_name(e);
	return UC2_End;
}

int uc2_finish_cdir(struct uc2_context *uc2, char label[12])
{
	int ret;

	if (uc2->cdir_state != AtTail) {
		ret = uc2_read_cdir(uc2, 0);
		if (ret < 0)
			return ret;
		assert(uc2->cdir_state == AtTail);
	}

	struct {
		REC(XTAIL) xtail;
		u32le aserial;
	} *t = range_get(&uc2->cdir_range, sizeof *t);
	if (!t)
		return UC2_Truncated;

	if (label) {
		u8 *p = memchr(t->xtail.label, 0, 11);
		if (!p) p = t->xtail.label + 11;
		while (p > t->xtail.label && p[-1] == ' ') p--;
		memcpy(label, t->xtail.label, p - t->xtail.label);
		label[p - t->xtail.label] = 0;
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
	uc2->message = "Damaged central directory";
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

/* extract */

int uc2_extract(
	struct uc2_context *uc2,
	struct uc2_xinfo *xi,
	unsigned size,
	int (*write)(void *context, const void *ptr, unsigned len),
	void *context)
{
	int ret;

	if (!uc2->scanned)
		return UC2_BadState;
	ret = resolve_master(uc2, xi->master);
	if (ret < 0)
		return ret;

	struct archive_ctx ar = {.offset = xi->offset, .uc2 = uc2};
	struct reader rd = {.read = archive_read, .context = &ar};
	struct user_write_ctx uw_ctx = {.write = write, .context = context};
	struct writer wr = {.write = user_write, .context = &uw_ctx};
	u16 csum;
	ret = decompressor(uc2, xi->method, &rd, &wr, xi->master, size, &csum);
	diag("decompressor ret:%d csum:%04X (expected:%04X)\n", ret, csum, xi->csum);
	if (ret >= 0 && csum != xi->csum)
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
		delta = 0;
ultra:
		if (delta) diag("Using delta %d\n", delta);
		ret = decompressor_ultra(uc2, master, delta, rd, wr, len, csum);
	} else if (method >= 30 && method <= 39) {
		delta = method - 29;
		goto ultra;
	} else if (method >= 40 && method <= 49) {
		delta = method - 39;
		goto ultra;
	} else if (method >= 21 && method <= 29) {
		delta = 1;
		goto ultra;
	} else if (method == 80) {
		uc2->message = "Turbo compression not implemented";
		ret = UC2_Unimplemented;
	}
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

static unsigned cbuf_have(struct cbuffer *cb)
{
	return (u16)(cb->tail - cb->head);
}

static unsigned cbuf_space(struct cbuffer *cb)
{
	return sizeof cb->data - cbuf_have(cb) - 1;
}

static int cbuf_flush(struct writer *wr, struct cbuffer *cb, struct delta *db, u8 *dbuf)
{
	for (;;) {
		unsigned n = cbuf_have(cb);
		if (!n) return 0;
		unsigned u = 0x10000 - cb->head;
		if (n > u) n = u;
		if (cb->limit < n) {
			diag("cbuf_flush %u < %u\a\n", cb->limit, n);
			n = cb->limit;
		}
		u8 *p = cb->data + cb->head;
		csum_update(&cb->csum, p, n);
		if (dbuf) {
			delta_revert(db, dbuf, p, n);
			p = dbuf;
		}
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

static const u8 vval[NumDeltaCodes][NumDeltaCodes] = {
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
			for (; n > 0; n--)
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
		*p++ = 1 << 24;

	return 0;
}

/* ultra */

struct ultra {
	struct bits bi;
	struct dcinfo dc;
	struct cbuffer cb;

	u32 bd_table[LookupSize];
	u32 l_table[LookupSize];
};

static int decode_ht(struct ultra *ultra);
static int decompress_block(struct ultra *ultra);

enum {
	End,
	More
};

static int decompressor_ultra(struct uc2_context *uc2, unsigned master, unsigned delta, struct reader *rd, struct writer *wr, unsigned limit, u16 *csum)
{
	diag("decompressor_ultra master:%X limit:%u\n", master, limit);

	int ret;

	struct ultra *ultra = u_alloc(uc2, sizeof *ultra);
	if (!ultra)
		return UC2_UserFault;

	ret = use_master(uc2, ultra->cb.data, master);
	if (ret < 0)
		goto ret;
	ultra->cb.limit = limit;
	ultra->cb.head = ultra->cb.tail = ret;
	csum_init(&ultra->cb.csum);

	u8 *dbuf = 0;
	struct delta db;
	if (delta) {
		if (master != SuperMaster) {
			delta_init(&db, delta);
			delta_apply(&db, ultra->cb.data, ultra->cb.tail);
		}
		dbuf = u_alloc(uc2, sizeof ultra->cb.data);
		ret = UC2_UserFault;
		if (!dbuf)
			goto ret;
		delta_init(&db, delta);
	}

	ret = bits_init(&ultra->bi, rd);
	if (ret < 0)
		goto ret2;

	dc_init(&ultra->dc);
	for (;;) {
		ret = decode_ht(ultra);
		if (ret <= 0)
			break;
		for (;;) {
			int o = decompress_block(ultra);
			ret = cbuf_flush(wr, &ultra->cb, &db, dbuf);
			if (ret < 0)
				goto ret2;
			if (o != More)
				break;
		}
	}
	bits_destroy(&ultra->bi);
	if (csum)
		*csum = csum_get(&ultra->cb.csum);
	ret = limit - ultra->cb.limit;
ret2:
	u_free(uc2, dbuf);
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

static int decompress_block(struct ultra *ultra)
{
	const unsigned EOB_MARK = 125*512+1;

	do {
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

			if (dist == EOB_MARK)
				return End;

			unsigned len = c & 0xffff;
			c = c >> 20 & 0xf;
			if (c)
				len += bits_get(&ultra->bi, c);
			assert(cbuf_space(&ultra->cb) >= len);
			do {
				ultra->cb.data[ultra->cb.tail] = ultra->cb.data[(u16)(ultra->cb.tail - dist)];
				ultra->cb.tail++;
			} while (--len);
		}

	} while (cbuf_space(&ultra->cb) >= 35482);

	return More;
}

/* initial */

static int start_read(struct uc2_context *uc2)
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
not_uc2:
		uc2->message = "Not an UC2 archive";
		return UC2_Damaged;
	}

	int ver = get16(h.xhead.versionNeededToExtract);

	diag("Cdir offset:%u made:%d need:%d\n",
	 get32(h.xhead.cdir.offset), get16(h.xhead.versionMadeBy), ver);


	if (ver >= 203) {
		if (ver > 203)
			goto not_uc2;
		uc2->pcp = 1;
	}

	return decompress_cdir(uc2, get32(h.xhead.cdir.offset), get16(h.xhead.fletch));
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
		uc2->cdir_buf = 0;
		uc2->cdir_state = Start;
		uc2->scanned = 0;
		uc2->pcp = 0;
		uc2->masters = 0;
	}
	return uc2;
}

struct uc2_context *uc2_close(struct uc2_context *uc2)
{
	if (uc2) {
		struct master_info *e = uc2->masters;
		while (e) {
			struct master_info *mi = e;
			e = e->next;
			u_free(uc2, mi->data);
			u_free(uc2, mi);
		}
		u_free(uc2, uc2->supermaster);
		u_free(uc2, uc2->cdir_buf);
		uc2 = u_free(uc2, uc2);
	}
	return uc2;
}

const char *uc2_message(struct uc2_context *uc2, int ret)
{
	const char *s = uc2->message;
	uc2->message = 0;
	if (!s) {
		static const char *tab[] = {
			[~UC2_UserFault] = "Callback fault",
			[~UC2_BadState] = "Bad state",
			[~UC2_Damaged] = "Damaged archive",
			[~UC2_Truncated] = "Truncated",
			[~UC2_Unimplemented] = "Unimplemented",
			[~UC2_InternalError] = "Internal error"
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
