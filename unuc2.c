/* UltraCompressor II extraction tool.
   Copyright © Jan Bobrowski 2020
   torinak.com/~jb/unuc2/

   This program is free software: you can redistribute it and modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
*/

#include <limits.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <utime.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <err.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "libunuc2.h"

#include "list.h"
#define endof(T) (T + sizeof T/sizeof*T)
#define STR(S) _STR(S)
#define _STR(S) #S

struct options {
	bool list:1;
	bool all:1;
	bool test:1;
	bool pipe:1;
	bool overwrite:1;
	bool no_dir_meta:1;
	bool no_file_meta:1;
	bool help:1;
	char sep;
	char *archive;
	char *dest;
} opt = {.sep = ' '};

static int my_read(void *ctx, unsigned pos, void *ptr, unsigned len)
{
	if (fseek(ctx, pos, SEEK_SET) < 0)
		err(EXIT_FAILURE, "fseek");
	return fread(ptr, 1, len, ctx);
}

static void *my_alloc(void *ctx, unsigned size)
{
	void *p = malloc(size);
	if (p)
		memset(p, 0, size);
	return p;
}

static void my_free(void *ctx, void *ptr)
{
	free(ptr);
}

static void my_warn(void *ctx, char *f, ...)
{
	fprintf(stderr, "%s: ", opt.archive);
	va_list ap;
	va_start(ap, f);
	vfprintf(stderr, f, ap);
	va_end(ap);
}

static void uc2err(uc2_handle uc2, int err, char *f, ...)
{
	fprintf(stderr, "%s: ", opt.archive);
	if (f) {
		va_list ap;
		va_start(ap, f);
		vfprintf(stderr, f, ap);
		va_end(ap);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", uc2_message(uc2, err));
}

static struct uc2_io io = {
	.read = my_read,
	.alloc = my_alloc,
	.free = my_free,
	.warn = my_warn
};

LIST(files);
LIST(dirs);

struct node {
	struct list by_type;
	struct list on_dir;
	struct list on_sel;
	struct list children; // head
	struct node *parent;
	unsigned version;
	bool visit:1;
	bool marked:1;
	struct uc2_entry entry;
};

struct node root = {
	.entry = {.is_dir = 1},
	.children = {.prev = &root.children, .next = &root.children}
};

static void new_entry(struct node *ne)
{
	struct uc2_entry *e = &ne->entry;
	struct node *dir = &root;
	if (e->dirid) {
		for (struct list *l = dirs.next;; l = l->next) {
			if (l == &dirs) {
				warnx("Missing dir of %s\n", e->name);
				dir = &root;
				break;
			}
			dir = list_item(l, struct node, by_type);
			if (dir->entry.id == ne->entry.dirid)
				break;
		}
	}
	ne->parent = dir;
	struct list *at = 0;
	if (!e->is_dir) {
		for (struct list *l = dir->children.next; l != &dir->children; l = l->next) {
			struct node *fe = list_item(l, struct node, on_dir);
			if (fe->entry.name_len == ne->entry.name_len
			 && memcmp(fe->entry.name, ne->entry.name, ne->entry.name_len) == 0) {
				fe->version++;
				if (!at) at = &fe->on_dir;
			}
		}
	}
	list_add_end(at ? at : &dir->children, &ne->on_dir);
	list_add_end(e->is_dir ? &dirs : &files, &ne->by_type);
	list_init(&ne->children);
	list_init(&ne->on_sel);
	ne->version = 0;
	ne->visit = false;
	ne->marked = false;
}

static void print_dir_path(struct node *ne)
{
	ne = ne->parent;
	if (!ne) {
		printf("?/");
		return;
	}
	if (ne->entry.dirid)
		print_dir_path(ne);
	printf("%s/", ne->entry.name);
}

static void print_time(unsigned t)
{
	int w = 0;
	if (t) {
		w += printf("%04u-%02u-%02u %02u:%02u", 1980 + (t>>25), t>>21&15, t>>16&31, t>>11&31, t>>5&63);
		int s = t<<1&62;
		if (s < 60)
			w += printf(":%02u", s);
	}
	if (opt.sep == ' ')
		printf("%*s", 19 - w, "");
}

static void mark(struct node *node)
{
	if (node->marked)
		return;
	node->marked = true;
	if (node->entry.is_dir) {
		node->visit = true;
		for (struct list *l = node->children.next; l != &node->children; l = l->next) {
			struct node *ne = list_item(l, struct node, on_dir);
			if (opt.all || ne->version == 0)
				mark(ne);
		}
	}
	while ((node = node->parent) && !node->visit)
		node->visit = true;
}

static void match_pattern(char *p)
{
	enum {
		IntermediateDirs,
		FilesAndSpecificDirs,
		Dirs
	};
	struct list selected;
	list_init(&selected);
	list_add(&selected, &root.on_sel);
	unsigned version = 0;
	for (;;) {
		char *q = strchr(p, '/');
		int mode = IntermediateDirs;
		if (!q) {
			mode = FilesAndSpecificDirs;
			q = strchr(p, 0);
			if (q - p > 2 && isdigit(q[-1])) {
				do q--; while (q - p > 2 && isdigit(q[-1]));
				if (q[-1] == ';') {
					q[-1] = 0;
					version = atoi(q);
				}
			}
		} else {
			*q = 0;
			if (!q[1])
				mode = Dirs;
		}
		struct list sentinel;
		list_add_end(&selected, &sentinel);
		while (selected.next != &sentinel) {
			struct node *dir = list_get_item(&selected, struct node, on_sel);
			for (struct list *l = dir->children.next; l != &dir->children; l = l->next) {
				struct node *ne = list_item(l, struct node, on_dir);
				if (!ne->entry.is_dir) {
					if (mode == FilesAndSpecificDirs
					 && ne->version == version && fnmatch(p, ne->entry.name, 0) == 0)
						mark(ne);
					continue;
				}
				if (mode == IntermediateDirs) {
					list_del(&ne->on_sel);
					if (fnmatch(p, ne->entry.name, 0) == 0)
						list_add_end(&selected, &ne->on_sel);
					continue;
				}
				if (strcmp(ne->entry.name, p) == 0
				 || (mode == Dirs && fnmatch(p, ne->entry.name, 0) == 0))
					mark(ne);
			}
		}
		list_del(&sentinel);
		if (mode != IntermediateDirs)
			break;
		p = q + 1;
	}
}

enum cause {
	VisitFile,
	EnterDir,
	LeaveDir
};

static int visit_selected(struct node *dir, bool (*cb)(struct node *, void *ctx, enum cause), void *ctx)
{
	int r = 1;
	for (struct list *l=dir->children.next; l!=&dir->children; l=l->next) {
		struct node *ne = list_item(l, struct node, on_dir);
		if (ne->entry.is_dir)
			continue;
		if (!ne->visit && !ne->marked)
			continue;
		r = cb(ne, ctx, VisitFile);
		if (r <= 0)
			break;
	}
	if (!r)
		return r;
	for (struct list *l=dir->children.next; l!=&dir->children; l=l->next) {
		struct node *ne = list_item(l, struct node, on_dir);
		if (!ne->entry.is_dir)
			continue;
		if (!ne->visit && !ne->marked)
			continue;
		r = cb(ne, ctx, EnterDir);
		if (r <= 0)
			break;
		r = visit_selected(ne, cb, ctx);
		if (r <= 0)
			break;
		if (!ne->marked)
			continue;
		r = cb(ne, ctx, LeaveDir);
		if (r <= 0)
			break;
	}
	return r;
}

static void print_entry(struct node *ne, int size_w)
{
	struct uc2_entry *e = &ne->entry;
	char t[] = "adlshr";
	unsigned a = e->attr;
	for (char *p = t; *p; p++, a<<=1)
		if (!(a & 0x20))
			*p = '-';
	printf("%s", t);
	putchar(opt.sep);
	print_time(e->dos_time);
	putchar(opt.sep);
	if (opt.sep == ' ') {
		if (e->is_dir) printf("%*s", size_w, "");
		else printf("%*u", size_w, e->size);
	} else
		if (!e->is_dir) printf("%u", e->size);
	putchar(opt.sep);
	if (e->dirid)
		print_dir_path(ne);
	printf("%s", e->name);
	if (e->is_dir && opt.sep == ' ')
		putchar('/');
	if (ne->version) {
		putchar(opt.sep == ' ' ? ';' : opt.sep);
		printf("%u", ne->version);
	}
	putchar('\n');
}

static bool max_size_cb(struct node *ne, void *ctx, enum cause cause)
{
	if (cause == VisitFile) {
		unsigned *max = ctx;
		if (*max < ne->entry.size)
			*max = ne->entry.size;
	}
	return true;
}

static bool print_entry_cb(struct node *ne, void *ctx, enum cause cause)
{
	if (cause == VisitFile) {
		int size_w = *(int*)ctx;
		print_entry(ne, size_w);
	}
	return true;
}

static void set_attrs(char *path, struct node *ne)
{
	unsigned dt = ne->entry.dos_time;
	time_t t = 0;
	if (dt) {
		struct tm tm = {
			.tm_year = 80 + (dt>>25),
			.tm_mon = (dt>>21&15) - 1,
			.tm_mday = dt>>16&31,
			.tm_hour = dt>>11&31,
			.tm_min = dt>>5&63,
			.tm_sec = dt<<1&62,
			.tm_isdst = -1
		};
		t = mktime(&tm);
	}
	if (t != (time_t)-1) {
		struct utimbuf ut = {.actime = t, .modtime = t};
		(void)utime(path, &ut);
	}
	if (ne->entry.attr & UC2_Attr_R)
		(void)chmod(path, 0444);
}

static int write_file(void *context, unsigned pos, const void *ptr, unsigned len)
{
	if (context)
		if (fwrite(ptr, 1, len, context) < len)
			return -1;
	return 0;
}

struct path {
	uc2_handle uc2;
	char *ptr;
	char buffer[PATH_MAX];
};

static bool pipe_cb(struct node *ne, void *ctx, enum cause cause)
{
	if (cause == VisitFile) {
		uc2_handle uc2 = ctx;
		struct uc2_entry *e = &ne->entry;
		if (opt.test)
			printf("Testing %s %u bytes\n", e->name, e->size);
		int ret = uc2_extract(uc2, e, write_file, opt.test ? 0 : stdout);
		if (ret < 0)
			uc2err(uc2, ret, "(%s)", e->name);
	}
	return true;
}

static bool extract_cb(struct node *ne, void *ctx, enum cause cause)
{
	struct path *path = ctx;
	struct uc2_entry *e = &ne->entry;
	unsigned l = e->name_len;

	switch (cause) {
	case VisitFile:
	case EnterDir:;
		char *p = path->ptr + l;
		if (p + 1 >= endof(path->buffer))
			errx(EXIT_FAILURE, "Path too long");
		memcpy(path->ptr, e->name, l);

		if (cause == VisitFile) {
			*p = 0;
			if (!opt.overwrite) {
				struct stat st;
				if (stat(path->buffer, &st) >= 0) {
					errno = EEXIST;
					warn("%s", path->buffer);
					break;
				}
			} else
				(void) unlink(path->buffer);

			FILE *f = fopen(path->buffer, "wb");
			if (!f)
				err(EXIT_FAILURE, "%s", path->buffer);
			int ret = uc2_extract(path->uc2, e, write_file, f);
			if (ret < 0)
				uc2err(path->uc2, ret, "(%s)", e->name);
			fclose(f);
			if (!opt.no_file_meta)
				set_attrs(path->buffer, ne);
			break;
		}
		*p++ = '/';
		if (p == endof(path->buffer))
			errx(EXIT_FAILURE, "Path too long");
		path->ptr = p;
		*p = 0;
		int r = mkdir(path->buffer, 0777);
		if (r < 0) {
			if (errno != EEXIST)
				err(EXIT_FAILURE, "mkdir %s", path->buffer);
			ne->marked = false; // skip meta setting
		}
		break;

	case LeaveDir:
		assert(ne->entry.is_dir);
		if (!opt.no_dir_meta) {
			*path->ptr = 0;
			set_attrs(path->buffer, ne);
		}
		path->ptr -= l + 1;
	}
	return true;
}

int main(int argc, char *argv[])
{
	if (argc == 1)
		goto usage;

	for (;;) {
		int o = getopt(argc, argv, "xlatfd:C:cpDTh?");
		if (o == -1)
			break;
		switch (o) {
		case 'x':
			opt.list = opt.test = false;
			break;
		case 'l':
			opt.list = true;
			break;
		case 'a':
			opt.all = true;
			break;
		case 't':
			opt.test = true;
			break;
		case 'f':
			opt.overwrite = true;
			break;
		case 'd':
			opt.dest = *optarg ? optarg : 0;
			break;
		case 'C':
			if (chdir(optarg) < 0)
				err(EXIT_FAILURE, "%s", optarg);
			break;
		case 'c':
		case 'p':
			opt.pipe = true;
			break;
		case 'D':
			opt.no_file_meta = opt.no_dir_meta;
			opt.no_dir_meta = true;
			break;
		case 'T':
			opt.sep = '\t';
			break;
		case '?':
			if (optopt)
				return EXIT_FAILURE;
		case 'h':
			opt.help = true;
			printf("UnUC2 " STR(VERSION) " by Jan Bobrowski\n\n");
usage:
			printf(
				"unuc2 [-afpDT] [-d destination] archive.uc2 [files]...\n"
				"unuc2 -l [-aT] archive.uc2 [files]...\n"
				"unuc2 -t [-a] archive.uc2 [files]...\n"
			);
			if (!opt.help)
				printf("unuc2 -h\n");
			else
				printf(
					" -l      list\n"
					" -t      test\n"
					" -a      all versions of files\n"
					" -d path destination to extract to\n"
					" -f      overwrite\n"
					" -p      to stdout\n"
					" -D      do not set time and permissions of dirs (also files: -DD)\n"
					" -T      tab separated\n"
					"\nhttp://torinak.com/~jb/unuc2/\n"
				);
			return opt.help ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}

	if (argc == optind)
		errx(EXIT_FAILURE, "Archive not given");
	opt.archive = argv[optind++];

	FILE *f = fopen(opt.archive, "rb");
	if (!f) err(EXIT_FAILURE, "%s", opt.archive);

	uc2_handle uc2 = uc2_open(&io, f);

	for (;;) {
		struct node *ne = malloc(sizeof *ne);
		if (!ne) err(EXIT_FAILURE, "malloc");

		int ret = uc2_scan(uc2, &ne->entry, 0);
		if (ret <= 0) {
			free(ne);
			if (ret == 0)
				break;
			uc2err(uc2, ret, 0);
			return EXIT_FAILURE;
		}

		new_entry(ne);
	}

	if (optind == argc) {
		mark(&root);
	} else do {
		match_pattern(argv[optind++]);
	} while (optind < argc);

	if (opt.list) {
		unsigned max = 0;
		int size_w = 0;
		if (opt.sep == ' ') {
			visit_selected(&root, max_size_cb, &max);
			size_w = snprintf(0, 0, "%u", max);
		}
		visit_selected(&root, print_entry_cb, &size_w);
		if (opt.sep == ' ') {
			const char *s = uc2_label(uc2);
			if (s) printf("Label: %s\n", s);
		}
	}

	if (opt.pipe || opt.test) {
		visit_selected(&root, pipe_cb, uc2);
	} else if (!opt.list) {
		struct path path = {.uc2 = uc2};
		char *p = path.buffer;
		if (opt.dest) {
			int n = strlen(opt.dest);
			assert(n);
			if (opt.dest[n-1] == '/')
				n--;
			if (n >= sizeof path.buffer)
				errx(EXIT_FAILURE, "Destination too long");
			memcpy(p, opt.dest, n);
			p += n;
			*p++ = '/';
		}
		path.ptr = p;
		visit_selected(&root, extract_cb, &path);
	}

	uc2_close(uc2);
	return EXIT_SUCCESS;
}