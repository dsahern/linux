// SPDX-License-Identifier: LGPL-2.1
/*
 * trace/beauty/ioctl.c
 *
 *  Copyright (C) 2017, Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
 */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/string.h>
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "trace/beauty/beauty.h"
#include "rblist.h"

/*
 * FIXME: to support all arches we have to improve this, for
 * now, to build on older systems without things like TIOCGEXCL,
 * get it directly from our copy.
 *
 * Right now only x86 is being supported for beautifying ioctl args
 * in 'perf trace', see tools/perf/trace/beauty/Build and builtin-trace.c
 */
#include <uapi/asm-generic/ioctls.h>

static size_t ioctl__scnprintf_tty_cmd(int nr, int dir, char *bf, size_t size)
{
	static const char *ioctl_tty_cmd[] = {
	[_IOC_NR(TCGETS)] = "TCGETS", "TCSETS", "TCSETSW", "TCSETSF", "TCGETA", "TCSETA", "TCSETAW",
	"TCSETAF", "TCSBRK", "TCXONC", "TCFLSH", "TIOCEXCL", "TIOCNXCL", "TIOCSCTTY",
	"TIOCGPGRP", "TIOCSPGRP", "TIOCOUTQ", "TIOCSTI", "TIOCGWINSZ", "TIOCSWINSZ",
	"TIOCMGET", "TIOCMBIS", "TIOCMBIC", "TIOCMSET", "TIOCGSOFTCAR", "TIOCSSOFTCAR",
	"FIONREAD", "TIOCLINUX", "TIOCCONS", "TIOCGSERIAL", "TIOCSSERIAL", "TIOCPKT",
	"FIONBIO", "TIOCNOTTY", "TIOCSETD", "TIOCGETD", "TCSBRKP",
	[_IOC_NR(TIOCSBRK)] = "TIOCSBRK", "TIOCCBRK", "TIOCGSID", "TCGETS2", "TCSETS2",
	"TCSETSW2", "TCSETSF2", "TIOCGRS48", "TIOCSRS485", "TIOCGPTN", "TIOCSPTLCK",
	"TIOCGDEV", "TCSETX", "TCSETXF", "TCSETXW", "TIOCSIG", "TIOCVHANGUP", "TIOCGPKT",
	"TIOCGPTLCK", [_IOC_NR(TIOCGEXCL)] = "TIOCGEXCL", "TIOCGPTPEER",
	"TIOCGISO7816", "TIOCSISO7816",
	[_IOC_NR(FIONCLEX)] = "FIONCLEX", "FIOCLEX", "FIOASYNC", "TIOCSERCONFIG",
	"TIOCSERGWILD", "TIOCSERSWILD", "TIOCGLCKTRMIOS", "TIOCSLCKTRMIOS",
	"TIOCSERGSTRUCT", "TIOCSERGETLSR", "TIOCSERGETMULTI", "TIOCSERSETMULTI",
	"TIOCMIWAIT", "TIOCGICOUNT", };
	static DEFINE_STRARRAY(ioctl_tty_cmd, "");

	if (nr < strarray__ioctl_tty_cmd.nr_entries && strarray__ioctl_tty_cmd.entries[nr] != NULL)
		return scnprintf(bf, size, "%s", strarray__ioctl_tty_cmd.entries[nr]);

	return scnprintf(bf, size, "(%#x, %#x, %#x)", 'T', nr, dir);
}

static size_t ioctl__scnprintf_drm_cmd(int nr, int dir, char *bf, size_t size)
{
#include "trace/beauty/generated/ioctl/drm_ioctl_array.c"
	static DEFINE_STRARRAY(drm_ioctl_cmds, "");

	if (nr < strarray__drm_ioctl_cmds.nr_entries && strarray__drm_ioctl_cmds.entries[nr] != NULL)
		return scnprintf(bf, size, "DRM_%s", strarray__drm_ioctl_cmds.entries[nr]);

	return scnprintf(bf, size, "(%#x, %#x, %#x)", 'd', nr, dir);
}

static size_t ioctl__scnprintf_sndrv_pcm_cmd(int nr, int dir, char *bf, size_t size)
{
#include "trace/beauty/generated/ioctl/sndrv_pcm_ioctl_array.c"
	static DEFINE_STRARRAY(sndrv_pcm_ioctl_cmds, "");

	if (nr < strarray__sndrv_pcm_ioctl_cmds.nr_entries && strarray__sndrv_pcm_ioctl_cmds.entries[nr] != NULL)
		return scnprintf(bf, size, "SNDRV_PCM_%s", strarray__sndrv_pcm_ioctl_cmds.entries[nr]);

	return scnprintf(bf, size, "(%#x, %#x, %#x)", 'A', nr, dir);
}

static size_t ioctl__scnprintf_sndrv_ctl_cmd(int nr, int dir, char *bf, size_t size)
{
#include "trace/beauty/generated/ioctl/sndrv_ctl_ioctl_array.c"
	static DEFINE_STRARRAY(sndrv_ctl_ioctl_cmds, "");

	if (nr < strarray__sndrv_ctl_ioctl_cmds.nr_entries && strarray__sndrv_ctl_ioctl_cmds.entries[nr] != NULL)
		return scnprintf(bf, size, "SNDRV_CTL_%s", strarray__sndrv_ctl_ioctl_cmds.entries[nr]);

	return scnprintf(bf, size, "(%#x, %#x, %#x)", 'U', nr, dir);
}

static size_t ioctl__scnprintf_kvm_cmd(int nr, int dir, char *bf, size_t size)
{
#include "trace/beauty/generated/ioctl/kvm_ioctl_array.c"
	static DEFINE_STRARRAY(kvm_ioctl_cmds, "");

	if (nr < strarray__kvm_ioctl_cmds.nr_entries && strarray__kvm_ioctl_cmds.entries[nr] != NULL)
		return scnprintf(bf, size, "KVM_%s", strarray__kvm_ioctl_cmds.entries[nr]);

	return scnprintf(bf, size, "(%#x, %#x, %#x)", 0xAE, nr, dir);
}

static size_t ioctl__scnprintf_vhost_virtio_cmd(int nr, int dir, char *bf, size_t size)
{
#include "trace/beauty/generated/ioctl/vhost_virtio_ioctl_array.c"
	static DEFINE_STRARRAY(vhost_virtio_ioctl_cmds, "");
	static DEFINE_STRARRAY(vhost_virtio_ioctl_read_cmds, "");
	struct strarray *s = (dir & _IOC_READ) ? &strarray__vhost_virtio_ioctl_read_cmds : &strarray__vhost_virtio_ioctl_cmds;

	if (nr < s->nr_entries && s->entries[nr] != NULL)
		return scnprintf(bf, size, "VHOST_%s", s->entries[nr]);

	return scnprintf(bf, size, "(%#x, %#x, %#x)", 0xAF, nr, dir);
}

static size_t ioctl__scnprintf_perf_cmd(int nr, int dir, char *bf, size_t size)
{
#include "trace/beauty/generated/ioctl/perf_ioctl_array.c"
	static DEFINE_STRARRAY(perf_ioctl_cmds, "");

	if (nr < strarray__perf_ioctl_cmds.nr_entries && strarray__perf_ioctl_cmds.entries[nr] != NULL)
		return scnprintf(bf, size, "PERF_%s", strarray__perf_ioctl_cmds.entries[nr]);

	return scnprintf(bf, size, "(%#x, %#x, %#x)", 0xAE, nr, dir);
}

static size_t ioctl__scnprintf_usbdevfs_cmd(int nr, int dir, char *bf, size_t size)
{
#include "trace/beauty/generated/ioctl/usbdevfs_ioctl_array.c"
	static DEFINE_STRARRAY(usbdevfs_ioctl_cmds, "");

	if (nr < strarray__usbdevfs_ioctl_cmds.nr_entries && strarray__usbdevfs_ioctl_cmds.entries[nr] != NULL)
		return scnprintf(bf, size, "USBDEVFS_%s", strarray__usbdevfs_ioctl_cmds.entries[nr]);

	return scnprintf(bf, size, "(%c, %#x, %#x)", 'U', nr, dir);
}

static size_t ioctl__scnprintf_cmd(unsigned long cmd, char *bf, size_t size, bool show_prefix)
{
	const char *prefix = "_IOC_";
	int dir	 = _IOC_DIR(cmd),
	    type = _IOC_TYPE(cmd),
	    nr	 = _IOC_NR(cmd),
	    sz	 = _IOC_SIZE(cmd);
	int printed = 0;
	static const struct ioctl_type {
		int	type;
		size_t	(*scnprintf)(int nr, int dir, char *bf, size_t size);
	} ioctl_types[] = { /* Must be ordered by type */
			      { .type	= '$', .scnprintf = ioctl__scnprintf_perf_cmd, },
		['A' - '$'] = { .type	= 'A', .scnprintf = ioctl__scnprintf_sndrv_pcm_cmd, },
		['T' - '$'] = { .type	= 'T', .scnprintf = ioctl__scnprintf_tty_cmd, },
		['U' - '$'] = { .type	= 'U', .scnprintf = ioctl__scnprintf_sndrv_ctl_cmd, },
		['d' - '$'] = { .type	= 'd', .scnprintf = ioctl__scnprintf_drm_cmd, },
		[0xAE - '$'] = { .type	= 0xAE, .scnprintf = ioctl__scnprintf_kvm_cmd, },
		[0xAF - '$'] = { .type	= 0xAF, .scnprintf = ioctl__scnprintf_vhost_virtio_cmd, },
	};
	const int nr_types = ARRAY_SIZE(ioctl_types);

	if (type >= ioctl_types[0].type && type <= ioctl_types[nr_types - 1].type) {
		const int index = type - ioctl_types[0].type;

		if (ioctl_types[index].scnprintf != NULL)
			return ioctl_types[index].scnprintf(nr, dir, bf, size);
	}

	printed += scnprintf(bf + printed, size - printed, "%c", '(');

	if (dir == _IOC_NONE) {
		printed += scnprintf(bf + printed, size - printed, "%s%s", show_prefix ? prefix : "", "NONE");
	} else {
		if (dir & _IOC_READ)
			printed += scnprintf(bf + printed, size - printed, "%s%s", show_prefix ? prefix : "", "READ");
		if (dir & _IOC_WRITE) {
			printed += scnprintf(bf + printed, size - printed, "%s%s%s", dir & _IOC_READ ? "|" : "",
					     show_prefix ? prefix : "",  "WRITE");
		}
	}

	return printed + scnprintf(bf + printed, size - printed, ", %#x, %#x, %#x)", type, nr, sz);
}

#ifndef USB_DEVICE_MAJOR
#define USB_DEVICE_MAJOR 189
#endif // USB_DEVICE_MAJOR

size_t syscall_arg__scnprintf_ioctl_cmd(char *bf, size_t size, struct syscall_arg *arg)
{
	unsigned long cmd = arg->val;
	int fd = syscall_arg__val(arg, 0);
	struct file *file = thread__files_entry(arg->thread, fd);

	if (file != NULL) {
		if (file->dev_maj == USB_DEVICE_MAJOR)
			return ioctl__scnprintf_usbdevfs_cmd(_IOC_NR(cmd), _IOC_DIR(cmd), bf, size);
	}

	return ioctl__scnprintf_cmd(cmd, bf, size, arg->show_string_prefix);
}

struct ioctl_node {
	struct rb_node rb_node;
	unsigned long op;
	char *name;
};

struct ioctl_list {
	struct rblist rb_list;
	struct list_head list;
	char *fname;
};

static struct rb_node *ioctl__node_new(struct rblist *rblist __maybe_unused,
				       const void *entry)
{
	const struct ioctl_node *e = entry;
	struct ioctl_node *inode;

	inode = calloc(1, sizeof(*inode));
	if (inode == NULL)
		return NULL;

	inode->op = e->op;
	inode->name = strdup(e->name);
	if (!inode->name) {
		free(inode);
		return NULL;
	}

	return &inode->rb_node;
}

static void ioctl__node_delete(struct rblist *rblisti __maybe_unused,
			       struct rb_node *rb_node)
{
	struct ioctl_node *inode = container_of(rb_node, struct ioctl_node, rb_node);

	free(inode->name);
	free(inode);
}

static int ioctl__node_cmp(struct rb_node *rb_node, const void *entry)
{
	const struct ioctl_node *e = entry;
	struct ioctl_node *inode = container_of(rb_node, struct ioctl_node, rb_node);

	if (inode->op < e->op)
		return -1;
	if (inode->op > e->op)
		return 1;
	return 0;
}

static struct ioctl_node *ioctl_find_op(struct ioctl_list *ilist, unsigned long op)
{
	struct ioctl_node inode = { .op = op };
	struct rb_node *rb_node;

	rb_node = rblist__find(&ilist->rb_list, &inode);
	if (rb_node)
		return container_of(rb_node, struct ioctl_node, rb_node);

	return NULL;
}

static void ioctl__list_delete(struct ioctl_list *ilist)
{
	list_del(&ilist->list);

	rblist__exit(&ilist->rb_list);
	free(ilist->fname);
	free(ilist);
}

static struct ioctl_list *ioctl__list_new(const char *fname)
{
	struct ioctl_list *ilist;

	ilist = calloc(1, sizeof(*ilist));
	if (ilist) {
		ilist->fname = strdup(fname);
		if (!ilist->fname) {
			free(ilist);
			ilist = NULL;
		}

		rblist__init(&ilist->rb_list);
		ilist->rb_list.node_cmp = ioctl__node_cmp;
		ilist->rb_list.node_new = ioctl__node_new;
		ilist->rb_list.node_delete = ioctl__node_delete;

		INIT_LIST_HEAD(&ilist->list);
	}

	return ilist;
}

#define IOCTL_FILE_STR "file: "

static int load_file(const char *fname, struct ioctl_list **pilist)
{
	struct ioctl_list *ilist = NULL;
	unsigned int lineno = 0;
	char buf[128], *p;
	int rc = 0;
	FILE *fp;

	*pilist = NULL;

	fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open %s: %s: %d\n", fname, strerror(errno), errno);
		return -1;
	}

	/* first line should be "# ioctl map" */
	if (fgets(buf, sizeof(buf), fp) == NULL ||
	    strncmp(buf, "# ioctl map", 11)) {
		fclose(fp);
		return 0;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		char *nl;

		lineno++;

		nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';

		p = strim(buf);
		if (strlen(p) == 0 || *p == '#')
			continue;

		if (!ilist) {
			if (strncmp(p, IOCTL_FILE_STR, sizeof(IOCTL_FILE_STR) - 1))
				continue;

			p += sizeof(IOCTL_FILE_STR) - 1;
			p = skip_spaces(p);

			ilist = ioctl__list_new(p);
			if (!ilist) {
				rc = -ENOMEM;
				break;
			}
		} else {
			char *sp = strchr(p, ' '), *endp = NULL;
			struct ioctl_node node;
			int err;

			if (!sp)
				continue;

			node.name = strim(p);

			*sp = 0;
			sp++;
			node.op = strtoul(sp, &endp, 0);
			if (endp && *endp != '\0') {
				rc = -EINVAL;
				fprintf(stderr,
					"Invalid entry at line %d; endp %s\n",
					lineno, endp);
				break;
			}

			err = rblist__add_node(&ilist->rb_list, &node);
			if (err) {
				rc = err;
				fprintf(stderr,
					"Failed to add entry for line %d\n",
					lineno);
				break;
			}
		}
	}

	fclose(fp);

	if (rc) {
		ioctl__list_delete(ilist);
		ilist = NULL;
	} else if (!ilist)
		rc = -EINVAL;

	*pilist = ilist;
	return rc;
}

static LIST_HEAD(ioctl_list);

void syscall_arg__ioctl_cmd_decode_fini(void)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &ioctl_list) {
		struct ioctl_list *ilist;

		ilist = container_of(pos, struct ioctl_list, list);
		ioctl__list_delete(ilist);
	}
}

int syscall_arg__ioctl_cmd_decode_init(const char *dirname)
{
	struct ioctl_list *ilist;
	struct dirent *de;
	int err;
	DIR *d;

	d = opendir(dirname);
	if (d == NULL) {
		fprintf(stderr, "Failed to open directory\n");
		return -errno;
	}

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];

		if (de->d_type != DT_REG && de->d_type != DT_LNK)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirname, de->d_name);

		err = load_file(path, &ilist);
		if (err)
			break;

		if (ilist)
			list_add(&ilist->list, &ioctl_list);
	}

	closedir(d);

	return 0;
}

static struct ioctl_list *ioctl_find_file(const char *fname)
{
	struct list_head *pos;

	list_for_each(pos, &ioctl_list) {
		struct ioctl_list *ilist;

		ilist = container_of(pos, struct ioctl_list, list);
		if (strcmp(ilist->fname, fname) == 0)
			return ilist;
	}

	return NULL;
}

const char *syscall_arg__ioctl_cmd_lookup(const char *fname, unsigned long op)
{
	static struct ioctl_list *ilist = NULL;
	struct ioctl_node *inode;

	if (!ilist || strcmp(ilist->fname, fname))
		ilist = ioctl_find_file(fname);

	if (ilist) {
		inode = ioctl_find_op(ilist, op);
		if (inode)
			return inode->name;
	}

	return NULL;
}

