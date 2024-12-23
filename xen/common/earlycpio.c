/* ----------------------------------------------------------------------- *
 *
 *   Copyright 2012 Intel Corporation; author H. Peter Anvin
 *
 *   This file is part of the Linux kernel, and is made available
 *   under the terms of the GNU General Public License version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

/*
 * earlycpio.c
 *
 * Find a specific cpio member; must precede any compressed content.
 * This is used to locate data items in the initramfs used by the
 * kernel itself during early boot (before the main initramfs is
 * decompressed.)  It is the responsibility of the initramfs creator
 * to ensure that these items are uncompressed at the head of the
 * blob.  Depending on the boot loader or package tool that may be a
 * separate file or part of the same file.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/string.h>
#include <xen/earlycpio.h>

#define ALIGN(x, a) ((x + (a) - 1) & ~((a) - 1))
#define PTR_ALIGN(p, a)         ((typeof(p))ALIGN((unsigned long)(p), (a)))

enum cpio_fields {
	C_MAGIC,
	C_INO,
	C_MODE,
	C_UID,
	C_GID,
	C_NLINK,
	C_MTIME,
	C_FILESIZE,
	C_MAJ,
	C_MIN,
	C_RMAJ,
	C_RMIN,
	C_NAMESIZE,
	C_CHKSUM,
	C_NFIELDS
};

/**
 * cpio_data find_cpio_data - Search for files in an uncompressed cpio
 * @path:       The directory to search for, including a slash at the end
 * @data:       Pointer to the the cpio archive or a header inside
 * @len:        Remaining length of the cpio based on data pointer
 *
 * @return:     struct cpio_data containing the address, length and
 *              filename (with the directory path cut off) of the found file.
 *              If you search for a filename and not for files in a directory,
 *              pass the absolute path of the filename in the cpio and make sure
 *              the match returned an empty filename string.
 */

struct cpio_data __init find_cpio_data(const char *path, void *data, size_t len)
{
	const size_t cpio_header_len = 8*C_NFIELDS - 2;
	struct cpio_data cd = { NULL, 0, "" };
	const char *p, *dptr, *nptr;
	unsigned int ch[C_NFIELDS], *chp, v;
	unsigned char c, x;
	size_t mypathsize = strlen(path);
	int i, j;

	p = data;

	while (len > cpio_header_len) {
		if (!*p) {
			/* All cpio headers need to be 4-byte aligned */
			p += 4;
			len -= 4;
			continue;
		}

		j = 6;		/* The magic field is only 6 characters */
		chp = ch;
		for (i = C_NFIELDS; i; i--) {
			v = 0;
			while (j--) {
				v <<= 4;
				c = *p++;

				x = c - '0';
				if (x < 10) {
					v += x;
					continue;
				}

				x = (c | 0x20) - 'a';
				if (x < 6) {
					v += x + 10;
					continue;
				}

				goto quit; /* Invalid hexadecimal */
			}
			*chp++ = v;
			j = 8;	/* All other fields are 8 characters */
		}

		if ((ch[C_MAGIC] - 0x070701) > 1)
			goto quit; /* Invalid magic */

		len -= cpio_header_len;

		dptr = PTR_ALIGN(p + ch[C_NAMESIZE], 4);
		nptr = PTR_ALIGN(dptr + ch[C_FILESIZE], 4);

		if (nptr > p + len || dptr < p || nptr < dptr)
			goto quit; /* Buffer overrun */

		if ((ch[C_MODE] & 0170000) == 0100000 &&
		    ch[C_NAMESIZE] >= mypathsize &&
		    !memcmp(p, path, mypathsize)) {
			if (ch[C_NAMESIZE] - mypathsize >= MAX_CPIO_FILE_NAME) {
				printk(
				"File %s exceeding MAX_CPIO_FILE_NAME [%d]\n",
				p, MAX_CPIO_FILE_NAME);
			}
			strlcpy(cd.name, p + mypathsize, MAX_CPIO_FILE_NAME);

			cd.data = (void *)dptr;
			cd.size = ch[C_FILESIZE];
			return cd; /* Found it! */
		}
		len -= (nptr - p);
		p = nptr;
	}

quit:
	return cd;
}

