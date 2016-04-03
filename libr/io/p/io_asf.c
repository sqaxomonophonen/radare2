/* radare - LGPL3 - Copyright 2016 - sqaxomonophonen

ASF (Amiga State File). see bin_asf.c

*/


#include "r_io.h"
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_hash.h>
#include "../bin/format/asf/asf.h"

struct rom_list {
	ut32 crc32;
	ut64 size;
	ut8* data;
	struct rom_list* next;
};

static struct rom_list* rom_list_new (RMmap *mm, struct asf_rom_header *header)
{
	struct rom_list* res;

	res = R_NEW0 (struct rom_list);
	if (res == NULL) {
		return NULL;
	}

	res->crc32 = header->crc32;
	res->size = mm->len;
	res->data = malloc (mm->len);
	if (res->data == NULL) {
		return NULL;
	}

	memcpy (res->data, mm->buf, mm->len);

	return res;
}

static int handle_rom(struct r_bin_asf_hunk *hunk, struct rom_list **roms) {
	struct asf_rom_header header;
	RMmap *mm;
	RMmap *romm;
	ut8 *s;
	struct rom_list* new_entry = NULL;
	char *amiga_roms;
	RList *dlist;
	RListIter *iter;
	char *basename;
	char *path;
	ut32 crc32;

	if (!asf_rom_header_unpack (hunk, &header)) return 0;

	// skip ahead to path
	s = hunk->data + sizeof(header);
	s += strlen ((char*)s) + 1;
	mm = r_file_mmap ((char*)s, false, 0);

	if (mm != NULL) {
		new_entry = rom_list_new (mm, &header);
		r_file_mmap_free (mm);
	} else {
		amiga_roms = r_sys_getenv ("AMIGA_ROMS");
		if (amiga_roms != NULL) {
			dlist = r_sys_dir (amiga_roms);
			if (dlist != NULL) {
				r_list_foreach (dlist, iter, basename) {
					if (strcasecmp (basename + strlen(basename) - 4, ".rom") != 0) continue;
					path = r_str_newf ("%s/%s", amiga_roms, basename);
					romm = r_file_mmap (path, false, 0);
					if (romm == NULL) continue;

					crc32 = r_hash_crc32 (romm->buf, header.size);
					if (crc32 == header.crc32) {
						new_entry = rom_list_new (romm, &header);
						r_file_mmap_free (romm);
						break;
					}

					r_file_mmap_free (romm);
				}
				r_list_purge (dlist);
				free (dlist);
			}
		}
	}

	if (new_entry != NULL) {
		new_entry->next = *roms;
		*roms = new_entry;
		return 1;
	} else {
		eprintf ("failed to locate ASF ROM file \"%s\" (hint: you can point the AMIGA_ROMS env var to your rom directory)\n", s);
		return 0;
	}
}

static struct rom_list* get_rom(struct r_bin_asf_hunk *hunk, struct rom_list* roms) {
	struct asf_rom_header header;

	if (!asf_rom_header_unpack (hunk, &header)) return NULL;

	for (; roms; roms = roms->next) {
		if (roms->crc32 == header.crc32) {
			return roms;
		}
	}

	return NULL;
}

static void free_roms (struct rom_list *roms)
{
	struct rom_list *rom = roms;
	struct rom_list *next;
	while (rom) {
		next = rom->next;
		free (rom->data);
		free (rom);
		rom = next;
	}
}

static int unwrap_asf (const char *pathname, ut8 **data, ut64 *size) {
	RMmap *mm;
	int offset;
	int data_offset;
	int inflated_size_actual;
	ut8 *inflated_data;
	ut32 v32;
	RBuffer *rbuf;
	struct r_bin_asf_hunk hunk;
	struct rom_list *roms = NULL;
	struct rom_list *rom;

	mm = r_file_mmap (pathname, false, 0);
	if (!mm || !mm->buf) {
		r_file_mmap_free (mm);
		return 0;
	}

	if (!r_bin_asf_check_bytes (mm->buf, mm->len)) {
		r_file_mmap_free (mm);
		return 0;
	}

	rbuf = r_buf_new_with_pointers (mm->buf, mm->len);

	/* calculate size needed to contain only non-zlib hunks */
	offset = 0;
	*size = 0;
	while (r_bin_asf_next_hunk (rbuf, &offset, &hunk)) {
		if (hunk.inflated_size > 0) {
			*size += 12 + hunk.inflated_size;
		} else if (handle_rom (&hunk, &roms)) {
			*size += 12 + sizeof(struct asf_rom_header) + roms->size;
		} else {
			*size += hunk.size;
		}
		*size = r_bin_asf_align_offset (*size);
	}

	*data = calloc (1, *size);
	if (*data == NULL) {
		r_buf_free (rbuf);
		r_file_mmap_free (mm);
		free_roms (roms);
		return 0;
	}

	/* iterate hunks, copy non-zlib hunks as-is and convert zlib hunks to
	 * non-zlib ones */
	offset = 0;
	data_offset = 0;
	while (r_bin_asf_next_hunk (rbuf, &offset, &hunk)) {
		// write header (without size)
		memcpy (*data + data_offset, (ut8*)hunk.name, 4);
		v32 = 0; // flags=0; means "not zlib'd"
		r_mem_copyendian (*data + data_offset + 8, (ut8*)&v32, 4, 0);

		if (hunk.inflated_size > 0) {
			inflated_data = r_inflate (hunk.data, hunk.size - 16, NULL, &inflated_size_actual);
			if (inflated_data == NULL) {
				eprintf ("failed to unpack zlib'd '%s' hunk\n", hunk.name);
				r_buf_free (rbuf);
				r_file_mmap_free (mm);
				free_roms (roms);
				return 0;
			}
			if (inflated_size_actual != hunk.inflated_size) {
				eprintf ("failed to unpack zlib'd '%s' hunk; actual size (%u) != expected size (%u)\n",
					hunk.name,
					inflated_size_actual,
					hunk.inflated_size);
				r_buf_free (rbuf);
				r_file_mmap_free (mm);
				free_roms (roms);
				return 0;
			}

			// write hunk size in header
			v32 = hunk.inflated_size + 12; // hunk size includes header
			r_mem_copyendian (*data + data_offset + 4, (ut8*)&v32, 4, 0);

			// write body
			memcpy (*data + 12 + data_offset, inflated_data, hunk.inflated_size);

			free (inflated_data);

			data_offset += 12 + hunk.inflated_size;
		} else if ((rom = get_rom (&hunk, roms)) != NULL) {
			/* converting "ROM " to "ROMI"; a ROM hunk format only
			 * used internally by bin_asf.c - the "ROM " hunk
			 * ostensibly supports appending the rom image to the
			 * end of the hunk, but it's broken in practice because
			 * the path string occasionally is not null terminated
			 * (I haven't seen it used either) */
			(*data)[data_offset + 3] = 'I';

			v32 = 12 + sizeof(struct asf_rom_header) + rom->size;
			r_mem_copyendian (*data + data_offset + 4, (ut8*)&v32, 4, 0);
			memcpy (*data + data_offset + 12, hunk.data, sizeof(struct asf_rom_header));

			// fixing rom header; the size is unreliable
			v32 = rom->size;
			r_mem_copyendian (
				*data + data_offset + 12 + r_offsetof (struct asf_rom_header, size),
				(ut8*)&v32,
				4,
				0);

			memcpy (*data + data_offset + 12 + sizeof(struct asf_rom_header), rom->data, rom->size);
			data_offset += 12 + sizeof(struct asf_rom_header) + rom->size;
		} else {
			r_mem_copyendian (*data + data_offset + 4, (ut8*)&hunk.size, 4, 0);
			if (hunk.data_size > 0) {
				memcpy (*data + data_offset + 12, hunk.data, hunk.data_size);
			}
			data_offset += hunk.size;
		}
		data_offset = r_bin_asf_align_offset(data_offset);
	}

	free_roms (roms);
	r_buf_free (rbuf);
	r_file_mmap_free (mm);

	return 1;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	RIODesc *res;
	ut8* data;
	ut64 size;
	char malloc_filename[256];

	if (!unwrap_asf (pathname, &data, &size)) {
		return NULL;
	}

	snprintf (malloc_filename, sizeof(malloc_filename), "malloc://%llu", size);

	res = r_io_plugin_malloc.open (io, malloc_filename, rw, mode);
	if (res != NULL) {
		r_io_plugin_malloc.write (io, res, data, size);
		r_io_plugin_malloc.lseek (io, res, 0, SEEK_SET);
	}

	free (data);

	return res;
}

static int __plugin_open(struct r_io_t *io, const char *pathname, ut8 many) {
	int res;
	RMmap *mm;

	if (many) return 0;

	mm = r_file_mmap (pathname, false, 0);
	if (!mm || !mm->buf) {
		r_file_mmap_free (mm);
		return 0;
	}

	res = r_bin_asf_check_bytes (mm->buf, mm->len);

	r_file_mmap_free (mm);

	return res;
}

static int __close(RIODesc *fd) {
	return r_io_plugin_malloc.close (fd);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	return r_io_plugin_malloc.read (io, fd, buf, count);
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	return r_io_plugin_malloc.lseek (io, fd, offset, whence);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	return r_io_plugin_malloc.write (io, fd, buf, count);
}

static int __resize(RIO *io, RIODesc *fd, ut64 count) {
	return r_io_plugin_malloc.resize (io, fd, count);
}

struct r_io_plugin_t r_io_plugin_asf = {
	.name = "asf",
	.desc = "ASF (Amiga State File)",
	.license = "LGPL3",
	.open = __open,
	.plugin_open = __plugin_open,

	.close = __close,
	.read = __read,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};


#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_malloc,
	.version = R2_VERSION
};
#endif
