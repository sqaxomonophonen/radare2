/* radare - LGPL3 - 2016 - sqaxomonophonen */

/*
ASF (Amiga State File) - see src/savestate.cpp in various UAE forks

NOTE that this plugin works closely together with io_asf.c which converts
various hunks. This is because r2 disassembles a file as-is (a bin plugin just
provides file offsets to interesting sections and such) whereas the real ASF
format allows zlib'd hunks and references to external files.
*/

#include <r_bin.h>
#include <r_util.h>
#include "asf/asf.h"

static Sdb* get_sdb (RBinObject *o) {
	if (!o || !o->bin_obj) return NULL;
	struct r_bin_asf_obj* bin = (struct r_bin_asf_obj*) o->bin_obj;
	return bin->kv;
}

static int check_bytes(const ut8 *buf, ut64 length) {
	return r_bin_asf_check_bytes(buf, length);
}

static int check(RBinFile *arch) { // XXX never called I think; see bin.c
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	struct r_bin_asf_obj *res = NULL;
	int offset;
	RBuffer *data_buf;
	struct r_bin_asf_hunk hunk;

	if (!check_bytes (buf, sz)) {
		return NULL;
	}

	if (!(res = R_NEW0 (struct r_bin_asf_obj))) {
		return NULL;
	}

	offset = 0;
	while (r_bin_asf_next_hunk (arch->buf, &offset, &hunk)) {
		if (hunk.inflated_size > 0) {
			eprintf ("unexpected deflated hunk; did io_asf.c fail?!\n");
			return NULL;
		}

		data_buf = r_buf_new_with_pointers (hunk.data, hunk.data_size);
		if (strcmp (hunk.name, "CPU ") == 0) {
			r_buf_fread_at (data_buf, 0, (ut8*)&res->cpu, "II15IIIIIII", 1);
		}

		r_buf_free (data_buf);
	}

	res->kv = sdb_new0 ();
	sdb_ns_set (sdb, "info", res->kv);

	return res;
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	struct r_bin_asf_obj* asf_obj = (struct r_bin_asf_obj*) arch->o->bin_obj;

	if (!asf_obj) return NULL;

	if (!(ret = r_list_new ())) return NULL;

	// PC
	if (!(ptr = R_NEW0 (RBinAddr))) return NULL;
	ptr->paddr = 0;
	ptr->vaddr = asf_obj->cpu.pc;
	r_list_append (ret, ptr);

	return ret;
}

static RList* sections(RBinFile* arch) {
	RList *ret = NULL;
	RBinSection *bs = NULL;
	struct r_bin_asf_obj* asf_obj;
	int offset;
	int data_offset;
	struct r_bin_asf_hunk hunk;
	struct asf_rom_header rom_header;
	char *name;
	ut64 vaddr, size;
	ut32 srwx;

	asf_obj = (struct r_bin_asf_obj*) arch->o->bin_obj;
	if (!asf_obj) return NULL;

	if (!(ret = r_list_new ())) return NULL;

	offset = 0;
	while (r_bin_asf_next_hunk (arch->buf, &offset, &hunk)) {
		if (strcmp (hunk.name + 1, "RAM") == 0) {
			name = hunk.name;
			if (strcmp (name, "CRAM") == 0) {
				vaddr = 0;
			} else if (strcmp (name, "BRAM") == 0) {
				vaddr = 0xc00000;
			} else {
				continue;
			}
			data_offset = 0;
			size = hunk.data_size;
			srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
		} else if (strcmp (hunk.name, "ROMI") == 0) {
			asf_rom_header_unpack (&hunk, &rom_header);
			name = rom_header.type == 0 ? "KICK_ROM" : "ROM";
			vaddr = rom_header.start_addr;
			size = rom_header.size;
			data_offset = sizeof(rom_header);
			srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
		} else {
			continue;
		}

		if (!(bs = R_NEW0 (RBinSection))) return NULL;
		strcpy (bs->name, name);
		bs->paddr = (hunk.data + data_offset) - arch->buf->buf;
		bs->vaddr = vaddr;
		bs->vsize = bs->size = size;
		bs->srwx = srwx;
		bs->add = true;

		r_list_append (ret, bs);
	}

	return ret;
}


static RList* symbols(RBinFile *arch) {
	RList *ret = NULL;
	if (!(ret = r_list_new())) return NULL;
	// TODO
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	struct r_bin_asf_obj* asf_obj = (struct r_bin_asf_obj*) arch->o->bin_obj;
	if (!asf_obj) return NULL;

	if (!(ret = R_NEW0 (RBinInfo))) return NULL;

	ret->file = strdup (arch->file);
	ret->type = strdup ("Snapshot");
	ret->machine = strdup ("Amiga");
	ret->os = strdup ("Amiga OS");
	ret->arch = strdup ("m68k");
	ret->bits = 16;
	ret->has_va = true;
	ret->big_endian = true;

	sdb_num_set (asf_obj->kv, "asf.reg_pc", asf_obj->cpu.pc, 0);

	return ret;
}

static int destroy(RBinFile *arch) {
	free(arch->o->bin_obj);
	return true;
}

static RList *mem(RBinFile *arch) {
	RList *ret;
	RBinMem *m;
	struct r_bin_asf_obj* asf_obj = (struct r_bin_asf_obj*) arch->o->bin_obj;

	if (!asf_obj) return NULL;
	if (!(ret = r_list_new())) return NULL;

	ret->free = free;
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}

	m->name = strdup ("RAM");
	m->addr = 0;
	m->size = 1<<24;
	m->perms = r_str_rwx ("mrwx");
	r_list_append (ret, m);

	return ret;
}

struct r_bin_plugin_t r_bin_plugin_asf = {
	.name = "asf",
	.desc = "ASF Amiga State File",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.destroy = &destroy,
	.mem = &mem,
};
#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_asf,
	.version = R2_VERSION
};
#endif
