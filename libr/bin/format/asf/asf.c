#include <r_types.h>
#include <r_bin.h>
#include <r_util.h>

#include "asf.h"

static int hunk_read(struct r_bin_asf_hunk *hunk, void* dst, const char* fmt) {
	RBuffer *buf;
	if ((buf = r_buf_new_with_pointers(hunk->data, hunk->data_size)) == NULL) return 0;
	r_buf_fread_at (buf, 0, (ut8*)dst, fmt, 1);
	r_buf_free (buf);
	return 1;
}

R_API int asf_rom_header_unpack(struct r_bin_asf_hunk *hunk, struct asf_rom_header *header)
{
	if (strcmp (hunk->name, "ROM ") != 0 && strcmp (hunk->name, "ROMI") != 0) return 0;
	return hunk_read (hunk, header, "IIISSI");
}

R_API int r_bin_asf_check_bytes(const ut8* bytes, ut64 sz) {
	if (!bytes || sz < 5) return false;
	return memcmp (bytes, "ASF \x00", 5) == 0;
}

R_API int r_bin_asf_align_offset(int offset) {
	/* hunk headers are aligned to 4 bytes (+3 would've made more sense so
	 * it doesn't waste 4 bytes when the offset is already aligned, but
	 * this is how the file format is!) */
	return ((offset + 4) >> 2) << 2;
}

R_API int r_bin_asf_next_hunk(RBuffer* buf, int* offset, struct r_bin_asf_hunk* hunk) {
	struct asf_hunk_header hunk_header;
	int n;
	ut32 flags;
	int data_offset;

	memset (hunk, 0, sizeof(*hunk));

	if (*offset < 0) return 0;

	n = r_buf_fread_at (buf, *offset, (ut8*)&hunk_header, "4cI", 1);
	if (n != sizeof(hunk_header)) {
		eprintf ("failed to read hunk header\n");
		return 0;
	}

	memcpy (hunk->name, hunk_header.name, 4);
	hunk->name[4] = 0;

	hunk->size = hunk_header.size;

	if (strcmp (hunk->name, "END ") == 0) {
		*offset = -1;
		return 1;
	}

	n = r_buf_fread_at (buf, *offset + 8, (ut8*)&flags, "I", 1);
	if (n != 4) {
		eprintf ("failed to read '%s' hunk flags\n", hunk->name);
		return 0;
	}

	if (flags & 1) {
		n = r_buf_fread_at (buf, *offset + 12, (ut8*)&hunk->inflated_size, "I", 1);
		if (n != 4) {
			eprintf ("failed to read zlib'd '%s' hunk inflated size\n", hunk->name);
			return 0;
		}
		data_offset = 16;
	} else {
		data_offset = 12;
	}

	hunk->data = buf->buf + *offset + data_offset;
	hunk->data_size = hunk->size - data_offset;

	*offset += hunk->size;
	if (*offset > buf->length) {
		eprintf ("'%s' hunk size extends %d bytes past end-of-file\n", hunk->name, *offset - buf->length);
		return 0;
	}

	*offset = r_bin_asf_align_offset(*offset);

	return 1;
}
