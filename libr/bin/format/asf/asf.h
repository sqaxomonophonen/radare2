#ifndef ASF_H

#include "asf_specs.h"

struct r_bin_asf_hunk {
	char name[5];
	ut32 size;
	ut32 inflated_size;
	ut8* data;
	ut32 data_size;
	ut32 offset_delta;
};

struct r_bin_asf_obj {
	Sdb* kv;
	struct asf_cpu cpu;
};

R_API int asf_rom_header_unpack(struct r_bin_asf_hunk *hunk, struct asf_rom_header *header);
R_API int r_bin_asf_check_bytes(const ut8* bytes, ut64 sz);
R_API int r_bin_asf_align_offset(int offset);
R_API int r_bin_asf_next_hunk(RBuffer* buf, int* offset, struct r_bin_asf_hunk* hunk);

#define ASF_H
#endif
