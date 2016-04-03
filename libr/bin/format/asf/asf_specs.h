#ifndef ASF_SPECS_H

#include <r_types_base.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

struct asf_hunk_header {
	char name[4];
	ut32 size;
} __attribute__((packed));

struct asf_rom_header {
	ut32 start_addr;
	ut32 size;
	ut32 type;
	ut16 version;
	ut16 revision;
	ut32 crc32;
} __attribute__((packed));

struct asf_cpu {
	ut32 model;
	ut32 flags;
	ut32 regs[15];
	ut32 pc;
	ut32 irc;
	ut32 ir;
	ut32 usp;
	ut32 isp;
	ut32 sr;
} __attribute__((packed));


#define ASF_SPECS_H
#endif
