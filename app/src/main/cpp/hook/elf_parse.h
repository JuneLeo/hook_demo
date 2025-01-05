//
// Created by juneleo on 2024/12/30.
//

#ifndef ELF_CALL_ELF_PARSE_H
#define ELF_CALL_ELF_PARSE_H

#include <stdint.h>
#include <linux/elf.h>
#include <link.h>
#include <errno.h>


#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <vector>
#include <string>


#if defined(__arm__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT      //.rel.plt
#define XH_ELF_R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT       //.rel.dyn
#define XH_ELF_R_GENERIC_ABS       R_ARM_ABS32          //.rel.dyn
#elif defined(__aarch64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_AARCH64_ABS64
#elif defined(__i386__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_386_32
#elif defined(__x86_64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_X86_64_64
#endif


#if defined(__LP64__)
#define XH_ELF_R_SYM(info)  ELF64_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define XH_ELF_R_SYM(info)  ELF32_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif


#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr + sizeof(uintptr_t) - 1) + PAGE_SIZE)
#define PAGE_COVER(addr) (PAGE_END(addr) - PAGE_START(addr))

struct ShareLibrary {
    uintptr_t base_addr;
    std::string pathname;
};

typedef struct
{
    uint8_t  *cur;
    uint8_t  *end;
    int       is_use_rela;
} xh_elf_plain_reloc_iterator_t;

typedef struct
{
    uint8_t  *cur;
    uint8_t  *end;
} xh_elf_sleb128_decoder_t;

typedef struct
{
    xh_elf_sleb128_decoder_t decoder;
    size_t                   relocation_count;
    size_t                   group_size;
    size_t                   group_flags;
    size_t                   group_r_offset_delta;
    size_t                   relocation_index;
    size_t                   relocation_group_index;
    ElfW(Rela)               rela;
    ElfW(Rel)                rel;
    ElfW(Addr)               r_offset;
    size_t                   r_info;
    ssize_t                  r_addend;
    int                      is_use_rela;
} xh_elf_packed_reloc_iterator_t;

typedef struct
{
    const char *pathname;

    ElfW(Addr)  base_addr;
    ElfW(Addr)  bias_addr;

    ElfW(Ehdr) *ehdr;
    ElfW(Phdr) *phdr;

    ElfW(Dyn)  *dyn; //.dynamic
    ElfW(Word)  dyn_sz;

    const char *strtab; //.dynstr (string-table)
    ElfW(Sym)  *symtab; //.dynsym (symbol-index to string-table's offset)

    ElfW(Addr)  relplt; //.rel.plt or .rela.plt
    ElfW(Word)  relplt_sz;

    ElfW(Addr)  reldyn; //.rel.dyn or .rela.dyn
    ElfW(Word)  reldyn_sz;

    ElfW(Addr)  relandroid; //android compressed rel or rela
    ElfW(Word)  relandroid_sz;

    //for ELF hash
    uint32_t   *bucket;
    uint32_t    bucket_cnt;
    uint32_t   *chain;
    uint32_t    chain_cnt; //invalid for GNU hash

    //append for GNU hash
    uint32_t    symoffset;
    ElfW(Addr) *bloom;
    uint32_t    bloom_sz;
    uint32_t    bloom_shift;

    int         is_use_rela;
    int         is_use_gnu_hash;
} xh_elf_t;

int xh_elf_init(xh_elf_t *self, uintptr_t base_addr, const char *pathname);
int xh_elf_hook(xh_elf_t *self, const char *symbol, void *new_func, void **old_func);

void xh_maps(std::vector<ShareLibrary> *vector);


#endif //ELF_CALL_ELF_PARSE_H
