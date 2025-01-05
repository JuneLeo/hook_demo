//
// Created by juneleo on 2024/12/30.
//

#include "elf_parse.h"
#include "log.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>


static void xh_elf_dump_rel(xh_elf_t *self, const char *type, ElfW(Addr) rel_addr, ElfW(Word) rel_sz) {
    ElfW(Rela) *rela;
    ElfW(Rel) *rel;
    ElfW(Word) cnt;
    ElfW(Word) i;
    ElfW(Sym) *sym;

    if (self->is_use_rela) {
        rela = (ElfW(Rela) *) (rel_addr);
        cnt = rel_sz / sizeof(ElfW(Rela));
    } else {
        rel = (ElfW(Rel) *) (rel_addr);
        cnt = rel_sz / sizeof(ElfW(Rel));
    }

    XH_LOG_DEBUG("Relocation section '.rel%s%s' contains %u entries:\n",
                 (self->is_use_rela ? "a" : ""), type, cnt);
    XH_LOG_DEBUG("  %-16s " \
                 "%-16s " \
                 "%-8s " \
                 "%-8s " \
                 "%-8s " \
                 "%s\n",
                 "Offset",
                 "Info",
                 "Type",
                 "Sym.Idx",
                 "Sym.Val",
                 "Sym.Name");
    const char *fmt = "  %.16llx " \
                      "%.16llx " \
                      "%.8x " \
                      "%.8u " \
                      "%.8x " \
                      "%s\n";
    for (i = 0; i < cnt; i++) {
        if (self->is_use_rela) {
            sym = &(self->symtab[XH_ELF_R_SYM(rela[i].r_info)]);
            XH_LOG_DEBUG(fmt,
                         rela[i].r_offset,
                         rela[i].r_info,
                         XH_ELF_R_TYPE(rela[i].r_info),
                         XH_ELF_R_SYM(rela[i].r_info),
                         sym->st_value,
                         self->strtab + sym->st_name);
        } else {
            sym = &(self->symtab[XH_ELF_R_SYM(rel[i].r_info)]);
            XH_LOG_DEBUG(fmt,
                         rel[i].r_offset,
                         rel[i].r_info,
                         XH_ELF_R_TYPE(rel[i].r_info),
                         XH_ELF_R_SYM(rel[i].r_info),
                         sym->st_value,
                         self->strtab + sym->st_name);
        }
    }
}

static void xh_elf_dump_symtab(xh_elf_t *self) {
    if (self->is_use_gnu_hash) return;

    ElfW(Word) symtab_cnt = self->chain_cnt;
    ElfW(Word) i;

    XH_LOG_DEBUG("Symbol table '.dynsym' contains %u entries:\n", symtab_cnt);
    XH_LOG_DEBUG("  %-8s " \
                 "%-16s " \
                 "%s\n",
                 "Idx",
                 "Value",
                 "Name");
    for (i = 0; i < symtab_cnt; i++) {
        XH_LOG_DEBUG("  %-8u " \
                     "%.16llx " \
                     "%s\n",
                     i,
                     self->symtab[i].st_value,
                     self->strtab + self->symtab[i].st_name);
    }
}

static void xh_elf_dump_programheader(xh_elf_t *self) {
    ElfW(Phdr) *phdr = self->phdr;
    size_t i;

    XH_LOG_DEBUG("Program Headers:\n");
    XH_LOG_DEBUG("  %-8s " \
                 "%-16s " \
                 "%-16s " \
                 "%-16s " \
                 "%-16s " \
                 "%-16s " \
                 "%-8s " \
                 "%-s\n",
                 "Type",
                 "Offset",
                 "VirtAddr",
                 "PhysAddr",
                 "FileSiz",
                 "MemSiz",
                 "Flg",
                 "Align");
    for (i = 0; i < self->ehdr->e_phnum; i++, phdr++) {
        XH_LOG_DEBUG("  %-8x " \
                     "%.16llx " \
                     "%.16llx " \
                     "%.16llx " \
                     "%.16llx " \
                     "%.16llx " \
                     "%-8x " \
                     "%llx\n",
                     phdr->p_type,
                     phdr->p_offset,
                     phdr->p_vaddr,
                     phdr->p_paddr,
                     phdr->p_filesz,
                     phdr->p_memsz,
                     phdr->p_flags,
                     phdr->p_align);
    }
}

static void xh_elf_dump_dynamic(xh_elf_t *self) {
    ElfW(Dyn) *dyn = self->dyn;
    size_t dyn_cnt = (self->dyn_sz / sizeof(ElfW(Dyn)));
    size_t i;

    XH_LOG_DEBUG("Dynamic section contains %zu entries:\n", dyn_cnt);
    XH_LOG_DEBUG("  %-16s " \
                 "%s\n",
                 "Tag",
                 "Val");
    for (i = 0; i < dyn_cnt; i++, dyn++) {
        XH_LOG_DEBUG("  %-16llx " \
                     "%-llx\n",
                     dyn->d_tag,
                     dyn->d_un.d_val);
    }
}

static void xh_elf_dump_elfheader(xh_elf_t *self) {
    static char alpha_tab[17] = "0123456789ABCDEF";
    int i;
    uint8_t ch;
    char buff[EI_NIDENT * 3 + 1];

    for (i = 0; i < EI_NIDENT; i++) {
        ch = self->ehdr->e_ident[i];
        buff[i * 3 + 0] = alpha_tab[(int) ((ch >> 4) & 0x0F)];
        buff[i * 3 + 1] = alpha_tab[(int) (ch & 0x0F)];
        buff[i * 3 + 2] = ' ';
    }
    buff[EI_NIDENT * 3] = '\0';

    XH_LOG_DEBUG("Elf Header:\n");
    XH_LOG_DEBUG("  Magic:                             %s\n", buff);
    XH_LOG_DEBUG("  Class:                             %#x\n", self->ehdr->e_ident[EI_CLASS]);
    XH_LOG_DEBUG("  Data:                              %#x\n", self->ehdr->e_ident[EI_DATA]);
    XH_LOG_DEBUG("  Version:                           %#x\n", self->ehdr->e_ident[EI_VERSION]);
    XH_LOG_DEBUG("  OS/ABI:                            %#x\n", self->ehdr->e_ident[EI_OSABI]);
    XH_LOG_DEBUG("  ABI Version:                       %#x\n", self->ehdr->e_ident[EI_ABIVERSION]);
    XH_LOG_DEBUG("  Type:                              %#x\n", self->ehdr->e_type);
    XH_LOG_DEBUG("  Machine:                           %#x\n", self->ehdr->e_machine);
    XH_LOG_DEBUG("  Version:                           %#x\n", self->ehdr->e_version);
    XH_LOG_DEBUG("  Entry point address:               %llx\n", self->ehdr->e_entry);
    XH_LOG_DEBUG("  Start of program headers:          %llx (bytes into file)\n", self->ehdr->e_phoff);
    XH_LOG_DEBUG("  Start of section headers:          %llx (bytes into file)\n", self->ehdr->e_shoff);
    XH_LOG_DEBUG("  Flags:                             %#x\n", self->ehdr->e_flags);
    XH_LOG_DEBUG("  Size of this header:               %u (bytes)\n", self->ehdr->e_ehsize);
    XH_LOG_DEBUG("  Size of program headers:           %u (bytes)\n", self->ehdr->e_phentsize);
    XH_LOG_DEBUG("  Number of program headers:         %u\n", self->ehdr->e_phnum);
    XH_LOG_DEBUG("  Size of section headers:           %u (bytes)\n", self->ehdr->e_shentsize);
    XH_LOG_DEBUG("  Number of section headers:         %u\n", self->ehdr->e_shnum);
    XH_LOG_DEBUG("  Section header string table index: %u\n", self->ehdr->e_shstrndx);
}

ElfW(Phdr) *xh_elf_get_first_segment_by_type_offset(xh_elf_t *self, ElfW(Word) type, ElfW(Off) offset) {
    ElfW(Phdr) *phdr;

    for (phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++) {
        if (phdr->p_type == type && phdr->p_offset == offset) {
            return phdr;
        }
    }
    return NULL;
}

static ElfW(Phdr) *xh_elf_get_first_segment_by_type(xh_elf_t *self, ElfW(Word) type) {
    ElfW(Phdr) *phdr;

    for (phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++) {
        if (phdr->p_type == type) {
            return phdr;
        }
    }
    return NULL;
}

static int xh_elf_check(xh_elf_t *self) {
    if (0 == self->base_addr) {
        XH_LOG_ERROR("base_addr == 0\n");
        return 1;
    }
    if (0 == self->bias_addr) {
        XH_LOG_ERROR("bias_addr == 0\n");
        return 1;
    }
    if (NULL == self->ehdr) {
        XH_LOG_ERROR("ehdr == NULL\n");
        return 1;
    }
    if (NULL == self->phdr) {
        XH_LOG_ERROR("phdr == NULL\n");
        return 1;
    }
    if (NULL == self->strtab) {
        XH_LOG_ERROR("strtab == NULL\n");
        return 1;
    }
    if (NULL == self->symtab) {
        XH_LOG_ERROR("symtab == NULL\n");
        return 1;
    }
    if (NULL == self->bucket) {
        XH_LOG_ERROR("bucket == NULL\n");
        return 1;
    }
    if (NULL == self->chain) {
        XH_LOG_ERROR("chain == NULL\n");
        return 1;
    }
    if (1 == self->is_use_gnu_hash && NULL == self->bloom) {
        XH_LOG_ERROR("bloom == NULL\n");
        return 1;
    }

    return 0;
}

static void xh_elf_dump(xh_elf_t *self) {

    XH_LOG_DEBUG("Elf Pathname: %s\n", self->pathname);
    XH_LOG_DEBUG("Elf bias addr: %p\n", (void *) self->bias_addr);
    xh_elf_dump_elfheader(self);
    xh_elf_dump_programheader(self);
    xh_elf_dump_dynamic(self);
    xh_elf_dump_rel(self, ".plt", self->relplt, self->relplt_sz);
    xh_elf_dump_rel(self, ".dyn", self->reldyn, self->reldyn_sz);
    xh_elf_dump_symtab(self);
}


int xh_elf_init(xh_elf_t *self, uintptr_t base_addr, const char *pathname) {
    self->base_addr = (ElfW(Addr)) base_addr;
    self->pathname = pathname;

    XH_LOG_DEBUG("base_address= %ld, pathname=%s", base_addr, pathname);

    self->ehdr = (ElfW(Ehdr) *) base_addr;

//    xh_elf_dump_elfheader(self);

    self->phdr = (ElfW(Phdr) *) (base_addr + self->ehdr->e_phoff);


    ElfW(Phdr) *phdr0 = xh_elf_get_first_segment_by_type_offset(self, PT_LOAD, 0);
    if (NULL == phdr0) {
        XH_LOG_ERROR("Can NOT found the first load segment. %s", pathname);
        return -1;
    }

    XH_LOG_DEBUG("first load-segment vaddr NOT 0 (vaddr: %p). %s",
                 (void *) (phdr0->p_vaddr), pathname);


    //save load bias addr
    if (self->base_addr < phdr0->p_vaddr) return -1;
    self->bias_addr = self->base_addr - phdr0->p_vaddr;

    //find dynamic-segment
    ElfW(Phdr) *dhdr = xh_elf_get_first_segment_by_type(self, PT_DYNAMIC);
    if (NULL == dhdr) {
        XH_LOG_ERROR("Can NOT found dynamic segment. %s", pathname);
        return -1;
    }

    //parse dynamic-segment
    self->dyn = (ElfW(Dyn) *) (self->bias_addr + dhdr->p_vaddr);
    self->dyn_sz = dhdr->p_memsz;
    ElfW(Dyn) *dyn = self->dyn;
    ElfW(Dyn) *dyn_end = self->dyn + (self->dyn_sz / sizeof(ElfW(Dyn)));
    uint32_t *raw;

    for (; dyn < dyn_end; dyn++) {
        switch (dyn->d_tag) //segmentation fault sometimes
        {
            case DT_NULL:
                //the end of the dynamic-section
                dyn = dyn_end;
                break;
            case DT_STRTAB: {
                self->strtab = (const char *) (self->bias_addr + dyn->d_un.d_ptr);
                if ((ElfW(Addr)) (self->strtab) < self->base_addr) return -1;
                break;
            }
            case DT_SYMTAB: {
                self->symtab = (ElfW(Sym) *) (self->bias_addr + dyn->d_un.d_ptr);
                if ((ElfW(Addr)) (self->symtab) < self->base_addr) return -1;
                break;
            }
            case DT_PLTREL:
                //use rel or rela?
                self->is_use_rela = (dyn->d_un.d_val == DT_RELA ? 1 : 0);
                break;
            case DT_JMPREL: {
                self->relplt = (ElfW(Addr)) (self->bias_addr + dyn->d_un.d_ptr);
                if ((ElfW(Addr)) (self->relplt) < self->base_addr) return -1;
                break;
            }
            case DT_PLTRELSZ:
                self->relplt_sz = dyn->d_un.d_val;
                break;
            case DT_REL:
            case DT_RELA: {
                self->reldyn = (ElfW(Addr)) (self->bias_addr + dyn->d_un.d_ptr);
                if ((ElfW(Addr)) (self->reldyn) < self->base_addr) return -1;
                break;
            }
            case DT_RELSZ:
            case DT_RELASZ:
                self->reldyn_sz = dyn->d_un.d_val;
                break;
            case DT_ANDROID_REL:
            case DT_ANDROID_RELA: {
                self->relandroid = (ElfW(Addr)) (self->bias_addr + dyn->d_un.d_ptr);
                if ((ElfW(Addr)) (self->relandroid) < self->base_addr) return -1;
                break;
            }
            case DT_ANDROID_RELSZ:
            case DT_ANDROID_RELASZ:
                self->relandroid_sz = dyn->d_un.d_val;
                break;
            case DT_HASH: {
                //ignore DT_HASH when ELF contains DT_GNU_HASH hash table
                if (1 == self->is_use_gnu_hash) continue;

                raw = (uint32_t *) (self->bias_addr + dyn->d_un.d_ptr);
                if ((ElfW(Addr)) raw < self->base_addr) return -1;
                self->bucket_cnt = raw[0];
                self->chain_cnt = raw[1];
                self->bucket = &raw[2];
                self->chain = &(self->bucket[self->bucket_cnt]);
                break;
            }
            case DT_GNU_HASH: {
                raw = (uint32_t *) (self->bias_addr + dyn->d_un.d_ptr);
                if ((ElfW(Addr)) raw < self->base_addr) return -1;
                self->bucket_cnt = raw[0];
                self->symoffset = raw[1];
                self->bloom_sz = raw[2];
                self->bloom_shift = raw[3];
                self->bloom = (ElfW(Addr) *) (&raw[4]);
                self->bucket = (uint32_t *) (&(self->bloom[self->bloom_sz]));
                self->chain = (uint32_t *) (&(self->bucket[self->bucket_cnt]));
                self->is_use_gnu_hash = 1;
                break;
            }
            default:
                break;
        }
    }


//    xh_elf_dump(self);

    //check android rel/rela
    if (0 != self->relandroid) {
        const char *rel = (const char *) self->relandroid;
        if (self->relandroid_sz < 4 ||
            rel[0] != 'A' ||
            rel[1] != 'P' ||
            rel[2] != 'S' ||
            rel[3] != '2') {
            XH_LOG_ERROR("android rel/rela format error\n");
            return -1;
        }

        self->relandroid += 4;
        self->relandroid_sz -= 4;
    }

    //check elf info
    if (0 != xh_elf_check(self)) {
        XH_LOG_ERROR("elf init check failed. %s", pathname);
        return -1;
    }

    return 0;
}



void xh_maps(std::vector<ShareLibrary> *vector) {

    char line[512];
    FILE *fp;
    uintptr_t base_addr;
    uintptr_t prev_base_addr = 0;
    char perm[5];
    char prev_perm[5] = "---p";
    unsigned long offset;
    unsigned long prev_offset = 0;
    int pathname_pos;
    char *pathname;
    char prev_pathname[512] = {0};
    size_t pathname_len;

    if (NULL == (fp = fopen("/proc/self/maps", "r"))) {
        XH_LOG_ERROR("fopen /proc/self/maps failed");
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx-%*lx %4s %lx %*x:%*x %*d%n", &base_addr, perm, &offset, &pathname_pos) != 3) continue;
        // do not touch the shared memory
        if (perm[3] != 'p') continue;

        // Ignore permission PROT_NONE maps
        if (perm[0] == '-' && perm[1] == '-' && perm[2] == '-') // ---p
            continue;

        //get pathname
        while (isspace(line[pathname_pos]) && pathname_pos < (int) (sizeof(line) - 1))
            pathname_pos += 1;
        if (pathname_pos >= (int) (sizeof(line) - 1)) continue;
        pathname = line + pathname_pos;
        pathname_len = strlen(pathname);
        if (0 == pathname_len) continue;
        if (pathname[pathname_len - 1] == '\n') {
            pathname[pathname_len - 1] = '\0';
            pathname_len -= 1;
        }
        if (0 == pathname_len) continue;
        if ('[' == pathname[0]) continue;

        // Find non-executable map, we need record it. Because so maps can begin with
        // an non-executable map.
        if (perm[2] != 'x') {
            prev_offset = offset;
            prev_base_addr = base_addr;
            memcpy(prev_perm, perm, sizeof(prev_perm));
            strcpy(prev_pathname, pathname);
            continue;
        }

        // Find executable map if offset == 0, it OK,
        // or we need check previous map for base address.
        if (offset != 0) {
            if (strcmp(prev_pathname, pathname) || prev_offset != 0 || prev_perm[0] != 'r') {
                continue;
            }
            // The previous map is real begin map
            base_addr = prev_base_addr;
        }
        auto *shareLibrary = new ShareLibrary();
        std::string pathNameStr(pathname);
        shareLibrary->pathname = pathNameStr;
        shareLibrary->base_addr = base_addr;
        vector->push_back(*shareLibrary);
        XH_LOG_DEBUG("pathname = %s, address=%ld", pathname, base_addr);
    }
}

//ELF hash func
static uint32_t xh_elf_hash(const uint8_t *name) {
    uint32_t h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }

    return h;
}

//GNU hash func
static uint32_t xh_elf_gnu_hash(const uint8_t *name) {
    uint32_t h = 5381;

    while (*name != 0) {
        h += (h << 5) + *name++;
    }
    return h;
}

static int xh_elf_gnu_hash_lookup_def(xh_elf_t *self, const char *symbol, uint32_t *symidx) {
    uint32_t hash = xh_elf_gnu_hash((uint8_t *) symbol);

    static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
    size_t word = self->bloom[(hash / elfclass_bits) % self->bloom_sz];
    size_t mask = 0
                  | (size_t) 1 << (hash % elfclass_bits)
                  | (size_t) 1 << ((hash >> self->bloom_shift) % elfclass_bits);

    //if at least one bit is not set, this symbol is surely missing
    if ((word & mask) != mask) return -1;

    //ignore STN_UNDEF
    uint32_t i = self->bucket[hash % self->bucket_cnt];
    if (i < self->symoffset) return -1;

    //loop through the chain
    while (1) {
        const char *symname = self->strtab + self->symtab[i].st_name;
        const uint32_t symhash = self->chain[i - self->symoffset];

        if ((hash | (uint32_t) 1) == (symhash | (uint32_t) 1) && 0 == strcmp(symbol, symname)) {
            *symidx = i;
            XH_LOG_INFO("found %s at symidx: %u (GNU_HASH DEF)\n", symbol, *symidx);
            return 0;
        }

        //chain ends with an element with the lowest bit set to 1
        if (symhash & (uint32_t) 1) break;

        i++;
    }

    return -1;
}

static int xh_elf_gnu_hash_lookup_undef(xh_elf_t *self, const char *symbol, uint32_t *symidx) {
    uint32_t i;

    for (i = 0; i < self->symoffset; i++) {
        const char *symname = self->strtab + self->symtab[i].st_name;
        if (0 == strcmp(symname, symbol)) {
            *symidx = i;
            XH_LOG_INFO("found %s at symidx: %u (GNU_HASH UNDEF)\n", symbol, *symidx);
            return 0;
        }
    }
    return -1;
}


static int xh_elf_gnu_hash_lookup(xh_elf_t *self, const char *symbol, uint32_t *symidx) {
    if (0 == xh_elf_gnu_hash_lookup_def(self, symbol, symidx)) return 0;
    if (0 == xh_elf_gnu_hash_lookup_undef(self, symbol, symidx)) return 0;
    return -1;
}

static int xh_elf_hash_lookup(xh_elf_t *self, const char *symbol, uint32_t *symidx) {
    uint32_t hash = xh_elf_hash((uint8_t *) symbol);
    const char *symbol_cur;
    uint32_t i;

    for (i = self->bucket[hash % self->bucket_cnt]; 0 != i; i = self->chain[i]) {
        symbol_cur = self->strtab + self->symtab[i].st_name;

        if (0 == strcmp(symbol, symbol_cur)) {
            *symidx = i;
            XH_LOG_INFO("found %s at symidx: %u (ELF_HASH)\n", symbol, *symidx);
            return 0;
        }
    }

    return -1;
}


static int xh_elf_find_symidx_by_name(xh_elf_t *self, const char *symbol, uint32_t *symidx) {
    if (self->is_use_gnu_hash)
        return xh_elf_gnu_hash_lookup(self, symbol, symidx);
    else
        return xh_elf_hash_lookup(self, symbol, symidx);
}

static void xh_elf_plain_reloc_iterator_init(xh_elf_plain_reloc_iterator_t *self,
                                             ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela) {
    self->cur = (uint8_t *) rel;
    self->end = self->cur + rel_sz;
    self->is_use_rela = is_use_rela;
}


static void *xh_elf_plain_reloc_iterator_next(xh_elf_plain_reloc_iterator_t *self) {
    if (self->cur >= self->end) return NULL;

    void *ret = (void *) (self->cur);
    self->cur += (self->is_use_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));
    return ret;
}


int xh_util_get_mem_protect(uintptr_t addr, size_t len, const char *pathname, unsigned int *prot) {
    uintptr_t start_addr = addr;
    uintptr_t end_addr = addr + len;
    FILE *fp;
    char line[512];
    uintptr_t start, end;
    char perm[5];
    int load0 = 1;
    int found_all = 0;

    *prot = 0;

    if (NULL == (fp = fopen("/proc/self/maps", "r"))) return -1;

    while (fgets(line, sizeof(line), fp)) {
        if (NULL != pathname)
            if (NULL == strstr(line, pathname)) continue;

        if (sscanf(line, "%lx-%lx %4s ", &start, &end, perm) != 3) continue;

        if (perm[3] != 'p') continue;

        if (start_addr >= start && start_addr < end) {
            if (load0) {
                //first load segment
                if (perm[0] == 'r') *prot |= PROT_READ;
                if (perm[1] == 'w') *prot |= PROT_WRITE;
                if (perm[2] == 'x') *prot |= PROT_EXEC;
                load0 = 0;
            } else {
                //others
                if (perm[0] != 'r') *prot &= ~PROT_READ;
                if (perm[1] != 'w') *prot &= ~PROT_WRITE;
                if (perm[2] != 'x') *prot &= ~PROT_EXEC;
            }

            if (end_addr <= end) {
                found_all = 1;
                break; //finished
            } else {
                start_addr = end; //try to find the next load segment
            }
        }
    }

    fclose(fp);

    if (!found_all) return -1;

    return 0;
}

int xh_util_get_addr_protect(uintptr_t addr, const char *pathname, unsigned int *prot) {
    return xh_util_get_mem_protect(addr, sizeof(addr), pathname, prot);
}

int xh_util_set_addr_protect(uintptr_t addr, unsigned int prot) {
    if (0 != mprotect((void *) PAGE_START(addr), PAGE_COVER(addr), (int) prot))
        return 0 == errno ? -1 : errno;

    return 0;
}

void xh_util_flush_instruction_cache(uintptr_t addr) {
//    __builtin___clear_cache((void *)PAGE_START(addr), (void *)PAGE_END(addr));
}

static int xh_elf_replace_function(xh_elf_t *self, const char *symbol, ElfW(Addr) addr, void *new_func, void **old_func) {
    void *old_addr;
    unsigned int old_prot = 0;
    unsigned int need_prot = PROT_READ | PROT_WRITE;
    int r;

    //already replaced?
    //here we assume that we always have read permission, is this a problem?
    if (*(void **) addr == new_func) return 0;

    //get old prot
    if (0 != (r = xh_util_get_addr_protect(addr, self->pathname, &old_prot))) {
        XH_LOG_ERROR("get addr prot failed. ret: %d", r);
        return r;
    }

    if (old_prot != need_prot) {
        //set new prot
        if (0 != (r = xh_util_set_addr_protect(addr, need_prot))) {
            XH_LOG_ERROR("set addr prot failed. ret: %d", r);
            return r;
        }
    }

    //save old func
    old_addr = *(void **) addr;
    if (NULL != old_func) *old_func = old_addr;

    //replace func
    *(void **) addr = new_func; //segmentation fault sometimes

    if (old_prot != need_prot) {
        //restore the old prot
        if (0 != (r = xh_util_set_addr_protect(addr, old_prot))) {
            XH_LOG_WARN("restore addr prot failed. ret: %d", r);
        }
    }

    //clear cache
    xh_util_flush_instruction_cache(addr);

    XH_LOG_INFO("XH_HK_OK %p: %p -> %p %s %s\n", (void *) addr, old_addr, new_func, symbol, self->pathname);
    return 0;
}

static int xh_elf_find_and_replace_func(xh_elf_t *self, const char *section,
                                        int is_plt, const char *symbol,
                                        void *new_func, void **old_func,
                                        uint32_t symidx, void *rel_common,
                                        int *found) {
    ElfW(Rela) *rela;
    ElfW(Rel) *rel;
    ElfW(Addr) r_offset;
    size_t r_info;
    size_t r_sym;
    size_t r_type;
    ElfW(Addr) addr;
    int r;

    if (NULL != found) *found = 0;

    if (self->is_use_rela) {
        rela = (ElfW(Rela) *) rel_common;
        r_info = rela->r_info;
        r_offset = rela->r_offset;
    } else {
        rel = (ElfW(Rel) *) rel_common;
        r_info = rel->r_info;
        r_offset = rel->r_offset;
    }

    //check sym
    r_sym = XH_ELF_R_SYM(r_info);
    if (r_sym != symidx) return 0;

    //check type
    r_type = XH_ELF_R_TYPE(r_info);
    if (is_plt && r_type != XH_ELF_R_GENERIC_JUMP_SLOT) return 0;
    if (!is_plt && (r_type != XH_ELF_R_GENERIC_GLOB_DAT && r_type != XH_ELF_R_GENERIC_ABS)) return 0;

    //we found it
    XH_LOG_INFO("found %s at %s offset: %p\n", symbol, section, (void *) r_offset);
    if (NULL != found) *found = 1;

    //do replace
    addr = self->bias_addr + r_offset;
    if (addr < self->base_addr) return -1;
    if (0 != (r = xh_elf_replace_function(self, symbol, addr, new_func, old_func))) {
        XH_LOG_ERROR("replace function failed: %s at %s\n", symbol, section);
        return r;
    }

    return 0;
}

static void xh_elf_sleb128_decoder_init(xh_elf_sleb128_decoder_t *self,
                                        ElfW(Addr) rel, ElfW(Word) rel_sz) {
    self->cur = (uint8_t *) rel;
    self->end = self->cur + rel_sz;
}

static int xh_elf_sleb128_decoder_next(xh_elf_sleb128_decoder_t *self, size_t *ret) {
    size_t value = 0;
    static const size_t size = 8 * sizeof(value);
    size_t shift = 0;
    uint8_t byte;

    do {
        if (self->cur >= self->end)
            return -1;

        byte = *(self->cur)++;
        value |= ((size_t) (byte & 127) << shift);
        shift += 7;
    } while (byte & 128);

    if (shift < size && (byte & 64)) {
        value |= -((size_t) (1) << shift);
    }

    *ret = value;
    return 0;
}

static int xh_elf_packed_reloc_iterator_init(xh_elf_packed_reloc_iterator_t *self,
                                             ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela) {
    int r;

    memset(self, 0, sizeof(xh_elf_packed_reloc_iterator_t));
    xh_elf_sleb128_decoder_init(&(self->decoder), rel, rel_sz);
    self->is_use_rela = is_use_rela;

    if (0 != (r = xh_elf_sleb128_decoder_next(&(self->decoder), &(self->relocation_count)))) return r;
    if (0 != (r = xh_elf_sleb128_decoder_next(&(self->decoder), (size_t *) &(self->r_offset)))) return r;
    return 0;
}


const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;


static int xh_elf_packed_reloc_iterator_read_group_fields(xh_elf_packed_reloc_iterator_t *self) {
    int r;
    size_t val;

    if (0 != (r = xh_elf_sleb128_decoder_next(&(self->decoder), &(self->group_size)))) return r;
    if (0 != (r = xh_elf_sleb128_decoder_next(&(self->decoder), &(self->group_flags)))) return r;

    if (self->group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG)
        if (0 != (r = xh_elf_sleb128_decoder_next(&(self->decoder), &(self->group_r_offset_delta)))) return r;

    if (self->group_flags & RELOCATION_GROUPED_BY_INFO_FLAG)
        if (0 != (r = xh_elf_sleb128_decoder_next(&(self->decoder), (size_t *) &(self->r_info)))) return r;

    if ((self->group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) &&
        (self->group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
        if (0 == self->is_use_rela) {
            XH_LOG_ERROR("unexpected r_addend in android.rel section");
            return -1;
        }
        if (0 != (r = xh_elf_sleb128_decoder_next(&(self->decoder), &val))) return r;
        self->r_addend += (ssize_t) val;
    } else if (0 == (self->group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG)) {
        self->r_addend = 0;
    }

    self->relocation_group_index = 0;
    return 0;
}

static void *xh_elf_packed_reloc_iterator_next(xh_elf_packed_reloc_iterator_t *self) {
    size_t val;

    if (self->relocation_index >= self->relocation_count) return NULL;

    if (self->relocation_group_index == self->group_size) {
        if (0 != xh_elf_packed_reloc_iterator_read_group_fields(self)) return NULL;
    }

    if (self->group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
        self->r_offset += self->group_r_offset_delta;
    } else {
        if (0 != xh_elf_sleb128_decoder_next(&(self->decoder), &val)) return NULL;
        self->r_offset += val;
    }

    if (0 == (self->group_flags & RELOCATION_GROUPED_BY_INFO_FLAG))
        if (0 != xh_elf_sleb128_decoder_next(&(self->decoder), &(self->r_info))) return NULL;

    if (self->is_use_rela &&
        (self->group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) &&
        (0 == (self->group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG))) {
        if (0 != xh_elf_sleb128_decoder_next(&(self->decoder), &val)) return NULL;
        self->r_addend += (ssize_t) val;
    }

    self->relocation_index++;
    self->relocation_group_index++;

    if (self->is_use_rela) {
        self->rela.r_offset = self->r_offset;
        self->rela.r_info = self->r_info;
        self->rela.r_addend = self->r_addend;
        return (void *) (&(self->rela));
    } else {
        self->rel.r_offset = self->r_offset;
        self->rel.r_info = self->r_info;
        return (void *) (&(self->rel));
    }
}


int xh_elf_hook(xh_elf_t *self, const char *symbol, void *new_func, void **old_func) {
    uint32_t symidx;
    void *rel_common;
    xh_elf_plain_reloc_iterator_t plain_iter;
    xh_elf_packed_reloc_iterator_t packed_iter;
    int found;
    int r;

    if (NULL == self->pathname) {
        XH_LOG_ERROR("not inited\n");
        return -1; //not inited?
    }

    if (NULL == symbol || NULL == new_func) return -1;

    XH_LOG_INFO("hooking %s in %s\n", symbol, self->pathname);

    //find symbol index by symbol name
    if (0 != (r = xh_elf_find_symidx_by_name(self, symbol, &symidx))) return 0;

    //replace for .rel(a).plt
    if (0 != self->relplt) {
        xh_elf_plain_reloc_iterator_init(&plain_iter, self->relplt, self->relplt_sz, self->is_use_rela);
        while (NULL != (rel_common = xh_elf_plain_reloc_iterator_next(&plain_iter))) {
            if (0 != (r = xh_elf_find_and_replace_func(self,
                                                       (self->is_use_rela ? ".rela.plt" : ".rel.plt"), 1,
                                                       symbol, new_func, old_func,
                                                       symidx, rel_common, &found)))
                return r;
            if (found) break;
        }
    }

    //replace for .rel(a).dyn
    if (0 != self->reldyn) {
        xh_elf_plain_reloc_iterator_init(&plain_iter, self->reldyn, self->reldyn_sz, self->is_use_rela);
        while (NULL != (rel_common = xh_elf_plain_reloc_iterator_next(&plain_iter))) {
            if (0 != (r = xh_elf_find_and_replace_func(self,
                                                       (self->is_use_rela ? ".rela.dyn" : ".rel.dyn"), 0,
                                                       symbol, new_func, old_func,
                                                       symidx, rel_common, NULL)))
                return r;
        }
    }

    //replace for .rel(a).android
    if (0 != self->relandroid) {
        xh_elf_packed_reloc_iterator_init(&packed_iter, self->relandroid, self->relandroid_sz, self->is_use_rela);
        while (NULL != (rel_common = xh_elf_packed_reloc_iterator_next(&packed_iter))) {
            if (0 != (r = xh_elf_find_and_replace_func(self,
                                                       (self->is_use_rela ? ".rela.android" : ".rel.android"), 0,
                                                       symbol, new_func, old_func,
                                                       symidx, rel_common, NULL)))
                return r;
        }
    }

    return 0;
}
