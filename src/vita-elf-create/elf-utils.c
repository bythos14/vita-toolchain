#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>

#include "utils/fail-utils.h"
#include "elf-utils.h"
#include "utils/varray.h"

typedef struct elf_utils_section_t {
	Elf_Scn *scn;
	GElf_Shdr shdr;
	GElf_Shdr shdr_o;
	int shndx;
} elf_utils_section_t;

typedef struct elf_utils_segment_t {
	int ndx;
	GElf_Phdr phdr_o; // Old Phdr, pre-shift
	GElf_Phdr phdr;   // New Phdr, Post-shift
} elf_utils_segment_t;

static int elf_utils_section_sort_compar(const void *el1, const void *el2)
{
	const elf_utils_section_t *s1 = el1, *s2 = el2;

	return s1->shdr.sh_offset - s2->shdr.sh_offset;
}
static int elf_utils_section_sort_compar_shndx(const void *el1, const void *el2)
{
	const elf_utils_section_t *s1 = el1, *s2 = el2;

	return s1->shndx - s2->shndx;
}

static int elf_utils_segment_sort_compar(const void *el1, const void *el2)
{
	const elf_utils_segment_t *s1 = el1, *s2 = el2;

	return s1->phdr.p_vaddr - s2->phdr.p_vaddr;
}

static varray *elf_utils_get_sections(Elf *e)
{
	varray *sections;
	size_t shnum = 0;
	elf_utils_section_t sect = {.scn = NULL};

	ELF_ASSERT((elf_getshdrnum(e, &shnum), shnum > 0));
	sections = varray_new(sizeof(elf_utils_section_t), shnum);
	sections->sort_compar = elf_utils_section_sort_compar;

	while ((sect.scn = elf_nextscn(e, sect.scn)) != NULL) {
		ELF_ASSERT((sect.shndx = elf_ndxscn(sect.scn)) != SHN_UNDEF);
		ELF_ASSERT(gelf_getshdr(sect.scn, &sect.shdr_o));
		memcpy(&sect.shdr, &sect.shdr_o, sizeof(sect.shdr_o));
		varray_push(sections, &sect);
	}
	varray_sort(sections);

	return sections;
failure:
	return NULL;
}

static varray *elf_utils_get_segments(Elf *e)
{
	varray *segments;
	size_t phnum = 0, segndx;
	elf_utils_segment_t seg = {.ndx = 0};

	/* A bug in libelf means that getphdrnum will report failure in a new file.
	 * However, it will still set segment_count, so we'll use it. */
	ELF_ASSERT((elf_getphdrnum(e, &phnum), phnum > 0));
	segments = varray_new(sizeof(elf_utils_segment_t), phnum);
	segments->sort_compar = elf_utils_segment_sort_compar;

	for (segndx = 0; segndx < phnum; segndx++) {
		seg.ndx = segndx;
		ELF_ASSERT(gelf_getphdr(e, segndx, &seg.phdr_o));
		memcpy(&seg.phdr, &seg.phdr_o, sizeof(seg.phdr_o));
		varray_push(segments, &seg);
	}

	varray_sort(segments);

	return segments;
failure:
	return NULL;
}

int elf_utils_copy(Elf *dest, Elf *source)
{
	GElf_Ehdr ehdr;
	Elf_Scn *dst_scn, *src_scn;
	GElf_Shdr shdr;
	Elf_Data *dst_data, *src_data;
	size_t segment_count, segndx, new_segndx;
	GElf_Phdr phdr;

	ELF_ASSERT(elf_flagelf(dest, ELF_C_SET, ELF_F_LAYOUT));

	ELF_ASSERT(gelf_getehdr(source, &ehdr));
	ELF_ASSERT(gelf_newehdr(dest, gelf_getclass(source)));
	ELF_ASSERT(gelf_update_ehdr(dest, &ehdr));

	src_scn = NULL;
	while ((src_scn = elf_nextscn(source, src_scn)) != NULL) {
		ELF_ASSERT(gelf_getshdr(src_scn, &shdr));
		ELF_ASSERT(dst_scn = elf_newscn(dest));
		ELF_ASSERT(gelf_update_shdr(dst_scn, &shdr));

		src_data = NULL;
		while ((src_data = elf_getdata(src_scn, src_data)) != NULL) {
			ELF_ASSERT(dst_data = elf_newdata(dst_scn));
			memcpy(dst_data, src_data, sizeof(Elf_Data));
		}
	}

	ELF_ASSERT(elf_getphdrnum(source, &segment_count) == 0);

	// only count PT_LOAD segments
	new_segndx = 0;
	for (segndx = 0; segndx < segment_count; segndx++) {
		ELF_ASSERT(gelf_getphdr(source, segndx, &phdr));
		if (phdr.p_type == PT_LOAD) {
			new_segndx++;
		}
	}
	ASSERT(new_segndx > 0);

	// copy PT_LOAD segments
	ELF_ASSERT(gelf_newphdr(dest, new_segndx));
	new_segndx = 0;
	for (segndx = 0; segndx < segment_count; segndx++) {
		ELF_ASSERT(gelf_getphdr(source, segndx, &phdr));
		if (phdr.p_type == PT_LOAD) {
			ELF_ASSERT(gelf_update_phdr(dest, new_segndx, &phdr));
			new_segndx++;
		}
	}
		
	return 1;
failure:
	return 0;
}

Elf *elf_utils_copy_to_file(const char *filename, Elf *source, FILE **file)
{
	Elf *dest = NULL;

	*file = fopen(filename, "wb");
	if (*file == NULL)
		FAIL("Could not open %s for writing", filename);


	ELF_ASSERT(elf_version(EV_CURRENT) != EV_NONE);
	ELF_ASSERT(dest = elf_begin(fileno(*file), ELF_C_WRITE, NULL));

	if (!elf_utils_copy(dest, source))
		goto failure;

	return dest;
failure:
	if (dest != NULL)
		elf_end(dest);
	return NULL;
}

int elf_utils_duplicate_scn_contents(Elf *e, int scndx)
{
	Elf_Scn *scn;
	Elf_Data *data;
	void *new_data;

	ELF_ASSERT(scn = elf_getscn(e, scndx));

	data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		ASSERT(new_data = malloc(data->d_size));
		memcpy(new_data, data->d_buf, data->d_size);
		data->d_buf = new_data;
	}
		
	return 1;
failure:
	return 0;
}

void elf_utils_free_scn_contents(Elf *e, int scndx)
{
	Elf_Scn *scn;
	Elf_Data *data;

	ELF_ASSERT(scn = elf_getscn(e, scndx));

	data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		free(data->d_buf);
		data->d_buf = NULL;
	}
		
failure:
	return;
}

int elf_utils_duplicate_shstrtab(Elf *e)
{
	size_t shstrndx;

	ELF_ASSERT(elf_getshdrstrndx(e, &shstrndx) == 0);

	return elf_utils_duplicate_scn_contents(e, shstrndx);
failure:
	return 0;
}

static int elf_utils_shift_syms(Elf *e, varray *sections, elf_utils_section_t *sym_sect)
{
	Elf_Data *data = NULL;
	size_t ndx, count;
	GElf_Sym sym;
	elf_utils_section_t *target_sect;

	while ((data = elf_getdata(sym_sect->scn, data)) != NULL) {
		count = data->d_size / sym_sect->shdr.sh_entsize;
		for (ndx = 0; ndx < count; ndx++) {
			ELF_ASSERT(gelf_getsym(data, ndx, &sym) != NULL);
			if ((sym.st_shndx == SHN_UNDEF) || (sym.st_shndx >= SHN_LORESERVE))
				continue;

			target_sect = VARRAY_ELEMENT(sections, sym.st_shndx - 1);
			if ((target_sect->shdr.sh_flags & SHF_ALLOC) == 0)
				continue;

			sym.st_value = target_sect->shdr.sh_addr + (sym.st_value - target_sect->shdr_o.sh_addr);
			ELF_ASSERT(gelf_update_sym(data, ndx, &sym));
		}
	}

	return 1;
failure:
	return 0;
}

static int elf_utils_shift_rels(Elf *e, elf_utils_section_t *rel_sect, elf_utils_section_t *target_sect)
{
	Elf_Data *data = NULL;
	size_t ndx, count;
	GElf_Rel rel;

	while ((data = elf_getdata(rel_sect->scn, data)) != NULL) {
		count = data->d_size / rel_sect->shdr.sh_entsize;
		for (ndx = 0; ndx < count; ndx++) {
			ELF_ASSERT(gelf_getrel(data, ndx, &rel) != NULL);
			rel.r_offset = target_sect->shdr.sh_addr + (rel.r_offset - target_sect->shdr_o.sh_addr);
			ELF_ASSERT(gelf_update_rel(data, ndx, &rel));
		}
	}

	return 1;
failure:
	return 0;
}

#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_VAL(align) ((align) > 0 ? (align) : 1)
int elf_utils_shift_contents(Elf *e, int start_offset, Elf32_Addr start_addr, int shift_amount)
{
	GElf_Ehdr ehdr;
	size_t segment_count = 0, segndx;
	int bottom_section_offset = 0;
	GElf_Xword sh_size;
	Elf32_Word shift_virt_amount = shift_amount, old_offset;
	Elf32_Addr old_addr;
	varray *sections, *segments;
	int shndx;
	elf_utils_section_t *sect, *target_sect;
	elf_utils_segment_t *seg, dummy_seg = {.phdr = {.p_vaddr = 0xFFFFFFFF, .p_offset = 0xFFFFFFFF, .p_filesz = 0, .p_memsz = 0}};
	
	if ((sections = elf_utils_get_sections(e)) == NULL) {
		FAILX("Failed to get sections");
	}
	
	if ((segments = elf_utils_get_segments(e)) == NULL) {
		FAILX("Failed to get segments");
	}

	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	if (ehdr.e_shoff >= start_offset) {
		ehdr.e_shoff += shift_amount;
		ELF_ASSERT(gelf_update_ehdr(e, &ehdr));
	}

	for (segndx = 0; segndx < segments->count; segndx++) {
		seg = VARRAY_ELEMENT(segments, segndx);
		if (seg->phdr.p_vaddr >= start_addr) {
			old_addr = seg->phdr.p_vaddr;
			seg->phdr.p_vaddr = ALIGN(seg->phdr.p_vaddr + shift_virt_amount, ALIGN_VAL(seg->phdr.p_align));
			shift_virt_amount += seg->phdr.p_vaddr - old_addr - shift_virt_amount;

			gelf_update_phdr(e, seg->ndx, &seg->phdr);
		}
	}

	seg = &dummy_seg; // Initial segment. Unconditionally out of bounds to force finding new segment initially
	for (shndx = 0; shndx < sections->count; shndx++) {
		sect = VARRAY_ELEMENT(sections, shndx);

		if (sect->shdr.sh_offset >= start_offset) {
			if ((sect->shdr.sh_flags & SHF_ALLOC) == 0) { // Not allocated, simple aligned shift.
				old_offset = sect->shdr.sh_offset;
				sect->shdr.sh_offset = ALIGN(sect->shdr.sh_offset + shift_amount, ALIGN_VAL(sect->shdr.sh_addralign));
				shift_amount += sect->shdr.sh_offset - old_offset - shift_amount;
			} else {
				/* For SHT_NOBITS sections, verify if the current segment has the section within its p_vaddr ->
				 * p_vaddr + p_memsz range, making it part of the segment*/
				if ((sect->shdr.sh_type == SHT_NOBITS) && 
					(((sect->shdr.sh_addr + sect->shdr.sh_size) <= seg->phdr.p_vaddr) || 
					(sect->shdr.sh_addr >= (seg->phdr.p_vaddr + seg->phdr.p_memsz)))) {
					for (segndx = 0; segndx < segments->count; segndx++) {
						seg = VARRAY_ELEMENT(segments, segndx);
						if ((sect->shdr.sh_addr >= seg->phdr.p_vaddr) && 
							(sect->shdr.sh_addr + sect->shdr.sh_size) <= (seg->phdr.p_vaddr + seg->phdr.p_memsz)) {
							// Fully within the segment
							old_offset = seg->phdr.p_offset;
							seg->phdr.p_offset = ALIGN(seg->phdr.p_offset + shift_amount, ALIGN_VAL(seg->phdr.p_align));
							shift_amount += seg->phdr.p_offset - old_offset - shift_amount;

							gelf_update_phdr(e, seg->ndx, &seg->phdr);
							break;
						}
					}

					/* For non SHT_NOBITS sections, verify if the current segment has the section within its p_offset ->
					 * p_offset + p_filesz range, making it part of the segment*/
				} else if ((sect->shdr.sh_type != SHT_NOBITS) && 
					(((sect->shdr.sh_offset + sect->shdr.sh_size) <= seg->phdr.p_offset) || 
					(sect->shdr.sh_offset >= (seg->phdr.p_offset + seg->phdr.p_filesz)))) {
					for (segndx = 0; segndx < segments->count; segndx++) {
						seg = VARRAY_ELEMENT(segments, segndx);
						if ((sect->shdr.sh_offset >= seg->phdr.p_offset) && 
							(sect->shdr.sh_offset + sect->shdr.sh_size) <= (seg->phdr.p_offset + seg->phdr.p_filesz)) {
							// Fully within the segment
							old_offset = seg->phdr.p_offset;
							seg->phdr.p_offset = ALIGN(seg->phdr.p_offset + shift_amount, ALIGN_VAL(seg->phdr.p_align));
							shift_amount += seg->phdr.p_offset - old_offset - shift_amount;

							gelf_update_phdr(e, seg->ndx, &seg->phdr);
							break;
						}
					}
				}

				if (segndx == segment_count) {
					FAILX("SHF_ALLOC set on section, but no segment found containing");
				}
				sect->shdr.sh_offset += shift_amount;
				sect->shdr.sh_addr += (seg->phdr.p_vaddr - seg->phdr_o.p_vaddr);
			}

			sh_size = (sect->shdr.sh_type == SHT_NOBITS) ? 0 : sect->shdr.sh_size;
			if (sect->shdr.sh_offset + sh_size > bottom_section_offset) {
				bottom_section_offset = sect->shdr.sh_offset + sh_size;
			}

			ELF_ASSERT(gelf_update_shdr(sect->scn, &sect->shdr));
		}
	}

	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	if (bottom_section_offset > ehdr.e_shoff) {
		ehdr.e_shoff = bottom_section_offset;
		ELF_ASSERT(gelf_update_ehdr(e, &ehdr));
	}

	sections->sort_compar = elf_utils_section_sort_compar_shndx;
	varray_sort(sections);
	for (shndx = 0; shndx < sections->count; shndx++) {
		sect = VARRAY_ELEMENT(sections, shndx);
		if (sect->shdr.sh_type == SHT_REL) {
			if (sect->shdr.sh_info == SHN_UNDEF)
				continue;

			target_sect = VARRAY_ELEMENT(sections, sect->shdr.sh_info - 1);
			elf_utils_shift_rels(e, sect, target_sect);
		} else if (sect->shdr.sh_type == SHT_SYMTAB) {
			elf_utils_shift_syms(e, sections, sect);
		}
	}

exit:
	varray_free(sections);
	varray_free(segments);
	
	return 1;
failure:
	if (segments != NULL) {
		varray_free(segments);
	}
	if (sections != NULL) {
		varray_free(sections);
	}

	return 0;
}
#undef ALIGN
#undef ALIGN_VAL

Elf_Scn *elf_utils_new_scn_with_name(Elf *e, const char *scn_name)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t shstrndx, index, namelen;
	Elf_Data *shstrdata;
	void *ptr;

	ELF_ASSERT(elf_getshdrstrndx(e, &shstrndx) == 0);

	ELF_ASSERT(scn = elf_getscn(e, shstrndx));
	ELF_ASSERT(shstrdata = elf_getdata(scn, NULL));

	namelen = strlen(scn_name) + 1;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	if (!elf_utils_shift_contents(e, shdr.sh_offset + shdr.sh_size, 0xFFFFFFFF, namelen))
		goto failure;
	ASSERT(ptr = realloc(shstrdata->d_buf, shstrdata->d_size + namelen));
	index = shstrdata->d_size;
	strcpy(ptr+index, scn_name);
	shstrdata->d_buf = ptr;
	shstrdata->d_size += namelen;
	shdr.sh_size += namelen;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	ELF_ASSERT(scn = elf_newscn(e));
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_name = index;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));
	
	return scn;
failure:
	return NULL;
}

Elf_Scn *elf_utils_new_scn_with_data(Elf *e, const char *scn_name, void *buf, int len)
{
	Elf_Scn *scn;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Data *data;
	int offset;

	scn = elf_utils_new_scn_with_name(e, scn_name);
	if (scn == NULL)
		goto failure;

	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	offset = ehdr.e_shoff;
	if (!elf_utils_shift_contents(e, offset, 0xFFFFFFFF, len + 0x10))
		goto failure;

	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_offset = (offset + 0x10) & ~0xF;
	shdr.sh_size = len;
	shdr.sh_addralign = 1;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	ELF_ASSERT(data = elf_newdata(scn));
	data->d_buf = buf;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	data->d_size = len;
	data->d_off = 0;
	data->d_align = 1;

	return scn;
failure:
	return NULL;
}
