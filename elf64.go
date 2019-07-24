// +build linux,amd64 !cgo

package plugin

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

const (
	ET_REL uint16 = 1 //Relocatable object file
	ET_DYN uint16 = 3 //SharedObject file

	amd64Arch uint16 = uint16(elf.EM_X86_64)

	symSize = 24
	relSize = 24
)

var (
	elfIdent = [elf.EI_NIDENT]byte{0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	ErrInvalidFileType = errors.New("invalid filetype, only ELF64 supported")
	ErrInvalidArch     = errors.New("invalid architecture, only AMD64 supported")
)

type mm struct {
	regionMap
	vaddr uintptr
	memsz uintptr
	prot  uintptr
}

// check that we are an ELF64 shared object file built for Linux
func checkArch(f *elf.File) error {
	if f.Type != elf.ET_DYN {
		return errors.New("file is not a shared object")
	}
	if f.Class != elf.ELFCLASS64 {
		return fmt.Errorf("SharedObject is not an ELF64 binary")
	}
	if f.Machine != elf.EM_X86_64 {
		return fmt.Errorf("SharedObject has wrong machine type: %s != %s", f.Machine.String(), elf.EM_X86_64.String())
	}
	if f.ByteOrder != binary.LittleEndian {
		return errors.New("SharedObject has the wrong endianness")
	}
	if f.OSABI != elf.ELFOSABI_NONE {
		//GOLANG without Cbindings is of non type
		return errors.New("SharedObject is not a golang SharedObject")
	}
	return nil
}

// checkForImports ensures that the ELF file does not call for other libraries or external symbols
func checkForImports(f *elf.File) (err error) {
	var importLibs []string
	var importSymbols []elf.ImportedSymbol

	if importLibs, err = f.ImportedLibraries(); err != nil {
		return
	} else if len(importLibs) > 0 {
		err = errors.New("SharedObject file contains library imports")
		return
	}

	if importSymbols, err = f.ImportedSymbols(); err != nil {
		return
	} else if len(importSymbols) > 0 {
		err = errors.New("SharedObject contains impmort symbols")
	}

	return
}

func checkGoVersion(f *elf.File) (err error) {
	//TODO
	return
}

// loadElf64Header reads in the ELF64 header and validates that the described offsets
// are all within the mapped memory region
func loadHeader64(buff []byte) (h elf.Header64, err error) {
	//actually read the header
	if err = binary.Read(bytes.NewBuffer(buff), binary.LittleEndian, &h); err != nil {
		return
	}
	if !bytes.Equal(elfIdent[:], h.Ident[:]) || h.Type != ET_DYN {
		err = ErrInvalidFileType
	} else if h.Machine != amd64Arch {
		err = ErrInvalidArch
	} else if int(h.Ehsize) >= len(buff) {
		err = errors.New("ELF64 header extends past library size")
	} else if h.Flags != 0 { //it appears all golang library binaries do not have any architecture specific flags
		err = errors.New("Unknown architecture specific flags")
	}
	err = validateElf64HeaderOffsets(h, buff)
	return
}

// validateElf64HeaderOffsets just sweeps through the header and ensures that all the
// offsets and sizes will actually end up in the mapped buffer
func validateElf64HeaderOffsets(h elf.Header64, buff []byte) error {
	var hdrend uint64
	bsz := uint64(len(buff))
	//check entrypoint address
	if h.Entry >= bsz {
		return fmt.Errorf("EntryPoint points outside the library: %x > %x", h.Entry, bsz)
	}
	//check program header
	if hdrend = h.Phoff; hdrend >= bsz {
		return fmt.Errorf("ProgramHeader points outside the library: %x > %x", h.Phoff, bsz)
	}
	if hdrend += uint64(h.Phentsize) * uint64(h.Phnum); hdrend >= bsz {
		return fmt.Errorf("ProgramHeader extends past the library: %x > %x", hdrend, bsz)
	}

	//check the section header
	if hdrend = h.Shoff; hdrend >= bsz {
		return fmt.Errorf("SectionHeader points outside the library: %x > %x", h.Shoff, bsz)
	}
	if hdrend += uint64(h.Shentsize) * uint64(h.Shnum); hdrend >= bsz {
		return fmt.Errorf("ProgramHeader extends past the library: %x > %x", hdrend, bsz)
	}

	//check that the section name strings section is valid
	if h.Shstrndx >= h.Shnum {
		return fmt.Errorf("Section name string index is invalid: %x > %x", h.Shstrndx, h.Shnum)
	}
	return nil
}

func checkSections(f *elf.File) (err error) {
	for _, s := range f.Sections {
		if err = checkSectionFlags(uint64(s.Flags)); err != nil {
			break
		}
	}
	return
}

// setPermissions reads the sections from the file buffer then sets the appropriate
// permission bits on each memory region
func setPermissions(mms []mm) (err error) {
	//first we set all memory regions to read only
	for _, v := range mms {
		if err = v.setPerms(v.prot); err != nil {
			return
		}
	}
	return
}

// checkElf64SectionsForImports swings through the section headers to make sure we do
// not have any imports.  This is basically to ensure the incoming library doesn't
// expect CGO.  The golang compiler seems to like to generate an import section
// even when CGO is disabled, it is just empty
func checkElf64SectionsForImports(h elf.Header64, buff []byte) (err error) {
	var sect elf.Section64
	if uintptr(h.Shentsize) != unsafe.Sizeof(sect) {
		err = fmt.Errorf("invalid section header entry size: %d != %d", h.Shentsize, unsafe.Sizeof(sect))
		return
	}
	shdrListSize := uint64(h.Shnum * h.Shentsize)
	if uint64(len(buff)) <= (h.Shoff + shdrListSize) {
		err = fmt.Errorf("Invalid section headers")
		return
	}
	for i := uint16(0); i < h.Shnum; i++ {
		if sect, err = readSection(i, h, buff); err != nil {
			return
		}
		if sect.Type == uint32(elf.SHT_DYNAMIC) {
			//check if it actually imports anything
			if err = checkImports(sect, buff); err != nil {
				return
			}
		} else if err = checkSectionFlags(sect.Flags); err != nil {
			return
		}
		/* DEBUG
		if name, err := lookupSectionString(sect.Name, h, buff); err == nil {
			fmt.Printf("%s %+v\n", name, sect)
		}
		*/
	}
	return
}

// readSection takes an index and reads the section64 data out
// we should have already validated that the section index is valid
func readSection(idx uint16, h elf.Header64, buff []byte) (sect elf.Section64, err error) {
	off := h.Shoff + uint64(idx)*uint64(h.Shentsize)
	if idx > h.Shnum || (off+uint64(h.Shentsize)) > uint64(len(buff)) {
		err = errors.New("invalid section index")
		return
	}
	err = binary.Read(bytes.NewBuffer(buff[off:]), binary.LittleEndian, &sect)
	return
}

// readProgramSection takes an index and reads the Prog64 data out
// we should have already validated that the section index is valid
func readProgramSection(idx uint16, h elf.Header64, buff []byte) (p elf.Prog64, err error) {
	off := h.Phoff + uint64(idx)*uint64(h.Phentsize)
	if idx > h.Phnum || (off+uint64(h.Phentsize)) > uint64(len(buff)) {
		err = errors.New("invalid program section index")
		return
	}
	err = binary.Read(bytes.NewBuffer(buff[off:]), binary.LittleEndian, &p)
	return
}

func readSymbol(b []byte) (s elf.Sym64, err error) {
	if len(b) < symSize {
		err = errors.New("Buffer is too small for a Sym64")
	} else {
		err = binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &s)
	}
	return
}

// checkImports is a debug implementation, we use the stddlib debug/elf package instead
func checkImports(sect elf.Section64, buff []byte) (err error) {
	if (sect.Off + sect.Size) > uint64(len(buff)) {
		err = fmt.Errorf("Import section is invalid: %d > %d", sect.Off+sect.Size, len(buff))
		return
	} else if sect.Size%16 != 0 {
		err = fmt.Errorf("Import section is misaligned %d", sect.Size)
		return
	}
	buff = buff[sect.Off : sect.Off+sect.Size]
	for i := 0; i < len(buff); i += 16 {
		if binary.LittleEndian.Uint64(buff[i:]) == uint64(elf.DT_NEEDED) {
			err = errors.New("Library requires imports")
		}
	}
	return
}

// checkSectionFlags just rips through the flags and makes sure we don't have anything we don't know how to deal with
func checkSectionFlags(flags uint64) error {
	if (flags & uint64(elf.SHF_OS_NONCONFORMING)) != 0 {
		return errors.New("Cannot import library with OS_NONCONFORMING section flags")
	} else if (flags & uint64(elf.SHF_LINK_ORDER)) != 0 {
		return errors.New("Cannot import library with LINK_ORDER section flags")
	} else if (flags & uint64(elf.SHF_COMPRESSED)) != 0 {
		return errors.New("Cannot import library with COMPRESSED section flags")
	}
	return nil
}

// loadProgramSections allocates memory maps for each of the program sections and does the work of
// actually copying from the ELF file to the allocated memory regions
func loadProgramSections(buff []byte, h elf.Header64) (mms []mm, err error) {
	for i := uint64(0); i < uint64(h.Phnum); i++ {
		var ps elf.Prog64
		var rm regionMap
		off := h.Phoff + i*uint64(h.Phentsize)
		if err = binary.Read(bytes.NewBuffer(buff[off:]), binary.LittleEndian, &ps); err != nil {
			mms = closeMaps(mms)
			return
		}
		if (ps.Off + ps.Filesz) > uint64(len(buff)) {
			err = fmt.Errorf("ProgramSection extends outside the file buffer: %d > %d",
				ps.Off+ps.Filesz, len(buff))
			mms = closeMaps(mms)
			return
		}
		if ps.Filesz == 0 && ps.Memsz == 0 {
			//add in the empty region maps, but don't attempt to allocate
			var m mm
			mms = append(mms, m)
			continue
		}
		if rm, err = newRegion(uintptr(ps.Vaddr), uintptr(ps.Memsz)); err != nil {
			mms = closeMaps(mms)
			return
		}
		copy(rm.buff, buff[ps.Off:ps.Off+ps.Filesz])
		m := mm{
			regionMap: rm,
			vaddr:     uintptr(ps.Vaddr),
			memsz:     uintptr(ps.Memsz),
			prot:      translateProtectFlags(uint32(ps.Flags)),
		}
		mms = append(mms, m)
	}
	return
}

type mappedSection struct {
	buff  []byte
	vaddr uintptr
	memsz uintptr
	tp    uint32
	link  uint32
	idx   int
}

func loadSections(mms []mm, h elf.Header64, buff []byte) (sects []elf.Section64, err error) {
	for i := uint64(0); i < uint64(h.Shnum); i++ {
		var sect elf.Section64
		off := h.Shoff + i*uint64(h.Shentsize)
		if err = binary.Read(bytes.NewBuffer(buff[off:]), binary.LittleEndian, &sect); err != nil {
			return
		}
		if (sect.Off + sect.Size) > uint64(len(buff)) {
			err = fmt.Errorf("Section extends outside the file buffer: %d > %d",
				sect.Off+sect.Size, len(buff))
			return
		}
		sects = append(sects, sect)
	}
	if len(sects) == 0 {
		err = errors.New("no sections loaded")
	}
	return
}

func mapSections(mms []mm, sects []elf.Section64, tps ...uint32) (tabs []mappedSection, err error) {
	if len(tps) == 0 || len(sects) == 0 {
		err = errors.New("Invalid arguments")
		return
	}
	for i, sect := range sects {
		var m mm
		for _, tp := range tps {
			if tp == sect.Type {
				if m, err = findAssignedRegionMap(mms, uintptr(sect.Addr), uintptr(sect.Size)); err != nil {
					return
				}
				//check that we can get a buff
				off := uintptr(sect.Addr) - m.vaddr
				ms := mappedSection{
					buff:  m.buff[off : off+uintptr(sect.Size)],
					vaddr: uintptr(sect.Addr),
					memsz: uintptr(sect.Size),
					tp:    uint32(sect.Type),
					link:  uint32(sect.Link),
					idx:   i,
				}
				tabs = append(tabs, ms)
				break
			}
		}
	}
	if len(tabs) == 0 {
		err = errors.New("Failed to find specified sections")
	}
	return
}

//performRelocations finds the relocation table and peforms all the needed relocations
func (s *elf64SharedObject) performRelocations(relocs []mappedSection) (err error) {
	for _, rtab := range relocs {
		if rtab.tp == uint32(elf.SHT_RELA) {
			if err = s.performAddendRelocations(rtab.buff); err != nil {
				return
			}
		} else if rtab.tp == uint32(elf.SHT_REL) {
			if err = s.performNoAddendsRelocations(rtab.buff); err != nil {
				return
			}
		}
		/* DEBUG
		if name, err := lookupSectionString(sect.Name, h, buff); err == nil {
			fmt.Printf("%s %+v\n", name, sect)
		}
		*/
	}
	return
}

func (s *elf64SharedObject) lookupSymbol(idx uint32) (sym elf.Sym64, err error) {
	off := int(idx * symSize)
	if s == nil || s.symtab.buff == nil {
		err = errors.New("SharedObject is not valid")
	} else if int(off+symSize) > len(s.symtab.buff) {
		//check the symbol index against the buffer size
		err = errors.New("Invalid symbol value")
	} else {
		sym, err = readSymbol(s.symtab.buff[off:])
	}
	return
}

type rel64 struct {
	off  uint64
	info uint64
}

type rela64 struct {
	rel64
	addend int64
}

func (r rel64) Symbol() uint32 {
	return uint32(r.info >> 32)
}

func (r rel64) Type() uint32 {
	return uint32(r.info & 0xFFFFFFFF)
}

func (s *elf64SharedObject) performAddendRelocations(buff []byte) (err error) {
	for len(buff) >= relSize {
		rel := rela64{
			rel64: rel64{
				off:  binary.LittleEndian.Uint64(buff),
				info: binary.LittleEndian.Uint64(buff[8:]),
			},
			addend: int64(binary.LittleEndian.Uint64(buff[16:])),
		}
		if err = s.doAddendRelocation(rel); err != nil {
			break
		}
		buff = buff[relSize:]
	}
	return
}

func (s *elf64SharedObject) doAddendRelocation(rel rela64) (err error) {
	var sym elf.Sym64
	if elf.R_X86_64(rel.Type()) == elf.R_X86_64_NONE {
		return
	}
	if sym, err = s.lookupSymbol(rel.Symbol()); err != nil {
		return
	}
	tp := elf.R_X86_64(rel.Type())
	switch tp {
	case elf.R_X86_64_64: //add 64bit symbol value
		var symval uintptr
		var relptr uintptr
		/*
			if sym.Size != 8 {
				err = fmt.Errorf("Invalid symbol size for relocation type %s %x", tp, sym.Size)
				return
			}
		*/
		if relptr, err = translatePointer(s.mms, uintptr(rel.off), 8); err != nil {
			return
		}
		if symval, err = translatePointer(s.mms, uintptr(sym.Value), 8); err != nil {
			return
		}
		val := *(*uint64)(unsafe.Pointer(symval))
		if n, lerr := s.lookupSymbolName(sym); lerr == nil {
			if n == `type..rAGIN0DE` {
				fmt.Printf("%s %s %x %x + %x %x %+v\n", n, tp, relptr, symval, rel.addend, val, sym)
			}
		}
		*(*uint64)(unsafe.Pointer(relptr)) = uint64(int64(val) + rel.addend)
	case elf.R_X86_64_RELATIVE: // add load address of shared object
		var relptr uintptr
		var rm mm
		if relptr, err = translatePointer(s.mms, uintptr(rel.off), 8); err != nil {
			return
		}
		if rm, err = findAssignedRegionMap(s.mms, uintptr(rel.off), 8); err != nil {
			return
		}
		*(*uint64)(unsafe.Pointer(relptr)) = uint64(int64(rm.base) + rel.addend)
	case elf.R_X86_64_GLOB_DAT: // set GOT entry to data address
	case elf.R_X86_64_JMP_SLOT: // set GOT entry to code address
	case elf.R_X86_64_TPOFF64: // offset in static TLS block
	default:
		err = fmt.Errorf("Unknown relocation type(%x)", rel.Type())
	}
	return
}

// haven't seen this come out of the golang compiler...
func (s *elf64SharedObject) performNoAddendsRelocations(buff []byte) (err error) {
	for len(buff) >= 16 {
		rel := rel64{
			off:  binary.LittleEndian.Uint64(buff),
			info: binary.LittleEndian.Uint64(buff[8:]),
		}
		if err = s.doRelocation(rel); err != nil {
			break
		}
		buff = buff[16:]
	}
	return
}

func (s *elf64SharedObject) doRelocation(rel rel64) (err error) {
	switch elf.R_X86_64(rel.Type()) {
	case elf.R_X86_64_NONE:
		//DO nothing
	default:
		err = fmt.Errorf("Unknown relocation type(%x)", rel.Type())
	}
	return
}

func lookupSectionString(start uint32, h elf.Header64, buff []byte) (s string, err error) {
	var sect elf.Section64
	if sect, err = readSection(h.Shstrndx, h, buff); err != nil {
		return
	}
	//readSection validates the section offsets for us
	buff = buff[sect.Off : sect.Off+sect.Size]
	if start > uint32(len(buff)) {
		err = errors.New("invalid string index")
	} else {
		for end := start; end < uint32(len(buff)); end++ {
			if buff[end] == 0 {
				s = string(buff[start:end])
				break
			}
		}
	}
	return
}

func findAssignedRegionMap(mms []mm, base, sz uintptr) (rm mm, err error) {
	end := uintptr(base + sz)
	for _, m := range mms {
		if base >= m.vaddr && end <= (m.vaddr+m.memsz) {
			rm = m
			return
		}
	}
	err = fmt.Errorf("Cannot find %x:%x in mapped regions", base, end)
	return
}

func translatePointer(mms []mm, base, sz uintptr) (p uintptr, err error) {
	var m mm
	if m, err = findAssignedRegionMap(mms, base, sz); err != nil {
		return
	}
	off := base - m.vaddr
	p = uintptr(unsafe.Pointer(&m.buff[off]))
	return
}

func closeMaps(mms []mm) []mm {
	for _, v := range mms {
		v.close()
	}
	return nil
}

const (
	pfr uint32 = 0x4
	pfw uint32 = 0x2
	pfx uint32 = 0x1
)

// translate the section protection flags to something we can pass to mprotect
func translateProtectFlags(flgs uint32) (r uintptr) {
	if (flgs & pfx) == pfx {
		r |= ProtX
	}
	if (flgs & pfw) == pfw {
		r |= ProtWO
	}
	if (flgs & pfr) == pfr {
		r |= ProtRO
	}
	return
}
