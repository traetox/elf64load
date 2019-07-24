// +build linux,amd64 !cgo

package plugin

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	pkgSep        string = `.`
	pluginPrefix  string = `plugin/`
	pkgNamePrefix string = `go.link.pkghashbytes.plugin/`
)

var ()

type elf64SharedObject struct {
	pkgName string
	hdr     elf.Header64
	mms     []mm

	//the symtabs and stringtabs are just references to the mapped regions
	// when we close they point to invalid memory
	symtab     mappedSection
	stringtabs []mappedSection

	sections []elf.Section64
}

// elf64load loads an ELF shared library file into memory and performs validation on the headers
// we will perform relocations and set the permission bits appriopriately on each section
// This implementation of DLoad WILL NOT link imports in the library, if the library has any imports
// we will return an error.  Staticly compiled libraries ONLY
func elf64load(p string) (s elf64SharedObject, err error) {
	var f fileMap
	var elfio *elf.File
	if f, err = newFileMap(p); err != nil {
		return
	}
	if elfio, err = elf.NewFile(f); err != nil {
		f.close()
		return
	}
	//validate that the ELF file meets our expectations
	if err = checkArch(elfio); err != nil {
		elfio.Close()
		f.close()
		return
	} else if err = checkForImports(elfio); err != nil {
		elfio.Close()
		f.close()
		return
	} else if err = checkSections(elfio); err != nil {
		elfio.Close()
		f.close()
		return
	}
	if err = checkGoVersion(elfio); err != nil {
		elfio.Close()
		f.close()
		return
	}
	if err = elfio.Close(); err != nil {
		f.close()
		return
	}

	//load and validate our elf64 header
	if s.hdr, err = loadHeader64(f.buff); err != nil {
		f.close()
		return
	}
	//load the program regions
	if s.mms, err = loadProgramSections(f.buff, s.hdr); err != nil {
		f.close()
		return
	}

	if s.sections, err = loadSections(s.mms, s.hdr, f.buff); err != nil {
		f.close()
		s.Close()
		return
	}

	//Close our file map, it is no longer needed
	if err = f.close(); err != nil {
		return
	}

	//get the symbol table
	var tabs []mappedSection
	if tabs, err = mapSections(s.mms, s.sections, uint32(elf.SHT_DYNSYM)); err == nil {
		if len(tabs) != 1 {
			err = errors.New("multiple symbol tables")
		} else {
			s.symtab = tabs[0]
		}
	}
	if err != nil {
		s.Close()
		f.close()
		return
	}

	//get the symbol table
	if s.stringtabs, err = mapSections(s.mms, s.sections, uint32(elf.SHT_STRTAB)); err != nil {
		s.Close()
		f.close()
		return
	}

	//get the relocation tables
	var relocs []mappedSection
	if relocs, err = mapSections(s.mms, s.sections, uint32(elf.SHT_RELA), uint32(elf.SHT_REL)); err != nil {
		s.Close()
		f.close()
		return
	}

	//perform relocations
	if err = s.performRelocations(relocs); err != nil {
		s.Close()
		return
	}

	//location package name via the symbol table
	if s.pkgName, err = s.identifyPluginName(); err != nil {
		s.Close()
		f.close()
		return
	}

	//set the permissions on the memory regions
	if err = setPermissions(s.mms); err != nil {
		s.Close()
		return
	}
	return
}

func (s *elf64SharedObject) lookup(v string) (ret elf.Sym64, err error) {
	//tgtName := pluginPrefix+s.pkgName+pkgSep+v
	tgtName := v

	err = s.symbolWalk(func(nm string, sym elf.Sym64, sect elf.Section64) (lerr error) {
		if nm == tgtName {
			lerr = io.EOF //return EOF to get the walk to stop
			ret = sym
		}
		return
	})
	if err == nil {
		err = errors.New("Symbol not found")
	} else if err == io.EOF {
		err = nil
	}
	return
}

func (s *elf64SharedObject) identifyPluginName() (r string, err error) {
	var found bool
	err = s.symbolWalk(func(nm string, sym elf.Sym64, sect elf.Section64) (lerr error) {
		if elf.ST_TYPE(sym.Info) != elf.STT_OBJECT {
			return
		}
		if ((sym.Value - sect.Addr) + sym.Size) > sect.Size {
			fmt.Printf("%s symbol points outside section %d %+v\n", nm, sect.Size, sym)
			lerr = errors.New("symbol points outside section")
		} else if strings.HasPrefix(nm, pkgNamePrefix) {
			r = strings.TrimPrefix(nm, pkgNamePrefix)
			found = true
			lerr = io.EOF
		}
		return
	})
	if err == io.EOF {
		err = nil
	} else if err == nil && !found {
		err = errors.New("packagename not found")
	}
	return

}

type symbolCallback func(string, elf.Sym64, elf.Section64) error

func (s *elf64SharedObject) symbolWalk(cb symbolCallback) (err error) {
	if s.mms == nil {
		err = errors.New("elf64SharedObject not loaded")
		return
	} else if cb == nil {
		err = errors.New("Invalid callback")
		return
	}
	strtab, ok := s.linkedStringTable(s.symtab.idx)
	if !ok {
		err = errors.New("no string table linked to symbol table")
		return
	}

	//swing through the symbol table looking looking for strings that match
	var sym elf.Sym64
	var str string
	for off := 0; (off + symSize) <= len(s.symtab.buff); off += symSize {
		if sym, err = readSymbol(s.symtab.buff[off:]); err != nil {
			return
		} else if sym.Shndx == 0 {
			continue
		} else if int(sym.Shndx) >= len(s.sections) {
			err = errors.New("symbol points outside our section table")
			return
		} else if str, err = s.getString(strtab, sym.Name); err != nil {
			return
		}

		if err = cb(str, sym, s.sections[sym.Shndx]); err != nil {
			return
		}
	}
	return
}

func (s *elf64SharedObject) lookupSymbolName(sym elf.Sym64) (n string, err error) {
	strtab, ok := s.linkedStringTable(s.symtab.idx)
	if ok {
		n, err = s.getString(strtab, sym.Name)
	} else {
		err = errors.New("no string table linked to symbol table")
	}
	return
}

func (s *elf64SharedObject) linkedStringTable(idx int) (ms mappedSection, ok bool) {
	for _, tab := range s.stringtabs {
		if tab.idx-1 == idx {
			ms = tab
			ok = true
		}
	}
	return
}

func (s *elf64SharedObject) getString(ms mappedSection, stroff uint32) (r string, err error) {
	//now get the string
	if stroff >= uint32(len(ms.buff)) {
		err = errors.New("INvalid string offset")
		return
	}
	var e uint32
	for e = stroff; e < uint32(len(ms.buff)); e++ {
		if ms.buff[e] == 0 {
			break
		}
	}
	r = string(ms.buff[stroff:e])
	return
}

func (s *elf64SharedObject) Close() (err error) {
	if s == nil {
		return errors.New("not open")
	}
	for _, mm := range s.mms {
		if lerr := mm.close(); lerr != nil {
			err = lerr
		}
	}
	return
}
