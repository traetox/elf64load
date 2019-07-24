// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64,!cgo

package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

type goDlopen struct {
	elf64SharedObject
}

// libPath turns the name into an absolute path and ensures its a regular file
// we do it the go way here
func libPath(name string) (s string, err error) {
	if s, err = filepath.Abs(name); err == nil {
		if s, err = filepath.EvalSymlinks(s); err == nil {
			var fi os.FileInfo
			if fi, err = os.Stat(s); err == nil {
				if !fi.Mode().IsRegular() {
					err = errors.New("path is not a file")
				}
			}
		}
	}
	return
}

// openLib does dlopen like functions to load a library, resolve the imports, etc..
// this implementation use the PURE go version
func openLib(name string) (dlopen, error) {
	p, err := libPath(name)
	if err != nil {
		return nil, err
	}
	s, err := elf64load(p)
	if err != nil {
		return nil, err
	}
	do := &goDlopen{
		elf64SharedObject: s,
	}
	test(do)
	return do, nil
}

func (do *goDlopen) lookup(v string) (uintptr, error) {
	sym, err := do.elf64SharedObject.lookup(v)
	if err != nil {
		return 0, err
	}
	if sym.Shndx == 0 || sym.Shndx >= 0xff00 {
		return 0, errors.New("Unknown symbol type")
	}
	fmt.Printf("%s %x %+v\n", v, sym.Shndx, sym)
	return translatePointer(do.mms, uintptr(sym.Value), 1)
}

func test(do *goDlopen) {
	tgt := `type..rAGIN0DE`
	if ptr, err := do.lookup(tgt); err == nil {
		fmt.Printf("lookup on pure go: %x\n", ptr)
		fmt.Printf("value: %x\n", *(*uintptr)(unsafe.Pointer(ptr)))
		time.Sleep(10 * time.Second)
	} else {
		fmt.Println("ERROR", err)
	}
}
