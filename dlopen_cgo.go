// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,cgo darwin,cgo

package plugin

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>

#include <stdio.h>

static uintptr_t pluginOpen(const char* path, char** err) {
	void* h = dlopen(path, RTLD_NOW|RTLD_GLOBAL);
	if (h == NULL) {
		*err = (char*)dlerror();
	}
	return (uintptr_t)h;
}

static void* pluginLookup(uintptr_t h, const char* name, char** err) {
	void* r = dlsym((void*)h, name);
	if (r == NULL) {
		*err = (char*)dlerror();
	}
	return r;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

type cgoDlopen struct {
	h C.uintptr_t
}

func libPath(name string) (s string, err error) {
	cPath := make([]byte, C.PATH_MAX+1)
	cRelName := make([]byte, len(name)+1)
	copy(cRelName, name)
	if C.realpath((*C.char)(unsafe.Pointer(&cRelName[0])), (*C.char)(unsafe.Pointer(&cPath[0]))) == nil {
		err = errors.New(`plugin.Open("` + name + `"): realpath failed`)
	} else {
		s = C.GoString((*C.char)(unsafe.Pointer(&cPath[0])))
	}

	return
}

func openLib(name string) (dlopen, error) {
	cPath := make([]byte, C.PATH_MAX+1)
	cRelName := make([]byte, len(name)+1)
	copy(cRelName, name)
	if C.realpath((*C.char)(unsafe.Pointer(&cRelName[0])), (*C.char)(unsafe.Pointer(&cPath[0]))) == nil {
		return nil, errors.New(`plugin.Open("` + name + `"): realpath failed`)
	}
	var cErr *C.char
	h := C.pluginOpen((*C.char)(unsafe.Pointer(&cPath[0])), &cErr)
	if h == 0 {
		return nil, errors.New(`plugin.Open("` + name + `"): ` + C.GoString(cErr))
	}
	do := &cgoDlopen{
		h: h,
	}
	test(do)
	return do, nil
}

func (do *cgoDlopen) lookup(pth string) (uintptr, error) {
	var cErr *C.char
	cname := make([]byte, len(pth)+1)
	copy(cname, pth)
	if p := C.pluginLookup(do.h, (*C.char)(unsafe.Pointer(&cname[0])), &cErr); p != nil {
		return uintptr(p), nil
	}
	return 0, errors.New(C.GoString(cErr))
}

func test(do *cgoDlopen) {
	tgt := `type..rAGIN0DE`
	if ptr, err := do.lookup(tgt); err == nil {
		fmt.Printf("lookup on cgo: %x\n", ptr)
		fmt.Printf("value: %x\n", *(*uintptr)(unsafe.Pointer(ptr)))
		time.Sleep(10 * time.Second)
	}
}
