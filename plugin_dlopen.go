// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,cgo darwin,cgo linux,!cgo,amd64

package plugin

import (
	"errors"
	"fmt"
	_ "plugin" // this is a hack to get the runtime to build up an internal data structure
	"sync"
	"unsafe"
)

type dlopen interface {
	lookup(string) (uintptr, error)
}

func open(name string) (*Plugin, error) {
	filepath, err := libPath(name)
	if err != nil {
		return nil, err
	}
	pluginsMu.Lock()
	if p := plugins[filepath]; p != nil {
		pluginsMu.Unlock()
		if p.err != "" {
			return nil, errors.New(`plugin.Open("` + name + `"): ` + p.err + ` (previous failure)`)
		}
		<-p.loaded
		return p, nil
	}
	hnd, err := openLib(name)
	if err != nil {
		pluginsMu.Unlock()
		return nil, err
	}
	// TODO(crawshaw): look for plugin note, confirm it is a Go plugin
	// and it was built with the correct toolchain.
	if len(name) > 3 && name[len(name)-3:] == ".so" {
		name = name[:len(name)-3]
	}
	if plugins == nil {
		plugins = make(map[string]*Plugin)
	}

	fmt.Println("running lastmoduleinit")
	pluginpath, syms, errstr := lastmoduleinit()
	if errstr != "" {
		plugins[filepath] = &Plugin{
			pluginpath: pluginpath,
			err:        errstr,
		}
		pluginsMu.Unlock()
		return nil, errors.New(`plugin.Open("` + name + `"): ` + errstr)
	}
	// This function can be called from the init function of a plugin.
	// Drop a placeholder in the map so subsequent opens can wait on it.
	p := &Plugin{
		pluginpath: pluginpath,
		loaded:     make(chan struct{}),
	}
	plugins[filepath] = p
	pluginsMu.Unlock()

	if initFuncPC, err := hnd.lookup(pluginpath + ".init"); err == nil {
		initFuncP := &initFuncPC
		initFunc := *(*func())(unsafe.Pointer(&initFuncP))
		initFunc()
	}

	// Fill out the value of each plugin symbol.
	updatedSyms := map[string]interface{}{}
	for symName, sym := range syms {
		isFunc := symName[0] == '.'
		if isFunc {
			delete(syms, symName)
			symName = symName[1:]
		}

		fullName := pluginpath + "." + symName
		cname := make([]byte, len(fullName)+1)
		copy(cname, fullName)

		p, err := hnd.lookup(pluginpath + "." + symName)
		if err != nil {
			return nil, errors.New(`plugin.Open("` + name + `"): could not find symbol ` + symName + `: ` + err.Error())
		}
		valp := (*[2]unsafe.Pointer)(unsafe.Pointer(&sym))
		if isFunc {
			(*valp)[1] = unsafe.Pointer(&p)
		} else {
			(*valp)[1] = unsafe.Pointer(p)
		}
		// we can't add to syms during iteration as we'll end up processing
		// some symbols twice with the inability to tell if the symbol is a function
		updatedSyms[symName] = sym
	}
	p.syms = updatedSyms

	close(p.loaded)
	return p, nil
}

func lookup(p *Plugin, symName string) (Symbol, error) {
	if s := p.syms[symName]; s != nil {
		return s, nil
	}
	return nil, errors.New("plugin: symbol " + symName + " not found in plugin " + p.pluginpath)
}

var (
	pluginsMu sync.Mutex
	plugins   map[string]*Plugin
)

// lastmoduleinit is defined in package runtime

//go:linkname lastmoduleinit plugin.lastmoduleinit
func lastmoduleinit() (pluginpath string, syms map[string]interface{}, errstr string)
