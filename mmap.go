// +build linux,amd64 !cgo

package plugin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"syscall"
	"unsafe"
)

const (
	MapShared    uintptr = 1
	MapPrivate   uintptr = 2
	MapAnonymous uintptr = 0x20

	pageSize int64   = 0x1000 //Align end on a 4k boundary
	nilFd    uintptr = 0xFFFFFFFFFFFFFFFF

	ProtRO  = 0x1
	ProtWO  = 0x2
	ProtX   = 0x4
	ProtRW  = ProtRO | ProtWO
	ProtRWX = ProtRO | ProtWO | ProtX

	madv_normal     uintptr = 0
	madv_random     uintptr = 1
	madv_sequential uintptr = 2
	madv_dontdump   uintptr = 16
	madv_willneed   uintptr = 3
)

type regionMap struct {
	buff []byte
	base uintptr
	size uintptr
}

type fileMap struct {
	fio  *os.File
	buff []byte
	base uintptr
}

// MapFile creates a new memory map of a file in read only mode
// we do NOT maintain a handle on the file
func newFileMap(f string) (fm fileMap, err error) {
	var sz int64
	if fm.fio, err = os.Open(f); err != nil {
		return
	}
	if sz, err = fileMapSize(fm.fio); err != nil {
		return
	}
	//ok, get our memory map and bring the whole thing in with an madvise call
	if fm.base, err = lin64mmap(0, uintptr(sz), ProtRO, MapPrivate, fm.fio.Fd(), 0); err != nil {
		err = fmt.Errorf("Failed to mmap region: %v", err)
		return
	} else if err = madvisePreload(fm.base, uintptr(sz)); err != nil {
		err = fmt.Errorf("Failed to preload region: %v", err)
		lin64munmap(fm.base, uintptr(sz))
		return
	}
	dh := (*reflect.SliceHeader)(unsafe.Pointer(&fm.buff))
	dh.Data = fm.base
	dh.Len = int(sz)
	dh.Cap = int(sz)

	return
}

// Close unmaps the file and closes the file handle
// WARNING: this is an unsafe operation, if code is running or there are active
// references, sorry...
func (fm *fileMap) close() (err error) {
	if fm == nil || fm.buff == nil || fm.base == 0 {
		return errors.New("Not open")
	}
	if err = lin64munmap(fm.base, uintptr(len(fm.buff))); err != nil {
		fm.fio.Close()
		fm.base = 0
	} else {
		err = fm.fio.Close()
		fm.base = 0
	}
	return
}

func (fm fileMap) ReadAt(b []byte, offset int64) (n int, err error) {
	if fm.fio == nil || fm.buff == nil {
		err = errors.New("File map not open")
	} else if offset >= int64(len(fm.buff)) {
		err = io.EOF
	} else {
		ibuff := fm.buff[offset:]
		if n = len(ibuff); n > len(b) {
			n = len(b)
		}
		copy(b, ibuff)
	}
	return
}

// newRegion creates a new memory reagion, we take a base hint but the kernel controls this
// value, it may or may not be appropriately located, we ALWAYS page align
// the region is mapped RW by default
func newRegion(base, sz uintptr) (r regionMap, err error) {
	base = alignMem(base)
	if r.size = uintptr(mapSize(int64(sz))); r.size == 0 {
		err = errors.New("invalid region map size")
		return
	}
	if r.base, err = lin64mmap(base, r.size, ProtRW, MapAnonymous|MapPrivate, 0, 0); err != nil {
		return
	}

	dh := (*reflect.SliceHeader)(unsafe.Pointer(&r.buff))
	dh.Data = r.base
	dh.Len = int(r.size)
	dh.Cap = int(r.size)
	return
}

func (r regionMap) close() (err error) {
	if r.size == 0 {
		return
	} else {
		err = lin64munmap(r.base, r.size)
		r.size = 0
		r.base = 0
	}
	return
}

// contains is looking to see if an address and size fits in the memory region
func (r regionMap) contains(b, sz uintptr) bool {
	//check if the base lies in our mapped region
	return b > r.base && (b+sz) <= (r.base+r.size)
}

// inbuff is looking to see if an offset and size fits in the buffer
func (r regionMap) inbuff(b, sz uintptr) bool {
	//check if the base lies in our mapped region
	return (b + sz) < r.size
}

// setPerms sets the permission bits for the entire region
func (r regionMap) setPerms(vflags uintptr) (err error) {
	err = lin64mprotect(r.base, r.size, vflags)
	return
}

// setSubPerms sets the permission bits for a subset of memory
// we ensure the specified region is page aligned on both sides
func (r regionMap) setSubPerms(off, sz uintptr, vflags uintptr) (err error) {
	if (off % uintptr(pageSize)) != 0 {
		fmt.Println(off, vflags)
		err = errors.New("offset is not page aligned")
	} else {
		err = lin64mprotect(r.base+off, sz, vflags)
	}
	return
}

func lin64mmap(base, length, prot, flags, fd uintptr, offset int64) (addr uintptr, err error) {
	var errno syscall.Errno
	addr, _, errno = syscall.Syscall6(syscall.SYS_MMAP, base, length, prot, flags, fd, uintptr(offset))
	if errno != 0 {
		err = errors.New(errno.Error())
	}
	return
}

func lin64munmap(base, length uintptr) (err error) {
	var errno syscall.Errno
	if _, _, errno = syscall.Syscall(syscall.SYS_MUNMAP, base, length, 0); errno != 0 {
		err = errors.New(errno.Error())
	}
	return
}

func lin64mremap(old, old_len, new_len uintptr) (addr uintptr, err error) {
	flags := uintptr(1) //MREMAP_MAYMOVE
	var errno syscall.Errno
	addr, _, errno = syscall.Syscall6(syscall.SYS_MREMAP, old, old_len, new_len, flags, 0, 0)
	if errno != 0 {
		err = errors.New(errno.Error())
	}
	return
}

func lin64mprotect(base, sz, flag uintptr) (err error) {
	var errno syscall.Errno
	_, _, errno = syscall.Syscall(syscall.SYS_MPROTECT, base, sz, flag)
	if errno != 0 {
		err = errors.New(errno.Error())
	}
	return
}

func lin64madvise(base, sz, flag uintptr) (err error) {
	var errno syscall.Errno
	_, _, errno = syscall.Syscall(syscall.SYS_MADVISE, base, sz, flag)
	if errno != 0 {
		err = errors.New(errno.Error())
	}
	return
}

func madvisePreload(p uintptr, sz uintptr) (err error) {
	var serr syscall.Errno
	if _, _, serr = syscall.Syscall(syscall.SYS_MADVISE, p, uintptr(sz), madv_willneed); serr != 0 {
		err = serr
	}
	return
}

func fileMapSize(fin *os.File) (sz int64, err error) {
	var fi os.FileInfo
	if fin == nil {
		err = errors.New("Invalid file handle")
		return
	}
	if fi, err = fin.Stat(); err != nil {
		return
	}
	//generate a size that overlaps by our overmap size
	if sz = fi.Size(); sz == 0 {
		err = errors.New("Empty file")
	}
	sz = mapSize(sz)
	return
}

func mapSize(sz int64) int64 {
	if m := sz % pageSize; m != 0 {
		sz += pageSize - m
	}
	return sz
}

// alignMem ensures a value is page aligned, if it is not we move it one page forward
func alignMem(v uintptr) uintptr {
	if m := v % uintptr(pageSize); m != 0 {
		v += uintptr(pageSize) - m
	}
	return v
}
