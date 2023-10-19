// copied from go syscall package

// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && arm64
// +build darwin,arm64

package syscall

import (
	"sync"
	"syscall"
	"unsafe"
	_ "unsafe"
)

type Errno = syscall.Errno

// Do the interface allocations only once for common
// Errno values.
var (
	errEAGAIN error = syscall.EAGAIN
	errEINVAL error = syscall.EINVAL
	errENOENT error = syscall.ENOENT
)

const (
	EAGAIN = syscall.Errno(0x23)
	EINVAL = syscall.Errno(0x16)
	ENOENT = syscall.Errno(0x2)
)

func Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error) {
	return mapper.Mmap(fd, offset, length, prot, flags)
}

func Munmap(b []byte) (err error) {
	return mapper.Munmap(b)
}

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case EAGAIN:
		return errEAGAIN
	case EINVAL:
		return errEINVAL
	case ENOENT:
		return errENOENT
	}
	return e
}

//go:linkname syscall_syscall syscall.syscall
//go:linkname syscall_syscall6 syscall.syscall6
//go:linkname syscall_rawSyscall syscall.rawSyscall
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func syscall_rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)

//go:cgo_import_dynamic libc_mmap mmap "/usr/lib/libSystem.B.dylib"
var libc_mmap_trampoline_addr uintptr

func mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error) {
	r0, _, e1 := syscall_syscall6(libc_mmap_trampoline_addr, uintptr(addr), uintptr(length), uintptr(prot), uintptr(flag), uintptr(fd), uintptr(pos))
	ret = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

//go:cgo_import_dynamic libc_munmap munmap "/usr/lib/libSystem.B.dylib"
var libc_munmap_trampoline_addr uintptr

func munmap(addr uintptr, length uintptr) (err error) {
	_, _, e1 := syscall_syscall(libc_munmap_trampoline_addr, uintptr(addr), uintptr(length), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

var mapper = &mmapper{
	active:           make(map[*byte][]byte),
	mmap:             mmap,
	munmap:           munmap,
	mremap_encrypted: mremap_encrypted,
}

type mmapper struct {
	sync.Mutex
	active           map[*byte][]byte // active mappings; key is last byte in mapping
	mmap             func(addr, length uintptr, prot, flags, fd int, offset int64) (uintptr, error)
	munmap           func(addr uintptr, length uintptr) error
	mremap_encrypted func(addr uintptr, length uintptr, cryptid uint32, cpuType uint32, cpuSubtype uint32) error
}

func (m *mmapper) Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error) {
	if length <= 0 {
		return nil, EINVAL
	}

	// Map the requested memory.
	addr, errno := m.mmap(0, uintptr(length), prot, flags, fd, offset)
	if errno != nil {
		return nil, errno
	}

	// Use unsafe to turn addr into a []byte.
	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), length)

	// Register mapping in m and return it.
	p := &b[cap(b)-1]
	m.Lock()
	defer m.Unlock()
	m.active[p] = b
	return b, nil
}

func (m *mmapper) Munmap(data []byte) (err error) {
	if len(data) == 0 || len(data) != cap(data) {
		return EINVAL
	}

	// Find the base of the mapping.
	p := &data[cap(data)-1]
	m.Lock()
	defer m.Unlock()
	b := m.active[p]
	if b == nil || &b[0] != &data[0] {
		return EINVAL
	}

	// Unmap the memory and update m.
	if errno := m.munmap(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))); errno != nil {
		return errno
	}
	delete(m.active, p)
	return nil
}
