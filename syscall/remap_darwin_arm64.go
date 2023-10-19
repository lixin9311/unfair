package syscall

import "unsafe"

func MremapEncrypted(data []byte, cryptid uint32, cpuType uint32, cpuSubtype uint32) (err error) {
	return mapper.MremapEncrypted(data, cryptid, cpuType, cpuSubtype)
}

//go:cgo_import_dynamic libc_mremap_encrypted mremap_encrypted "/usr/lib/libSystem.B.dylib"
var libc_mremap_encrypted_trampoline_addr uintptr

func mremap_encrypted(addr uintptr, length uintptr, cryptid uint32, cpuType uint32, cpuSubtype uint32) (err error) {
	_, _, e1 := syscall_syscall6(libc_mremap_encrypted_trampoline_addr, uintptr(addr), uintptr(length), uintptr(cryptid), uintptr(cpuType), uintptr(cpuSubtype), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func (m *mmapper) MremapEncrypted(data []byte, cryptid uint32, cpuType uint32, cpuSubtype uint32) (err error) {
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

	// Remap the memory and update m.
	if errno := m.mremap_encrypted(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), cryptid, cpuType, cpuSubtype); errno != nil {
		return errno
	}
	delete(m.active, p)
	return nil
}
