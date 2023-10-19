// copied from go syscall package

// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

TEXT libc_mmap_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mmap(SB)
GLOBL	·libc_mmap_trampoline_addr(SB), RODATA, $8
DATA	·libc_mmap_trampoline_addr(SB)/8, $libc_mmap_trampoline<>(SB)

TEXT libc_munmap_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_munmap(SB)
GLOBL	·libc_munmap_trampoline_addr(SB), RODATA, $8
DATA	·libc_munmap_trampoline_addr(SB)/8, $libc_munmap_trampoline<>(SB)
