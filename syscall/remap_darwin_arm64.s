#include "textflag.h"

TEXT libc_mremap_encrypted_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mremap_encrypted(SB)
GLOBL	·libc_mremap_encrypted_trampoline_addr(SB), RODATA, $8
DATA	·libc_mremap_encrypted_trampoline_addr(SB)/8, $libc_mremap_encrypted_trampoline<>(SB)
