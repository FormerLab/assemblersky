; Assemblersky utility helpers
; Best-effort helper file carried forward for milestone packs.

BITS 64
DEFAULT REL

SECTION .text
GLOBAL asb_mem_eq

; int asb_mem_eq(const uint8_t *a, const uint8_t *b, size_t len)
; returns 1 if equal, 0 otherwise
asb_mem_eq:
    push rbp
    mov rbp, rsp
    xor rax, rax
    test rdx, rdx
    jz .eq
.loop:
    mov bl, [rdi]
    cmp bl, [rsi]
    jne .done
    inc rdi
    inc rsi
    dec rdx
    jnz .loop
.eq:
    mov eax, 1
.done:
    pop rbp
    ret
