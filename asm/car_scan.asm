; Assemblersky v0.4 — Milestone 3
; NASM x86-64 SysV ABI
;
; int asb_car_find_block(
;     const uint8_t *car_buf, size_t car_len,
;     const uint8_t *target_cid, size_t target_cid_len,
;     const uint8_t **block_ptr, size_t *block_len);
;
; Returns 0 on success, non-zero on failure.
; Best-effort CARv1 scanner:
; - reads header varint length
; - skips header bytes
; - iterates block sections
; - each section assumed to be [CID bytes][payload bytes]
; - CID size inferred heuristically for common CIDv1 layout

BITS 64
DEFAULT REL

SECTION .text
GLOBAL asb_car_find_block

; ----------------------------------------
; Internal helper: decode unsigned LEB128-ish varint
; in:  rdi = ptr, rsi = end
; out: rax = value, rdx = next ptr, rcx = 0 success / 1 failure
; clobbers: r8, r9
; ----------------------------------------
_decode_varint:
    xor rax, rax
    xor r8, r8              ; shift
.var_loop:
    cmp rdi, rsi
    jae .var_fail
    movzx r9d, byte [rdi]
    inc rdi
    mov rdx, r9
    and rdx, 0x7f
    mov rcx, r8
    shl rdx, cl
    or rax, rdx
    test r9b, 0x80
    jz .var_ok
    add r8, 7
    cmp r8, 63
    ja .var_fail
    jmp .var_loop
.var_ok:
    mov rdx, rdi
    xor rcx, rcx
    ret
.var_fail:
    xor rax, rax
    xor rdx, rdx
    mov rcx, 1
    ret

; ----------------------------------------
; Internal helper: memcmp-like
; in: rdi = a, rsi = b, rdx = len
; out: eax = 1 equal / 0 not equal
; ----------------------------------------
_mem_eq:
    test rdx, rdx
    jz .eq_yes
.eq_loop:
    mov al, [rdi]
    cmp al, [rsi]
    jne .eq_no
    inc rdi
    inc rsi
    dec rdx
    jnz .eq_loop
.eq_yes:
    mov eax, 1
    ret
.eq_no:
    xor eax, eax
    ret

; ----------------------------------------
; Internal helper: heuristic CID length guess
; in:  rdi = section_ptr, rsi = section_end
; out: rax = cid_len (0 on failure)
;
; Heuristic for common CIDv1 binary form:
;   version varint     (usually 0x01)
;   codec varint
;   multihash code
;   digest length
;   digest bytes
; ----------------------------------------
_guess_cid_len:
    push rbx
    push r13                ; save section_end across _decode_varint calls
    mov rbx, rdi            ; save section_ptr start
    mov r13, rsi            ; save section_end (rsi clobbered by _decode_varint)

    ; version
    mov rsi, r13
    call _decode_varint
    test rcx, rcx
    jnz .cid_fail
    mov rdi, rdx

    ; codec
    mov rsi, r13
    call _decode_varint
    test rcx, rcx
    jnz .cid_fail
    mov rdi, rdx

    ; multihash code
    mov rsi, r13
    call _decode_varint
    test rcx, rcx
    jnz .cid_fail
    mov rdi, rdx

    ; digest length
    mov rsi, r13
    call _decode_varint
    test rcx, rcx
    jnz .cid_fail
    mov r8, rax             ; digest length
    mov rdi, rdx

    ; ensure digest bytes fit
    mov rax, r13
    sub rax, rdi
    cmp rax, r8
    jb .cid_fail

    ; total cid len = consumed so far + digest length
    mov rax, rdi
    sub rax, rbx
    add rax, r8
    pop r13
    pop rbx
    ret

.cid_fail:
    xor rax, rax
    pop r13
    pop rbx
    ret

; ----------------------------------------
; int asb_car_find_block(...)
; rdi=car_buf, rsi=car_len, rdx=target_cid, rcx=target_cid_len,
; r8=block_ptr_out, r9=block_len_out
; ----------------------------------------
asb_car_find_block:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; null checks before saving state
    test rdi, rdi
    jz .fail_early
    test rdx, rdx
    jz .fail_early
    test r8, r8
    jz .fail_early
    test r9, r9
    jz .fail_early
    test rcx, rcx
    jz .fail_early

    ; preserve inputs in callee-save registers
    mov r12, rdi            ; car start
    mov r13, rsi            ; car len (used to compute end)
    mov r14, rdx            ; target cid ptr
    mov r15, rcx            ; target cid len

    ; r8=block_ptr_out, r9=block_len_out are clobbered by _decode_varint
    ; save them on the stack
    push r9                 ; [rsp+8] = block_len_out
    push r8                 ; [rsp+0] = block_ptr_out

    lea rbx, [r12 + r13]    ; car end

    ; decode CAR header section length
    mov rdi, r12
    mov rsi, rbx
    call _decode_varint
    test rcx, rcx
    jnz .fail

    ; rax = header_len, rdx = after header-len varint
    mov r12, rdx            ; current ptr = header bytes start
    add r12, rax            ; skip header section
    cmp r12, rbx
    ja .fail

.block_loop:
    cmp r12, rbx
    jae .not_found

    ; decode next section length
    mov rdi, r12
    mov rsi, rbx
    call _decode_varint
    test rcx, rcx
    jnz .fail

    mov r10, rax            ; section_len
    mov r11, rdx            ; section_ptr

    ; compute section_end = section_ptr + section_len
    lea r12, [r11 + r10]    ; next iteration ptr if not match
    cmp r12, rbx
    ja .fail

    ; guess CID length within section
    mov rdi, r11
    mov rsi, r12
    call _guess_cid_len
    test rax, rax
    jz .block_loop          ; skip unrecognized section conservatively

    mov r10, rax            ; cid_len

    ; compare cid length first
    cmp r10, r15
    jne .block_loop

    ; compare bytes
    mov rdi, r11
    mov rsi, r14
    mov rdx, r15
    call _mem_eq
    test eax, eax
    jz .block_loop

    ; match found: payload starts after CID bytes
    lea rax, [r11 + r15]    ; payload ptr
    mov r8, [rsp+0]         ; restore block_ptr_out
    mov [r8], rax

    mov rdx, r12            ; section_end
    sub rdx, rax            ; payload len
    mov r9, [rsp+8]         ; restore block_len_out
    mov [r9], rdx

    xor eax, eax
    jmp .done

.not_found:
    mov eax, 2
    jmp .done

.fail:
    mov eax, 1
    jmp .done

.fail_early:
    mov eax, 1
    jmp .done_early

.done:
    add rsp, 16             ; discard saved r8/r9
.done_early:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
