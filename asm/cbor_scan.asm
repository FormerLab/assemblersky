; Assemblersky — cbor_scan.asm
; x86-64 SysV ABI, NASM syntax
;
; int asb_decode_envelope(const uint8_t *buf, size_t len, asb_envelope_t *out)
;
; Parses two concatenated CBOR items from an AT Protocol event-stream frame:
;   - header map: {op: 1, t: "#commit"}
;   - body map:   {seq, repo, rev, ops, blocks, ...}
;
; Fills asb_envelope_t with pointers/lengths into the original buffer.
; Definite-length CBOR subset only.

BITS 64
DEFAULT REL

%define OFF_SEQ         0
%define OFF_REPO_PTR    8
%define OFF_REPO_LEN    16
%define OFF_REV_PTR     24
%define OFF_REV_LEN     32
%define OFF_OPS_PTR     40
%define OFF_OPS_LEN     48
%define OFF_BLOCKS_PTR  56
%define OFF_BLOCKS_LEN  64
%define OFF_IS_COMMIT   72

section .rodata
key_op:         db 'op'
key_t:          db 't'
key_seq:        db 'seq'
key_repo:       db 'repo'
key_rev:        db 'rev'
key_ops:        db 'ops'
key_blocks:     db 'blocks'
str_commit:     db '#commit'

section .text

global asb_decode_envelope

; =============================================================================
; asb_decode_envelope(rdi=buf, rsi=len, rdx=out)
; returns eax = 0 on success, -1 on error
; =============================================================================
asb_decode_envelope:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    test rdi, rdi
    jz .err
    test rdx, rdx
    jz .err

    mov r12, rdi            ; cur ptr (advances through frame)
    lea r13, [rdi + rsi]    ; end ptr (fixed for entire call)
    mov r14, rdx            ; out struct ptr

    ; zero output struct (80 bytes = 10 qwords)
    xor eax, eax
    mov ecx, 10
    mov rdi, r14
.zero_loop:
    mov qword [rdi], 0
    add rdi, 8
    loop .zero_loop

    ; parse header map
    mov rdi, r12
    mov rsi, r13
    call parse_header_map
    test rax, rax
    jz .err
    mov r12, rax

    ; require #commit
    cmp dword [r14 + OFF_IS_COMMIT], 1
    jne .err

    ; parse body map
    mov rdi, r12
    mov rsi, r13
    call parse_body_map
    test rax, rax
    jz .err

    xor eax, eax
    jmp .done

.err:
    mov eax, -1
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; parse_header_map(rdi=cur, rsi=end) -> rax=next or 0
; Register map (callee-save, so stable across inner calls):
;   r12 = end ptr (copy of rsi, reloaded into rsi before each call)
;   r13 = cur ptr
;   r14 = out ptr  (from caller's frame, not modified here)
;   r15 = pair count
;   rbx = key ptr
;   rbp saved
; Stack slot [rsp+0] = key len (can't use r13 since we need end separately)
; =============================================================================
parse_header_map:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r15
    sub rsp, 16             ; local: [rsp+0]=key_len

    ; save end ptr into r12 (stable across calls)
    mov r12, rsi

    ; decode map header
    ; rdi already = cur, rsi already = end
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 5              ; must be map
    jne .fail

    mov r13, rax            ; cur = after map header
    mov r15, rcx            ; pair count

.loop:
    test r15, r15
    jz .ok

    ; parse key as text
    mov rdi, r13
    mov rsi, r12            ; reload end
    call parse_text_item
    test rax, rax
    jz .fail
    mov r13, rax            ; cur = after key
    mov rbx, rdx            ; key ptr
    mov [rsp+0], rcx        ; key len (on stack)

    ; check "t"
    mov rdx, rbx
    mov rcx, [rsp+0]
    lea r8, [rel key_t]
    mov r9, 1
    call match_key
    test eax, eax
    jz .check_op

    mov rdi, r13
    mov rsi, r12
    call parse_text_item
    test rax, rax
    jz .fail
    mov r13, rax
    ; rdx=value ptr, rcx=value len — compare to "#commit"
    lea r8, [rel str_commit]
    mov r9, 7
    call match_value
    test eax, eax
    jz .next
    mov dword [r14 + OFF_IS_COMMIT], 1
    jmp .next

.check_op:
    mov rdx, rbx
    mov rcx, [rsp+0]
    lea r8, [rel key_op]
    mov r9, 2
    call match_key
    test eax, eax
    jz .skip_value

    mov rdi, r13
    mov rsi, r12
    call parse_uint_item
    test rax, rax
    jz .fail
    mov r13, rax
    jmp .next

.skip_value:
    mov rdi, r13
    mov rsi, r12
    call skip_item
    test rax, rax
    jz .fail
    mov r13, rax

.next:
    dec r15
    jmp .loop

.ok:
    mov rax, r13
    jmp .done
.fail:
    xor eax, eax
.done:
    add rsp, 16
    pop r15
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; parse_body_map(rdi=cur, rsi=end) -> rax=next or 0
; Register map:
;   r12 = end ptr (stable)
;   r13 = cur ptr
;   r14 = out ptr (from outer frame)
;   r15 = pair count
;   rbx = key ptr
;   [rsp+0] = key len
; =============================================================================
parse_body_map:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r15
    sub rsp, 16             ; local: [rsp+0]=key_len

    mov r12, rsi            ; save end ptr

    mov rdi, rdi            ; cur already in rdi
    ; rsi already = end
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 5              ; must be map
    jne .fail

    mov r13, rax            ; cur = after map header
    mov r15, rcx            ; pair count

.loop:
    test r15, r15
    jz .ok

    ; parse key
    mov rdi, r13
    mov rsi, r12
    call parse_text_item
    test rax, rax
    jz .fail
    mov r13, rax
    mov rbx, rdx            ; key ptr
    mov [rsp+0], rcx        ; key len

    ; seq
    mov rdx, rbx
    mov rcx, [rsp+0]
    lea r8, [rel key_seq]
    mov r9, 3
    call match_key
    test eax, eax
    jz .check_repo
    mov rdi, r13
    mov rsi, r12
    call parse_uint_item
    test rax, rax
    jz .fail
    mov [r14 + OFF_SEQ], rdx
    mov r13, rax
    jmp .next

.check_repo:
    mov rdx, rbx
    mov rcx, [rsp+0]
    lea r8, [rel key_repo]
    mov r9, 4
    call match_key
    test eax, eax
    jz .check_rev
    mov rdi, r13
    mov rsi, r12
    call parse_text_item
    test rax, rax
    jz .fail
    mov [r14 + OFF_REPO_PTR], rdx
    mov [r14 + OFF_REPO_LEN], rcx
    mov r13, rax
    jmp .next

.check_rev:
    mov rdx, rbx
    mov rcx, [rsp+0]
    lea r8, [rel key_rev]
    mov r9, 3
    call match_key
    test eax, eax
    jz .check_ops
    mov rdi, r13
    mov rsi, r12
    call parse_text_item
    test rax, rax
    jz .fail
    mov [r14 + OFF_REV_PTR], rdx
    mov [r14 + OFF_REV_LEN], rcx
    mov r13, rax
    jmp .next

.check_ops:
    mov rdx, rbx
    mov rcx, [rsp+0]
    lea r8, [rel key_ops]
    mov r9, 3
    call match_key
    test eax, eax
    jz .check_blocks
    ; capture the raw ops slice (pointer + length before skipping)
    mov rbx, r13            ; save start of ops value
    mov rdi, r13
    mov rsi, r12
    call skip_item
    test rax, rax
    jz .fail
    mov [r14 + OFF_OPS_PTR], rbx
    mov rdx, rax
    sub rdx, rbx
    mov [r14 + OFF_OPS_LEN], rdx
    mov r13, rax
    jmp .next

.check_blocks:
    mov rdx, rbx
    mov rcx, [rsp+0]
    lea r8, [rel key_blocks]
    mov r9, 6
    call match_key
    test eax, eax
    jz .skip_value
    mov rdi, r13
    mov rsi, r12
    call parse_bytes_item
    test rax, rax
    jz .fail
    mov [r14 + OFF_BLOCKS_PTR], rdx
    mov [r14 + OFF_BLOCKS_LEN], rcx
    mov r13, rax
    jmp .next

.skip_value:
    mov rdi, r13
    mov rsi, r12
    call skip_item
    test rax, rax
    jz .fail
    mov r13, rax

.next:
    dec r15
    jmp .loop

.ok:
    mov rax, r13
    jmp .done
.fail:
    xor eax, eax
.done:
    add rsp, 16
    pop r15
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; Helpers — all take rdi=ptr, rsi=end
; =============================================================================

; parse_uint_item -> rax=next or 0, rdx=value
parse_uint_item:
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 0
    jne .fail
    mov rdx, rcx
    ret
.fail:
    xor eax, eax
    ret

; parse_text_item -> rax=next or 0, rdx=data_ptr, rcx=len
parse_text_item:
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 3
    jne .fail
    mov rdx, rax
    mov r10, rcx
    add rax, rcx
    cmp rax, rsi
    ja .fail
    mov rcx, r10
    ret
.fail:
    xor eax, eax
    ret

; parse_bytes_item -> rax=next or 0, rdx=data_ptr, rcx=len
parse_bytes_item:
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 2
    jne .fail
    mov rdx, rax
    mov r10, rcx
    add rax, rcx
    cmp rax, rsi
    ja .fail
    mov rcx, r10
    ret
.fail:
    xor eax, eax
    ret

; skip_item -> rax=next or 0
; Handles: uint, negint, bytes, text, array, map, simple/float, tag
skip_item:
    push rbx
    push r12
    push r13

    ; save end ptr — rsi may be clobbered by recursive calls
    mov r12, rsi

    call decode_head
    test rax, rax
    jz .fail

    cmp r8b, 0
    je .scalar_ok
    cmp r8b, 1
    je .scalar_ok
    cmp r8b, 7
    je .scalar_ok
    cmp r8b, 2
    je .len_data
    cmp r8b, 3
    je .len_data
    cmp r8b, 4
    je .skip_array
    cmp r8b, 5
    je .skip_map
    cmp r8b, 6
    je .skip_tag
    jmp .fail

.scalar_ok:
    jmp .done

.len_data:
    add rax, rcx
    cmp rax, r12
    ja .fail
    jmp .done

.skip_tag:
    ; tag: consume the tag argument (already in rcx via decode_head),
    ; then skip the wrapped item
    mov rdi, rax
    mov rsi, r12
    call skip_item
    test rax, rax
    jz .fail
    jmp .done

.skip_array:
    mov r13, rcx            ; item count
    mov rbx, rax            ; cur
.array_loop:
    test r13, r13
    jz .array_done
    mov rdi, rbx
    mov rsi, r12
    call skip_item
    test rax, rax
    jz .fail
    mov rbx, rax
    dec r13
    jmp .array_loop
.array_done:
    mov rax, rbx
    jmp .done

.skip_map:
    mov r13, rcx            ; pair count
    mov rbx, rax            ; cur
.map_loop:
    test r13, r13
    jz .map_done
    mov rdi, rbx
    mov rsi, r12
    call skip_item          ; key
    test rax, rax
    jz .fail
    mov rbx, rax
    mov rdi, rbx
    mov rsi, r12
    call skip_item          ; value
    test rax, rax
    jz .fail
    mov rbx, rax
    dec r13
    jmp .map_loop
.map_done:
    mov rax, rbx
    jmp .done

.fail:
    xor eax, eax
.done:
    pop r13
    pop r12
    pop rbx
    ret

; decode_head(rdi=ptr, rsi=end) -> rax=after_head or 0, r8b=major, rcx=arg
; Supports info values 0-27 (definite only). Indefinite (31) returns fail.
decode_head:
    cmp rdi, rsi
    jae .fail
    movzx eax, byte [rdi]
    mov r8d, eax
    shr r8b, 5              ; major type
    and eax, 31             ; additional info
    lea rdx, [rdi + 1]

    cmp eax, 23
    jbe .small
    cmp eax, 24
    je .u8
    cmp eax, 25
    je .u16
    cmp eax, 26
    je .u32
    cmp eax, 27
    je .u64
    jmp .fail

.small:
    mov ecx, eax
    mov rax, rdx
    ret
.u8:
    cmp rdx, rsi
    jae .fail
    movzx ecx, byte [rdx]
    lea rax, [rdx + 1]
    ret
.u16:
    lea rax, [rdx + 2]
    cmp rax, rsi
    ja .fail
    movzx ecx, byte [rdx]
    shl ecx, 8
    movzx r9d, byte [rdx + 1]
    or ecx, r9d
    ret
.u32:
    lea rax, [rdx + 4]
    cmp rax, rsi
    ja .fail
    xor ecx, ecx
    movzx r9d, byte [rdx]
    shl r9, 24
    or rcx, r9
    movzx r9d, byte [rdx + 1]
    shl r9, 16
    or rcx, r9
    movzx r9d, byte [rdx + 2]
    shl r9, 8
    or rcx, r9
    movzx r9d, byte [rdx + 3]
    or rcx, r9
    ret
.u64:
    lea rax, [rdx + 8]
    cmp rax, rsi
    ja .fail
    xor rcx, rcx
    movzx r9d, byte [rdx]
    shl r9, 56
    or rcx, r9
    movzx r9d, byte [rdx + 1]
    shl r9, 48
    or rcx, r9
    movzx r9d, byte [rdx + 2]
    shl r9, 40
    or rcx, r9
    movzx r9d, byte [rdx + 3]
    shl r9, 32
    or rcx, r9
    movzx r9d, byte [rdx + 4]
    shl r9, 24
    or rcx, r9
    movzx r9d, byte [rdx + 5]
    shl r9, 16
    or rcx, r9
    movzx r9d, byte [rdx + 6]
    shl r9, 8
    or rcx, r9
    movzx r9d, byte [rdx + 7]
    or rcx, r9
    ret
.fail:
    xor eax, eax
    ret

; match_key(rdx=ptr, rcx=len, r8=ref_ptr, r9=ref_len) -> eax=1/0
match_key:
    push rbx
    cmp rcx, r9
    jne .no
    xor eax, eax
.loop:
    cmp rax, rcx
    je .yes
    mov bl, [rdx + rax]
    cmp bl, [r8 + rax]
    jne .no
    inc rax
    jmp .loop
.yes:
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret

match_value:
    jmp match_key
