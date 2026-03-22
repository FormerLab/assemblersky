; Assemblersky — post_extract.asm
; Complete implementation of Milestones 2 and 4:
;
;   int asb_find_create_post_op(const uint8_t *ops_buf, size_t ops_len, asb_post_op_t *out)
;   int asb_extract_post_record(const uint8_t *block_buf, size_t block_len, asb_post_record_t *out)
;
; x86-64 SysV ABI, NASM syntax.
;
; asb_find_create_post_op:
;   - walks a definite-length CBOR array of op maps
;   - matches action=="create" and path=="app.bsky.feed.post/<rkey>"
;   - captures collection, rkey, cid, record_cid slices
;
; asb_extract_post_record:
;   - walks a definite-length DAG-CBOR map (post record block)
;   - extracts "$type", "text", "createdAt" as pointer/length pairs
;
; Both are best-effort: definite-length CBOR subset only.
; Indefinite-length items fail gracefully.

BITS 64
DEFAULT REL

; ---- asb_post_op_t offsets ----
%define OFF_COLLECTION_PTR   0
%define OFF_COLLECTION_LEN   8
%define OFF_RKEY_PTR         16
%define OFF_RKEY_LEN         24
%define OFF_CID_PTR          32
%define OFF_CID_LEN          40
%define OFF_RECORD_CID_PTR   48
%define OFF_RECORD_CID_LEN   56
%define OFF_IS_CREATE_POST   64

; ---- asb_post_record_t offsets ----
%define OFF_TYPE_PTR        0
%define OFF_TYPE_LEN        8
%define OFF_TEXT_PTR        16
%define OFF_TEXT_LEN        24
%define OFF_CREATED_PTR     32
%define OFF_CREATED_LEN     40
%define OFF_OK              48

%define POST_PREFIX_LEN     19
%define POST_COLLECTION_LEN 18

SECTION .rodata
key_action:         db 'action'
key_path:           db 'path'
key_cid:            db 'cid'
str_create:         db 'create'
post_path_prefix:   db 'app.bsky.feed.post/'
key_type_str:       db '$type'
key_type_len_val:   equ $ - key_type_str
key_text_str:       db 'text'
key_text_len_val:   equ $ - key_text_str
key_created_str:    db 'createdAt'
key_created_len_val: equ $ - key_created_str

SECTION .text

GLOBAL asb_find_create_post_op
GLOBAL asb_extract_post_record
EXTERN asb_mem_eq

; =============================================================================
; asb_find_create_post_op(rdi=ops_buf, rsi=ops_len, rdx=out)
; returns eax = 0 on success, -1 on failure / no matching op
; =============================================================================
asb_find_create_post_op:
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

    mov r12, rdi            ; base
    lea r13, [rdi + rsi]    ; end
    mov r14, rdx            ; out

    ; zero output struct (72 bytes = 9 qwords)
    xor eax, eax
    mov ecx, 9
    mov rdi, r14
.zero_loop:
    mov qword [rdi], 0
    add rdi, 8
    loop .zero_loop

    mov rdi, r12
    mov rsi, r13
    call decode_head
    test rax, rax
    jz .err
    cmp r8b, 4              ; array
    jne .err

    mov r15, rax            ; cur after array head
    mov rbx, rcx            ; item count

.op_loop:
    test rbx, rbx
    jz .err                 ; no matching op found

    mov rdi, r15
    mov rsi, r13
    mov rdx, r14
    call parse_single_op_map
    cmp rax, -1
    je .err
    mov r15, rax            ; next item ptr

    cmp dword [r14 + OFF_IS_CREATE_POST], 1
    je .ok

    dec rbx
    jmp .op_loop

.ok:
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

; -----------------------------------------------------------------------------
; parse_single_op_map(rdi=ptr, rsi=end, rdx=out) -> eax=nextptr or -1
; -----------------------------------------------------------------------------
parse_single_op_map:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48

    xor eax, eax
    mov [rsp+0],  rax       ; action_create flag
    mov [rsp+8],  rax       ; path_ptr
    mov [rsp+16], rax       ; path_len
    mov [rsp+24], rax       ; cid_ptr
    mov [rsp+32], rax       ; cid_len

    mov r14, rsi
    mov r15, rdx

    mov rsi, r14
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 5
    jne .fail

    mov r12, rax
    mov r13, rcx

.field_loop:
    test r13, r13
    jz .finalize

    mov rdi, r12
    mov rsi, r14
    call parse_text_item
    test rax, rax
    jz .fail
    mov r12, rax
    mov rbx, rdx
    mov r11, rcx

    mov rdx, rbx
    mov rcx, r11
    lea r8, [rel key_action]
    mov r9, 6
    call match_bytes
    test eax, eax
    jz .check_path

    mov rdi, r12
    mov rsi, r14
    call parse_text_item
    test rax, rax
    jz .fail
    mov r12, rax
    lea r8, [rel str_create]
    mov r9, 6
    call match_bytes
    test eax, eax
    jz .next_field
    mov qword [rsp+0], 1
    jmp .next_field

.check_path:
    mov rdx, rbx
    mov rcx, r11
    lea r8, [rel key_path]
    mov r9, 4
    call match_bytes
    test eax, eax
    jz .check_cid

    mov rdi, r12
    mov rsi, r14
    call parse_text_item
    test rax, rax
    jz .fail
    mov [rsp+8],  rdx
    mov [rsp+16], rcx
    mov r12, rax
    jmp .next_field

.check_cid:
    mov rdx, rbx
    mov rcx, r11
    lea r8, [rel key_cid]
    mov r9, 3
    call match_bytes
    test eax, eax
    jz .skip_value

    mov rdi, r12
    mov rsi, r14
    call parse_text_bytes_or_tagged
    test rax, rax
    jz .fail
    mov [rsp+24], rdx
    mov [rsp+32], rcx
    mov r12, rax
    jmp .next_field

.skip_value:
    mov rdi, r12
    mov rsi, r14
    call skip_item_op
    test rax, rax
    jz .fail
    mov r12, rax

.next_field:
    dec r13
    jmp .field_loop

.finalize:
    cmp qword [rsp+0], 1
    jne .no_match

    mov rdx, [rsp+8]
    mov rcx, [rsp+16]
    test rdx, rdx
    jz .no_match
    cmp rcx, POST_PREFIX_LEN
    jb .no_match

    lea r8, [rel post_path_prefix]
    mov r9, POST_PREFIX_LEN
    mov rcx, POST_PREFIX_LEN   ; compare only the prefix length, not full path len
    call match_bytes
    test eax, eax
    jz .no_match

    mov rax, [rsp+8]
    mov [r15 + OFF_COLLECTION_PTR], rax
    mov qword [r15 + OFF_COLLECTION_LEN], POST_COLLECTION_LEN

    lea rax, [rax + POST_PREFIX_LEN]
    mov [r15 + OFF_RKEY_PTR], rax
    mov rdx, [rsp+16]
    sub rdx, POST_PREFIX_LEN
    mov [r15 + OFF_RKEY_LEN], rdx

    mov rax, [rsp+24]
    mov [r15 + OFF_CID_PTR],        rax
    mov [r15 + OFF_RECORD_CID_PTR], rax
    mov rdx, [rsp+32]
    mov [r15 + OFF_CID_LEN],        rdx
    mov [r15 + OFF_RECORD_CID_LEN], rdx
    mov dword [r15 + OFF_IS_CREATE_POST], 1

    mov rax, r12
    jmp .done

.no_match:
    mov rax, r12
    jmp .done

.fail:
    mov rax, -1
.done:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; asb_extract_post_record(rdi=block_buf, rsi=block_len, rdx=out)
; returns eax = 1 on success, 0 on failure
; =============================================================================
asb_extract_post_record:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    lea r13, [rdi + rsi]
    mov r14, rdx

    xor rax, rax
    mov [r14+OFF_TYPE_PTR],    rax
    mov [r14+OFF_TYPE_LEN],    rax
    mov [r14+OFF_TEXT_PTR],    rax
    mov [r14+OFF_TEXT_LEN],    rax
    mov [r14+OFF_CREATED_PTR], rax
    mov [r14+OFF_CREATED_LEN], rax
    mov dword [r14+OFF_OK], 0

    ; expect definite map
    cmp r12, r13
    jae .fail
    movzx eax, byte [r12]
    inc r12
    mov ecx, eax
    shr ecx, 5
    and eax, 0x1F
    cmp ecx, 5
    jne .fail
    cmp eax, 31
    je .fail
    call read_len_rec
    jc .fail
    mov r15, rax            ; pair count

.loop_pairs:
    test r15, r15
    jz .finish

    call read_text_rec
    jc .fail

    ; check "$type" -- rdi=key_ptr, rdx=key_len from read_text_rec
    cmp rdx, key_type_len_val
    jne .check_text_key
    lea rsi, [rel key_type_str]
    call asb_mem_eq
    cmp eax, 1
    jne .check_text_key
    call read_text_rec
    jc .fail
    mov [r14+OFF_TYPE_PTR], rdi
    mov [r14+OFF_TYPE_LEN], rdx
    dec r15
    jmp .loop_pairs

.check_text_key:
    cmp rdx, key_text_len_val
    jne .check_created_key
    lea rsi, [rel key_text_str]
    call asb_mem_eq
    cmp eax, 1
    jne .check_created_key
    call read_text_rec
    jc .fail
    mov [r14+OFF_TEXT_PTR], rdi
    mov [r14+OFF_TEXT_LEN], rdx
    dec r15
    jmp .loop_pairs

.check_created_key:
    cmp rdx, key_created_len_val
    jne .skip_val_rec
    lea rsi, [rel key_created_str]
    call asb_mem_eq
    cmp eax, 1
    jne .skip_val_rec
    call read_text_rec
    jc .fail
    mov [r14+OFF_CREATED_PTR], rdi
    mov [r14+OFF_CREATED_LEN], rdx
    dec r15
    jmp .loop_pairs

.skip_val_rec:
    call skip_item_rec
    jc .fail
    dec r15
    jmp .loop_pairs

.finish:
    mov rax, [r14+OFF_TYPE_PTR]
    test rax, rax
    jz .fail
    mov rax, [r14+OFF_TEXT_PTR]
    test rax, rax
    jz .fail
    mov dword [r14+OFF_OK], 1
    mov eax, 1
    jmp .done

.fail:
    xor eax, eax
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; Shared helpers for asb_find_create_post_op
; (use r12=cur, r13/r14=end, register-passing convention)
; =============================================================================

; decode_head(rdi=ptr, rsi=end) -> rax=after_head, rcx=arg, r8b=major
decode_head:
    xor eax, eax
    xor ecx, ecx
    mov r8b, 0xff
    cmp rdi, rsi
    jae .fail
    movzx edx, byte [rdi]
    mov r8d, edx
    shr r8b, 5
    and edx, 0x1f
    lea rax, [rdi + 1]
    cmp dl, 23
    jbe .small
    cmp dl, 24
    je .u8
    cmp dl, 25
    je .u16
    cmp dl, 26
    je .u32
    jmp .fail
.small:
    movzx ecx, dl
    ret
.u8:
    cmp rax, rsi
    jae .fail
    movzx ecx, byte [rax]
    inc rax
    ret
.u16:
    lea r9, [rax + 2]
    cmp r9, rsi
    ja .fail
    movzx ecx, byte [rax]
    shl ecx, 8
    movzx edx, byte [rax + 1]
    or ecx, edx
    mov rax, r9
    ret
.u32:
    lea r9, [rax + 4]
    cmp r9, rsi
    ja .fail
    xor ecx, ecx
    movzx edx, byte [rax]
    shl rdx, 24
    or rcx, rdx
    movzx edx, byte [rax+1]
    shl rdx, 16
    or rcx, rdx
    movzx edx, byte [rax+2]
    shl rdx, 8
    or rcx, rdx
    movzx edx, byte [rax+3]
    or rcx, rdx
    mov rax, r9
    ret
.fail:
    xor eax, eax
    ret

; parse_text_item(rdi=ptr, rsi=end) -> rax=next, rdx=ptr, rcx=len
parse_text_item:
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 3
    jne .fail
    mov rdx, rax
    add rax, rcx
    cmp rax, rsi
    ja .fail
    ret
.fail:
    xor eax, eax
    ret

; parse_text_bytes_or_tagged -> rax=next, rdx=ptr, rcx=len
parse_text_bytes_or_tagged:
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 6
    jne .not_tag
    mov rdi, rax
    call decode_head
    test rax, rax
    jz .fail
.not_tag:
    cmp r8b, 2
    je .ok_payload
    cmp r8b, 3
    je .ok_payload
    jmp .fail
.ok_payload:
    mov rdx, rax
    add rax, rcx
    cmp rax, rsi
    ja .fail
    ret
.fail:
    xor eax, eax
    ret

; skip_item_op(rdi=ptr, rsi=end) -> rax=next or 0
skip_item_op:
    push rbx
    push r12
    push r13
    call decode_head
    test rax, rax
    jz .fail
    cmp r8b, 0
    je .scalar_ok
    cmp r8b, 2
    je .blob_ok
    cmp r8b, 3
    je .blob_ok
    cmp r8b, 6
    je .tag_item
    cmp r8b, 4
    je .array_item
    cmp r8b, 5
    je .map_item
    jmp .fail
.scalar_ok:
    jmp .done
.blob_ok:
    add rax, rcx
    cmp rax, rsi
    ja .fail
    jmp .done
.tag_item:
    mov rdi, rax
    call skip_item_op
    test rax, rax
    jz .fail
    jmp .done
.array_item:
    mov r12, rcx
    mov r13, rax
.array_loop:
    test r12, r12
    jz .array_done
    mov rdi, r13
    call skip_item_op
    test rax, rax
    jz .fail
    mov r13, rax
    dec r12
    jmp .array_loop
.array_done:
    mov rax, r13
    jmp .done
.map_item:
    mov r12, rcx
    mov r13, rax
.map_loop:
    test r12, r12
    jz .map_done
    mov rdi, r13
    call skip_item_op
    test rax, rax
    jz .fail
    mov r13, rax
    mov rdi, r13
    call skip_item_op
    test rax, rax
    jz .fail
    mov r13, rax
    dec r12
    jmp .map_loop
.map_done:
    mov rax, r13
    jmp .done
.fail:
    xor eax, eax
.done:
    pop r13
    pop r12
    pop rbx
    ret

; match_bytes(rdx=ptr, rcx=len, r8=ref, r9=ref_len) -> eax=1/0
match_bytes:
    push rbx
    cmp rcx, r9
    jne .no
    xor ebx, ebx
.loop:
    cmp rbx, rcx
    je .yes
    mov al, [rdx + rbx]
    cmp al, [r8 + rbx]
    jne .no
    inc rbx
    jmp .loop
.yes:
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret

; =============================================================================
; Helpers for asb_extract_post_record
; These use r12=cur_ptr, r13=end_ptr (callee convention matching v0_5 style)
; =============================================================================

; read_len_rec: read additional-info length from AL, advance r12
; result in RAX, CF=0 success, CF=1 fail
read_len_rec:
    cmp al, 23
    jbe .small
    cmp al, 24
    je .u8
    cmp al, 25
    je .u16
    cmp al, 26
    je .u32
    jmp .fail
.small:
    movzx rax, al
    clc
    ret
.u8:
    cmp r12, r13
    jae .fail
    movzx rax, byte [r12]
    inc r12
    clc
    ret
.u16:
    lea rcx, [r12+2]
    cmp rcx, r13
    ja .fail
    xor eax, eax
    mov al, [r12]
    shl eax, 8
    mov dl, [r12+1]
    movzx edx, dl
    or eax, edx
    add r12, 2
    clc
    ret
.u32:
    lea rcx, [r12+4]
    cmp rcx, r13
    ja .fail
    xor eax, eax
    mov al, [r12]
    shl rax, 8
    mov dl, [r12+1]
    movzx rdx, dl
    or rax, rdx
    shl rax, 8
    mov dl, [r12+2]
    movzx rdx, dl
    or rax, rdx
    shl rax, 8
    mov dl, [r12+3]
    movzx rdx, dl
    or rax, rdx
    add r12, 4
    clc
    ret
.fail:
    stc
    ret

; read_text_rec: read definite text string at r12
; returns: rdi=ptr, rdx=len, r12 advanced; CF=0 success
read_text_rec:
    cmp r12, r13
    jae .fail
    movzx eax, byte [r12]
    inc r12
    mov ecx, eax
    shr ecx, 5
    and eax, 0x1F
    cmp ecx, 3
    jne .fail
    cmp eax, 31
    je .fail
    call read_len_rec
    jc .fail
    lea rcx, [r12+rax]
    cmp rcx, r13
    ja .fail
    mov rdi, r12
    mov rdx, rax
    mov r12, rcx
    clc
    ret
.fail:
    stc
    ret

; skip_item_rec: skip one CBOR item at r12; CF=0 success
skip_item_rec:
    cmp r12, r13
    jae .fail
    movzx eax, byte [r12]
    inc r12
    mov edx, eax
    shr edx, 5
    and eax, 0x1F
    cmp eax, 31
    je .fail
    cmp edx, 1
    jbe .scalar_number
    cmp edx, 3
    jbe .blob_or_text
    cmp edx, 4
    je .array
    cmp edx, 5
    je .map
    cmp edx, 6
    je .tag
    cmp eax, 23
    jbe .ok
    cmp eax, 24
    je .need1
    cmp eax, 25
    je .need2
    cmp eax, 26
    je .need4
    cmp eax, 27
    je .need8
    jmp .fail
.scalar_number:
    cmp eax, 23
    jbe .ok
    cmp eax, 24
    je .need1
    cmp eax, 25
    je .need2
    cmp eax, 26
    je .need4
    cmp eax, 27
    je .need8
    jmp .fail
.blob_or_text:
    call read_len_rec
    jc .fail
    lea rcx, [r12+rax]
    cmp rcx, r13
    ja .fail
    mov r12, rcx
    clc
    ret
.array:
    call read_len_rec
    jc .fail
    mov rcx, rax
.array_loop_rec:
    test rcx, rcx
    jz .ok
    call skip_item_rec
    jc .fail
    dec rcx
    jmp .array_loop_rec
.map:
    call read_len_rec
    jc .fail
    mov rcx, rax
.map_loop_rec:
    test rcx, rcx
    jz .ok
    call skip_item_rec
    jc .fail
    call skip_item_rec
    jc .fail
    dec rcx
    jmp .map_loop_rec
.tag:
    call read_len_rec
    jc .fail
    call skip_item_rec
    ret
.need1:
    lea rcx, [r12+1]
    cmp rcx, r13
    ja .fail
    mov r12, rcx
    clc
    ret
.need2:
    lea rcx, [r12+2]
    cmp rcx, r13
    ja .fail
    mov r12, rcx
    clc
    ret
.need4:
    lea rcx, [r12+4]
    cmp rcx, r13
    ja .fail
    mov r12, rcx
    clc
    ret
.need8:
    lea rcx, [r12+8]
    cmp rcx, r13
    ja .fail
    mov r12, rcx
    clc
    ret
.ok:
    clc
    ret
.fail:
    stc
    ret
