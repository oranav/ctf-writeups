BITS 64

; No need to zero out rdi as it's already zero
; xor edi, edi
mov rsi, r12
mov dl, 0xff
xor eax, eax
syscall
