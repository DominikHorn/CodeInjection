section .data
	msg db	"hello, world!", 0xa

section .text
	global _start

_start:
	mov	rax, 1
	mov	rdi, rax
	mov	rsi, msg
	mov	rdx, 15
	syscall
	
	mov	rax, 60
	mov	rdi, 0
	syscall
