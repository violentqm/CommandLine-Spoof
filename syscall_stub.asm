section .text
global indirect_syscall

indirect_syscall:
    mov rax, rcx          ; Syscall number (from 1st C arg)
    mov r10, rdx          ; Syscall Arg1 (from 2nd C arg)
    mov rdx, r8           ; Syscall Arg2 (from 3rd C arg)
    mov r8, r9            ; Syscall Arg3 (from 4th C arg)
    mov r9, [rsp + 40]    ; Syscall Arg4 (from 5th C arg on stack)
    ; Note: This stub only supports up to 4 arguments to the syscall itself.
    ; For syscalls with more arguments, a more complex stub would be needed
    ; to move more arguments from the C stack to the correct registers/syscall stack positions.
    syscall
    ret
