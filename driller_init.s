.text
.globl    driller_init
driller_init:
    pushq %rax
start_driller_loop:
    callq fork
    testl %eax, %eax
    je exit_driller_loop
    int3
    cmpl $0xabadcafe, %eax
    jne start_driller_loop
exit_driller_loop:
    popq %rax
    retq
