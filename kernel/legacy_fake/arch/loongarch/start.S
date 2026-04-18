    .section .text.init
    .globl _start
_start:
    la.global $r3, boot_stack_top
    bl kernel_main
1:
    b 1b

    .section .bss.stack,"aw",@nobits
    .align 12
boot_stack:
    .space 16384
    .globl boot_stack_top
boot_stack_top:
