    .section .text
    .globl _start
_start:
    ori         $t0, $zero, 0x1
    lu52i.d     $t0, $t0, -2048
    csrwr       $t0, 0x180
    ori         $t0, $zero, 0x11
    lu52i.d     $t0, $t0, -1792
    csrwr       $t0, 0x181
    li.d        $t0, 0x9000000080000000
    jirl        $zero, $t0, 0
