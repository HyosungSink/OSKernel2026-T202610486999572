OUTPUT_ARCH(loongarch)
ENTRY(_start)

SECTIONS {
    . = 0x00200000;

    .text : {
        *(.text.init)
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss.stack)
        *(.bss .bss.*)
        *(COMMON)
    }
}
