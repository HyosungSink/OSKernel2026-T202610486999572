#include "kernel.h"

void uart_puthex64(unsigned long long value) {
    static const char hex[] = "0123456789abcdef";
    int shift;

    uart_puts("0x");
    for (shift = 60; shift >= 0; shift -= 4) {
        uart_putc(hex[(value >> shift) & 0xf]);
    }
}

void uart_putdec(unsigned long long value) {
    char buf[32];
    int i = 0;

    if (value == 0) {
        uart_putc('0');
        return;
    }

    while (value != 0) {
        buf[i++] = (char)('0' + (value % 10));
        value /= 10;
    }

    while (i > 0) {
        uart_putc(buf[--i]);
    }
}

void kernel_main(unsigned long long arg0, unsigned long long arg1, unsigned long long arg2) {
    (void)arg0;
    (void)arg1;
    (void)arg2;
    uart_init();
    run_contest_suite();
    platform_halt();
}
