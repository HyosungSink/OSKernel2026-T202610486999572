#ifndef OSKERNEL2026_KERNEL_H
#define OSKERNEL2026_KERNEL_H

void uart_init(void);
void uart_putc(char ch);
void platform_halt(void);
const char *platform_arch_name(void);
void uart_puthex64(unsigned long long value);
void uart_putdec(unsigned long long value);
void run_contest_suite(void);

static inline void uart_puts(const char *s) {
    while (*s != '\0') {
        uart_putc(*s++);
    }
}

#endif
