#include <stdint.h>
#include "kernel.h"

#define UART0_REG ((volatile uint8_t *)0x1fe001e0UL)
#define UART_THR 0
#define UART_LSR 5
#define UART_LSR_THRE 0x20

void uart_init(void) {
}

void uart_putc(char ch) {
    while ((UART0_REG[UART_LSR] & UART_LSR_THRE) == 0) {
    }
    UART0_REG[UART_THR] = (uint8_t)ch;
}
