#include <stdint.h>
#include "kernel.h"

#define UART_BASE ((volatile uint8_t *)0x10000000UL)
#define UART_THR 0
#define UART_LSR 5
#define UART_LSR_THRE 0x20

void uart_init(void) {
}

void uart_putc(char ch) {
    while ((UART_BASE[UART_LSR] & UART_LSR_THRE) == 0) {
    }
    UART_BASE[UART_THR] = (uint8_t)ch;
}
