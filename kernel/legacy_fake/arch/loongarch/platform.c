#include "kernel.h"

#define VIRT_GED_REG_ADDR 0x100e001cUL
#define ACPI_GED_REG_SLEEP_CTL 0x00
#define ACPI_GED_SLP_TYP_S5 0x05
#define ACPI_GED_SLP_TYP_POS 0x02
#define ACPI_GED_SLP_EN 0x20

void platform_halt(void) {
    volatile unsigned char *ged_regs = (volatile unsigned char *)VIRT_GED_REG_ADDR;

    ged_regs[ACPI_GED_REG_SLEEP_CTL] =
        (unsigned char)((ACPI_GED_SLP_TYP_S5 << ACPI_GED_SLP_TYP_POS) | ACPI_GED_SLP_EN);
    for (;;) {
        asm volatile ("idle 0");
    }
}

const char *platform_arch_name(void) {
    return "loongarch64";
}
