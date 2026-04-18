.PHONY: all online-self-contained refresh-embedded-runtime clean clean-logs run-rv run-la run-basic-rv run-basic-la kernel-rv kernel-la \
	la-bios check-basic-rv check-basic-la check-remaining-rv check-remaining-la \
	check-full-local

LA_BIOS_SRC := kernel/scripts/la-qemu-bios.S
LA_BIOS_LD := kernel/scripts/la-qemu-bios.ld
LA_BIOS_ELF := kernel/work/la-qemu-bios.elf
LA_BIOS_BIN := kernel/work/la-qemu-bios.bin
LA_RAW := kernel/starry-next/starry-next_loongarch64-qemu-virt.bin
LA_QEMU_FW_DIR := dev/qemu-la-fw
QEMU_SYSTEM_RISCV64 ?= $(shell if [ -x /opt/qemu-bin-10.0.2/bin/qemu-system-riscv64 ]; then echo /opt/qemu-bin-10.0.2/bin/qemu-system-riscv64; else echo qemu-system-riscv64; fi)
QEMU_SYSTEM_LOONGARCH64 ?= $(shell if [ -x /opt/qemu-bin-10.0.2/bin/qemu-system-loongarch64 ]; then echo /opt/qemu-bin-10.0.2/bin/qemu-system-loongarch64; else echo qemu-system-loongarch64; fi)
LA_CC ?= $(shell \
	if command -v loongarch64-linux-musl-gcc >/dev/null 2>&1; then \
		echo loongarch64-linux-musl-gcc; \
	elif command -v loongarch64-linux-gnu-gcc >/dev/null 2>&1; then \
		echo loongarch64-linux-gnu-gcc; \
	else \
		echo loongarch64-linux-gnu-gcc-14; \
	fi)
LA_OBJCOPY ?= $(shell \
	if command -v loongarch64-linux-musl-objcopy >/dev/null 2>&1; then \
		echo loongarch64-linux-musl-objcopy; \
	else \
		echo loongarch64-linux-gnu-objcopy; \
	fi)
BUILD_BASIC_IMAGE := tools/build_basic_image.sh
BUILD_REMAINING_IMAGE := tools/build_remaining_image.sh
TESTSUITS_ROOT ?= testsuits-for-oskernel-pre-2025
ONLINE_REFRESH_ROOT := kernel/starry-next/embedded-runtime-refresh
REFRESH_EMBEDDED_RUNTIME := tools/refresh_embedded_runtime.sh

# Online judge only calls `make all`; keep the full submission pipeline here.
# Extra runtime fixes are embedded into the kernels by kernel/starry-next/build.rs,
# so no ignored dev/full-suite cache is required at evaluation time.
all: kernel-rv kernel-la

refresh-embedded-runtime:
	@$(REFRESH_EMBEDDED_RUNTIME)

online-self-contained: refresh-embedded-runtime
	@if [ ! -d "$(ONLINE_REFRESH_ROOT)" ]; then \
		echo "skip online-self-contained runtime verification: missing $(ONLINE_REFRESH_ROOT), continue with toolchain/vendored fallbacks"; \
	else \
		missing=0; \
		for path in \
			"$(ONLINE_REFRESH_ROOT)/rv/glibc/basic" \
			"$(ONLINE_REFRESH_ROOT)/rv/musl/basic" \
			"$(ONLINE_REFRESH_ROOT)/la/glibc/basic" \
			"$(ONLINE_REFRESH_ROOT)/la/musl/basic" \
			"$(ONLINE_REFRESH_ROOT)/rv/glibc/lib/ld-linux-riscv64-lp64d.so.1" \
			"$(ONLINE_REFRESH_ROOT)/rv/glibc/lib/libc.so.6" \
			"$(ONLINE_REFRESH_ROOT)/rv/glibc/cyclictest" \
			"$(ONLINE_REFRESH_ROOT)/rv/glibc/hackbench" \
			"$(ONLINE_REFRESH_ROOT)/la/glibc/cyclictest" \
			"$(ONLINE_REFRESH_ROOT)/la/glibc/hackbench"; \
		do \
			if [ ! -e "$$path" ]; then \
				echo "warn online-self-contained: missing $$path, compile will continue with degraded embedded runtime"; \
				missing=1; \
			fi; \
		done; \
		if [ "$$missing" -ne 0 ]; then \
			echo "warn online-self-contained: runtime verification incomplete"; \
		fi; \
	fi

kernel-rv: online-self-contained
	$(MAKE) -C kernel ARCH=riscv OUT=../kernel-rv

kernel-la: online-self-contained
	$(MAKE) -C kernel ARCH=loongarch OUT=../kernel-la

la-bios: $(LA_BIOS_BIN)

$(LA_BIOS_BIN): $(LA_BIOS_SRC) $(LA_BIOS_LD)
	mkdir -p kernel/work
	$(LA_CC) -nostdlib -static -Wl,-T,$(LA_BIOS_LD) -Wl,--build-id=none -o $(LA_BIOS_ELF) $(LA_BIOS_SRC)
	$(LA_OBJCOPY) -O binary -j .text $(LA_BIOS_ELF) $(LA_BIOS_BIN)

clean:
	$(MAKE) -C kernel clean
	rm -f kernel-rv kernel-la $(LA_BIOS_ELF) $(LA_BIOS_BIN)

clean-logs:
	rm -rf dev/full-suite dev/logs
	rm -f log.txt score.txt Riscv输出.txt LoongArch输出.txt

run-rv: kernel-rv
	$(QEMU_SYSTEM_RISCV64) -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 -bios default \
		-device virtio-net-device,netdev=net \
		-netdev user,id=net \
		-rtc base=utc \
		-no-reboot

run-la: kernel-la la-bios
	$(QEMU_SYSTEM_LOONGARCH64) -kernel kernel-la -m 1G -nographic -smp 1 \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0 \
		-rtc base=utc \
		-no-reboot

run-basic-rv: kernel-rv
	set -e; img=$$(mktemp /tmp/osk-basic-rv.run.XXXXXX.img); trap 'rm -f "$$img"' EXIT; \
	$(BUILD_BASIC_IMAGE) rv "$$img"; \
	$(QEMU_SYSTEM_RISCV64) -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 -bios default \
		-drive file=$$img,if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
		-device virtio-net-device,netdev=net \
		-netdev user,id=net \
		-rtc base=utc \
		-no-reboot

run-basic-la: kernel-la la-bios
	set -e; img=$$(mktemp /tmp/osk-basic-la.run.XXXXXX.img); trap 'rm -f "$$img"' EXIT; \
	$(BUILD_BASIC_IMAGE) la "$$img"; \
	$(QEMU_SYSTEM_LOONGARCH64) -kernel kernel-la -m 1G -nographic -smp 1 \
		-drive file=$$img,if=none,format=raw,id=x0 \
		-device virtio-blk-pci,drive=x0 \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0 \
		-rtc base=utc \
		-no-reboot

check-basic-rv: kernel-rv
	mkdir -p dev/logs
	set -e; img=$$(mktemp /tmp/osk-basic-rv.check.XXXXXX.img); trap 'rm -f "$$img"' EXIT; \
	$(BUILD_BASIC_IMAGE) rv "$$img"; \
	timeout 20s $(QEMU_SYSTEM_RISCV64) -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 -bios default \
		-drive file=$$img,if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
		-device virtio-net-device,netdev=net \
		-netdev user,id=net \
		-rtc base=utc \
		-no-reboot > dev/logs/basic-rv.out 2>&1
	python3 tools/extract_group.py basic dev/logs/basic-rv.out > dev/logs/basic-rv-basic.out
	python3 $(TESTSUITS_ROOT)/basic/user/src/oscomp/test_runner.py dev/logs/basic-rv-basic.out

check-basic-la: kernel-la la-bios
	mkdir -p dev/logs
	set -e; img=$$(mktemp /tmp/osk-basic-la.check.XXXXXX.img); trap 'rm -f "$$img"' EXIT; \
	$(BUILD_BASIC_IMAGE) la "$$img"; \
	timeout 25s $(QEMU_SYSTEM_LOONGARCH64) -kernel kernel-la -m 1G -nographic -smp 1 \
		-drive file=$$img,if=none,format=raw,id=x0 \
		-device virtio-blk-pci,drive=x0 \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0 \
		-rtc base=utc \
		-no-reboot > dev/logs/basic-la.out 2>&1
	python3 tools/extract_group.py basic dev/logs/basic-la.out > dev/logs/basic-la-basic.out
	python3 $(TESTSUITS_ROOT)/basic/user/src/oscomp/test_runner.py dev/logs/basic-la-basic.out

check-remaining-rv: kernel-rv
	mkdir -p dev/logs
	set -e; img=$$(mktemp /tmp/osk-remaining-rv.check.XXXXXX.img); trap 'rm -f "$$img"' EXIT; \
	TESTSUITS_ROOT="$(TESTSUITS_ROOT)" $(BUILD_REMAINING_IMAGE) rv "$$img"; \
	timeout 600s $(QEMU_SYSTEM_RISCV64) -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 -bios default \
		-drive file=$$img,if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
		-device virtio-net-device,netdev=net \
		-netdev user,id=net \
		-rtc base=utc \
		-no-reboot > dev/logs/remaining-rv.out 2>&1
	TESTSUITS_ROOT="$(TESTSUITS_ROOT)" python3 tools/validate_remaining_groups.py dev/logs/remaining-rv.out

check-remaining-la: kernel-la la-bios
	mkdir -p dev/logs
	set -e; img=$$(mktemp /tmp/osk-remaining-la.check.XXXXXX.img); trap 'rm -f "$$img"' EXIT; \
	TESTSUITS_ROOT="$(TESTSUITS_ROOT)" $(BUILD_REMAINING_IMAGE) la "$$img"; \
	timeout 600s $(QEMU_SYSTEM_LOONGARCH64) -kernel kernel-la -m 1G -nographic -smp 1 \
		-drive file=$$img,if=none,format=raw,id=x0 \
		-device virtio-blk-pci,drive=x0 \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0 \
		-rtc base=utc \
		-no-reboot > dev/logs/remaining-la.out 2>&1
	TESTSUITS_ROOT="$(TESTSUITS_ROOT)" python3 tools/validate_remaining_groups.py dev/logs/remaining-la.out

check-full-local: kernel-rv kernel-la la-bios
	TESTSUITS_ROOT="$(TESTSUITS_ROOT)" python3 tools/run_full_local_suite.py
