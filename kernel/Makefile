ARCH ?= riscv
OUT ?= ../kernel-$(ARCH)
KERNEL_DIR := $(CURDIR)
WORK_ROOT ?= $(KERNEL_DIR)/work
WORK_TREE ?= $(KERNEL_DIR)/starry-next
BOOTSTRAP := $(KERNEL_DIR)/scripts/bootstrap_starry_overlay.sh
MUSL_TOOLCHAIN_PATHS := /opt/riscv64-linux-musl-cross/bin:/opt/loongarch64-linux-musl-cross/bin:$(HOME)/.cache/osk-toolchains/riscv64-linux-musl-cross/bin:$(HOME)/.cache/osk-toolchains/loongarch64-linux-musl-cross/bin

.PHONY: all prepare clean clean-work run check-basic-rv check-basic-la

all: $(OUT)

prepare:
	"$(BOOTSTRAP)"

ifeq ($(ARCH),riscv)
$(OUT): prepare
	cd "$(WORK_TREE)" && PATH="$(MUSL_TOOLCHAIN_PATHS):$$PATH" RUSTUP_TOOLCHAIN=nightly-2025-01-18 $(MAKE) test_build ARCH=riscv64 AX_TESTCASE=oscomp BUS=mmio FEATURES=lwext4_rs,sched_rr APP_FEATURES=lwext4_rs
	cp "$(WORK_TREE)/kernel-rv" "$(OUT)"
endif

ifeq ($(ARCH),loongarch)
$(OUT): prepare
	cd "$(WORK_TREE)" && PATH="$(MUSL_TOOLCHAIN_PATHS):$$PATH" RUSTUP_TOOLCHAIN=nightly-2025-01-18 $(MAKE) test_build ARCH=loongarch64 AX_TESTCASE=oscomp FEATURES=lwext4_rs,sched_rr APP_FEATURES=lwext4_rs
	cp "$(WORK_TREE)/kernel-la" "$(OUT)"
endif

clean:
	rm -f "$(OUT)"

clean-work:
	rm -rf "$(WORK_ROOT)"
