# ==================== 编译器配置 ====================

# x86编译器（默认）
CC = gcc

# ARM架构编译器
CC_ARM64 = aarch64-linux-gnu-gcc
CC_ARM32 = arm-linux-gnueabihf-gcc

# ==================== 编译选项 ====================

# x86编译选项
CFLAGS = -Wall -Wextra -O2 -std=gnu11
LDFLAGS = 

# ARM64编译选项
CFLAGS_ARM64 = -Wall -Wextra -O2 -std=gnu11
LDFLAGS_ARM64 = 

# ARM32编译选项
CFLAGS_ARM32 = -Wall -Wextra -O2 -std=gnu11
LDFLAGS_ARM32 = 

# ==================== x86编译目标（默认） ====================

all: hsm_test

hsm_test: hsm_test.c hsm_lite.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ==================== ARM64编译目标 ====================

arm64: hsm_test_arm64

hsm_test_arm64: hsm_test.c hsm_lite.c
	$(CC_ARM64) $(CFLAGS_ARM64) -o $@ $^ $(LDFLAGS_ARM64)

# ==================== ARM32编译目标 ====================

arm32: hsm_test_arm32

hsm_test_arm32: hsm_test.c hsm_lite.c
	$(CC_ARM32) $(CFLAGS_ARM32) -o $@ $^ $(LDFLAGS_ARM32)

# ==================== 清理目标 ====================

clean:
	rm -f hsm_test *.o

clean-arm64:
	rm -f hsm_test_arm64 *.o

clean-arm32:
	rm -f hsm_test_arm32 *.o

clean-all: clean clean-arm64 clean-arm32

# ==================== 辅助目标 ====================

# 编译所有架构版本
all-arch: all arm64 arm32

# 显示帮助信息
help:
	@echo "hsm-lite 编译选项:"
	@echo "  make           - 编译x86版本（默认）"
	@echo "  make arm64     - 编译ARM64版本"
	@echo "  make arm32     - 编译ARM32版本"
	@echo "  make all-arch  - 编译所有架构版本"
	@echo ""
	@echo "清理选项:"
	@echo "  make clean         - 清理x86版本"
	@echo "  make clean-arm64   - 清理ARM64版本"
	@echo "  make clean-arm32   - 清理ARM32版本"
	@echo "  make clean-all     - 清理所有版本"

.PHONY: all arm64 arm32 clean clean-arm64 clean-arm32 clean-all all-arch help