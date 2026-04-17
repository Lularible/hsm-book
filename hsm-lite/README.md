# HSM Lite - 轻量级PKCS#11实现

一个用于教学的轻量级HSM（Hardware Security Module）实现，遵循PKCS#11 v3.1规范核心接口。

## 项目特点

- **简洁易懂**：代码总量约500行，注释详细
- **核心功能**：实现PKCS#11核心接口
- **易于学习**：适合理解HSM和PKCS#11核心机制
- **可实际运行**：真正能够加密解密
- **无编译警告**：代码规范严格，适合教学
- **多架构支持**：x86、ARM32、ARM64

## 技术选型

- **密钥类型**：AES-256
- **加密模式**：ECB、CBC（教学简化实现）
- **随机数源**：/dev/urandom

## 实现的PKCS#11函数

| 函数 | 描述 |
|:---|:---|
| C_Initialize | 初始化Cryptoki库 |
| C_Finalize | 清理Cryptoki库 |
| C_GetSlotList | 获取Slot列表 |
| C_OpenSession | 打开Session |
| C_CloseSession | 关闭Session |
| C_CreateObject | 创建对象（导入密钥） |
| C_DestroyObject | 销毁对象 |
| C_GetAttributeValue | 获取属性值 |
| C_GenerateKey | 生成密钥 |
| C_EncryptInit | 初始化加密操作 |
| C_Encrypt | 执行加密 |
| C_DecryptInit | 初始化解密操作 |
| C_Decrypt | 执行解密 |
| C_GenerateRandom | 生成随机数 |

## 快速开始

### 编译

#### x86架构（默认）

```bash
make
```

#### ARM64架构

```bash
make arm64
```

生成文件：`hsm_test_arm64`

#### ARM32架构

```bash
make arm32
```

生成文件：`hsm_test_arm32`

#### 编译所有架构

```bash
make all-arch
```

#### 查看帮助

```bash
make help
```

#### 交叉编译工具链安装

**Ubuntu/Debian系统**：
```bash
# 安装ARM64工具链
sudo apt install gcc-aarch64-linux-gnu

# 安装ARM32工具链（硬浮点）
sudo apt install gcc-arm-linux-gnueabihf
```

#### 验证编译结果

```bash
file hsm_test        # ELF 64-bit x86-64
file hsm_test_arm64  # ELF 64-bit ARM aarch64
file hsm_test_arm32  # ELF 32-bit ARM
```

### 运行测试

```bash
./hsm_test
```

输出示例：
```
========================================
  hsm-lite Test Suite (version 1.0.0)
========================================

=== Test 1: Basic Flow ===

[hsm-lite] Initialized (version 1.0.0)
PASS: C_Initialize
PASS: C_GetSlotList (count=1)
PASS: C_OpenSession (handle=1)
PASS: C_CloseSession
PASS: C_Finalize

=== Test 2: Key Generation ===

[hsm-lite] GenerateKey: handle=1 (AES-256)
Key value: a1b2c3d4e5f6... (32 bytes)
PASS: C_GenerateKey

=== Test 3: Encrypt/Decrypt ===

Plaintext: 48656c6c6f2c2068736d2d6c69746521
Ciphertext: e9d8c7b6a5f4...
Decrypted: 48656c6c6f2c2068736d2d6c69746521
PASS: Plaintext matches decrypted text

=== Test 4: Random Generation ===

Random: 1a2b3c4d5e6f...

========================================
  ALL TESTS PASSED
========================================
```

## 文件结构

```
hsm-lite/
├── README.md           # 项目说明
├── Makefile            # 编译脚本
├── hsm_lite.h          # PKCS#11类型定义（简化）
├── hsm_lite.c          # PKCS#11核心实现
├── hsm_test.c          # 测试程序
└── .gitignore          # Git忽略文件
```

## PKCS#11核心概念

### Slot与Session

```
Slot 0 → 软件Token
         ↓
    Session（操作通道）
         ↓
    Object（密钥对象）
         ↓
    Operation（加密/解密）
```

### 密钥对象

hsm-lite支持AES-256密钥：
- C_GenerateKey：生成新密钥
- C_CreateObject：导入已有密钥
- C_DestroyObject：销毁密钥
- C_GetAttributeValue：读取密钥属性

### 加密流程

```c
// 生成密钥
C_GenerateKey(session, &mechanism, NULL, 0, &hKey);

// 初始化加密
C_EncryptInit(session, &mechanism, hKey);

// 执行加密
C_Encrypt(session, plaintext, pt_len, ciphertext, &ct_len);

// 初始化解密
C_DecryptInit(session, &mechanism, hKey);

// 执行解密
C_Decrypt(session, ciphertext, ct_len, decrypted, &dec_len);
```

## 教学说明

### 简化说明

本实现为教学目的做了以下简化：

1. **加密算法**：使用简单的异或操作，而非真实的AES算法
   - 目的：让读者理解PKCS#11接口流程，而非密码学细节
   - 实际应用应使用OpenSSL等成熟库

2. **密钥存储**：密钥存储在内存中，无持久化
   - 目的：简化实现，聚焦接口逻辑
   - 实际HSM使用加密文件或硬件存储

3. **Session管理**：简化状态管理
   - 目的：减少代码量，便于理解
   - 实际HSM需要完整的状态机和权限检查

4. **Slot/Token**：仅支持一个Slot
   - 目的：简化架构
   - 实际HSM可能支持多个Token

### 学习路径

推荐学习顺序：

1. 阅读 README 了解项目概况
2. 研究 hsm_lite.h 理解PKCS#11类型定义
3. 分析 hsm_lite.c 学习核心接口实现
4. 运行 hsm_test 观察完整调用流程
5. 修改代码进行实验

### 与真实HSM的差异

| 特性 | hsm-lite | 真实HSM |
|:---|:---|:---|
| 加密算法 | 异或（教学） | AES硬件加速 |
| 密钥存储 | 内存 | 加密Flash |
| 物理隔离 | 无 | 独立安全芯片 |
| 认证机制 | 无 | FIPS 140-3 |
| 机制数量 | 3种 | 100+种 |
| 函数数量 | 13个 | ~400个 |

## 扩展方向

可继续改进：

- [ ] 使用OpenSSL实现真实AES
- [ ] 添加RSA密钥支持
- [ ] 添加签名验证功能
- [ ] 实现密钥持久化存储
- [ ] 添加PIN认证机制
- [ ] 支持多Slot

## 参考资料

- [PKCS#11 v3.1规范](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html)
- [SoftHSM2项目](https://github.com/opendnssec/SoftHSMv2)
- [HSM技术书（配套教程）](../chapters/)

## 许可证

MIT License

## 作者

本代码为HSM教程配套示例，用于教学目的。

## 贡献

欢迎提交Issue和Pull Request！