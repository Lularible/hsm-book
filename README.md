# HSM 技术书 — 从思想实验到安全基石

一本从岩画密码学到 HSM 集成实战的完整开源技术书。

### 实际运行效果
<img width="910" height="1150" alt="hsm_demo" src="https://github.com/user-attachments/assets/e34e3891-3f12-47b1-b16f-5bcc448db597" />


## 这本书讲了什么

全书 57 节，分六章：

- **第一章（5 节）**：从岩壁上的第一条信息开始，讲安全通信的起源——信道的原罪、密码学的诞生、信任从软件到硬件的跃迁
- **第二章（4 节）**：认识 HSM 这个"数字保险箱"——两种物理形态、标准生态全景、从 Host 到密室的通信旅程
- **第三章（21 节）**：深度解析 PKCS#11 v3.1 规范——Slot/Token/Session/Object 对象模型、所有函数族、AES/RSA/ECC/哈希机制
- **第四章（15 节）**：走进 SoftHSM2 源码——解析 SoftHSM.cpp 心脏代码、Object/Slot/Session/Handle 管理模块、CryptoFactory 双后端架构
- **第五章（4 节）**：亲手实现 hsm-lite（约 620 行 C），完整 PKCS#11 核心流程，x86/ARM64/ARM32 多架构编译
- **第六章（8 节）**：真实 SDK 集成经验——三层驱动架构、I2C/SPI 通信踩坑与修复、AUTOSAR UDS 服务实现

**无密码学先修要求——第一章从岩画讲起，逐步建立安全通信的直觉。后五章涉及 C 代码和嵌入式通信，需具备基础编程阅读能力。**

## 快速开始

在线阅读：直接浏览 `chapters/` 目录下的 Markdown 文件，按文件名顺序阅读。

运行示例代码：

```bash
cd hsm-lite
make

# 运行测试
./hsm_test

# ARM64 编译
make arm64
```

## 许可证

书籍内容：[CC BY-NC-ND 4.0](LICENSE) · hsm-lite 源码：MIT

## 姊妹篇

本书是"汽车电子七部曲"系列中的一部。另外四部已发布：

- **[从沙子到车辙——一个工程师的理解](https://github.com/Lularible/from-sand-to-ruts)** — 从图灵机到 CAN 总线，从半导体物理到 AUTOSAR，一部为汽车电子工程师写的全景入门
- **[PTP 技术书——从思想实验到协议实现](https://github.com/Lularible/ptp-book)** — 从时间同步的思想实验开始，到 PTP 协议实现，逐机制拆解 + 动手实践
- **[存储 技术书——在不可靠的硬件上构建可靠的数据家园](https://github.com/Lularible/storage-book)** — 一本关于存储技术演进与文件系统实现的深度技术书籍
- **[UDS 技术书——从望闻问切到UDS协议实现](https://github.com/Lularible/uds-book)** — 一本从诊断元问题出发，直通ISO 14229协议规范与AUTOSAR DCM源码、再到亲手实现UDS栈的技术书

"汽车电子七部曲"是一个持续更新的系列——还有功能安全、软件工程两本在打磨中。
如果觉得这系列对你有用，不妨给个 ⭐ 关注进度。
