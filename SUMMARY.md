# 目录 (SUMMARY)

## HSM技术书：从思想实验到安全基石

## 第一章：安全通信的起源——从岩画到密码学

* [1.1 岩壁上的第一条信息](chapters/1.1-岩壁上的第一条信息.md)
* [1.2 信道的"原罪"](chapters/1.2-信道的原罪.md)
* [1.3 从符号到文字：协议的标准化](chapters/1.3-从符号到文字-协议的标准化.md)
* [1.4 当信道不再可信：密码学的诞生](chapters/1.4-当信道不再可信-密码学的诞生.md)
* [1.5 信任的终极锚点：从软件到硬件](chapters/1.5-信任的终极锚点-从软件到硬件.md)

## 第二章：HSM世界观——认识HSM世界的"角色"

* [2.1 HSM是什么：从数字保险箱说起](chapters/2.1-HSM是什么-从数字保险箱说起.md)
* [2.2 HSM的两种物理形态：独立保险箱 vs 内置保险箱](chapters/2.2-HSM的两种物理形态.md)
* [2.3 HSM标准生态全景：一个"工"字形的世界](chapters/2.3-HSM标准生态全景.md)
* [2.4 HSM通信全景：从Host到密室的完整旅程](chapters/2.4-HSM通信全景.md)

## 第三章：HSM的"普通话"——PKCS#11标准深度解析

### 基础概念

* [3.1 PKCS#11的设计哲学](chapters/3.1-PKCS#11的设计哲学.md)
* [3.2 核心对象模型：Slot、Token、Session、Object的"四重奏"](chapters/3.2-核心对象模型.md)
* [3.3 PKCS#11的安全哲学："提供机制而非策略"的深意](chapters/3.3-PKCS#11的安全哲学.md)
* [3.4 Session状态与并发管理：PKCS#11的"会话状态机"](chapters/3.4-Session状态与并发管理.md)
* [3.5 Object与属性：密码世界的"数据容器"](chapters/3.5-Object与属性.md)

### 属性详解

* [3.6 通用属性详解：所有Object共享的"基因"](chapters/3.6-通用属性详解.md)
* [3.7 密钥对象与安全属性：密码安全的"四大金刚"](chapters/3.7-密钥对象与安全属性.md)
* [3.8 证书对象：数字世界的"身份证明"](chapters/3.8-证书对象.md)
* [3.9 硬件特征对象：密码设备独有的"特异功能"](chapters/3.9-硬件特征对象.md)

### 函数接口

* [3.10 初始化与Slot管理函数：打开密码世界的"大门"](chapters/3.10-初始化与Slot管理函数.md)
* [3.11 Session管理函数：应用程序与Token的"握手协议"](chapters/3.11-Session管理函数.md)
* [3.12 Object管理函数：密钥与证书的"仓储管理"](chapters/3.12-Object管理函数.md)
* [3.13 加密解密函数：密码运算的"生产线"](chapters/3.13-加密解密函数.md)
* [3.14 签名验证函数：密码世界的"签名盖章"](chapters/3.14-签名验证函数.md)
* [3.15 哈希与MAC函数：数据的"指纹与印章"](chapters/3.15-哈希与MAC函数.md)
* [3.16 密钥管理函数：密钥的"生与死"](chapters/3.16-密钥管理函数.md)

### 机制系统

* [3.17 Mechanism系统：密码算法的"配方库"](chapters/3.17-Mechanism系统.md)
* [3.18 AES机制详解：对称加密的"瑞士军刀"](chapters/3.18-AES机制详解.md)
* [3.19 RSA机制详解：非对称加密的"门面担当"](chapters/3.19-RSA机制详解.md)
* [3.20 ECC与哈希机制：现代密码学的"双子星"](chapters/3.20-ECC与哈希机制.md)
* [3.21 安全属性组合实战：密钥安全的"最佳配方"](chapters/3.21-安全属性组合实战.md)

## 第四章：HSM的"图纸"——开源实现深度解析

### 项目概览

* [4.1 SoftHSM2项目概述](chapters/4.1-SoftHSM2项目概述.md)
* [4.2 从PKCS#11头文件到实现：解剖"标准与现实的桥梁"](chapters/4.2-从PKCS11头文件到实现.md)

### 核心实现

* [4.3 SoftHSM.cpp深度解析：密码库的"心脏"](chapters/4.3-SoftHSMcpp深度解析.md)
* [4.4 P11Objects与P11Attributes：对象的"DNA"](chapters/4.4-P11Objects与P11Attributes.md)

### 管理模块

* [4.5 Slot管理模块：Token的"注册中心"](chapters/4.5-Slot管理模块.md)
* [4.6 Session管理模块：跟踪每一次交互](chapters/4.6-Session管理模块.md)
* [4.7 Handle管理模块：对象的"身份证发放"](chapters/4.7-Handle管理模块.md)

### 存储模块

* [4.8 Object存储架构：密钥的"永久家园"](chapters/4.8-Object存储架构.md)
* [4.9 Token存储实现：PIN与元数据的安全存储](chapters/4.9-Token存储实现.md)

### 密码模块

* [4.10 CryptoFactory架构：密码算法的"万能适配器"](chapters/4.10-CryptoFactory架构.md)
* [4.11 对称算法实现：AES与DES的密码引擎](chapters/4.11-对称算法实现.md)
* [4.12 非对称算法实现：RSA与ECDSA的密码引擎](chapters/4.12-非对称算法实现.md)
* [4.13 哈希与MAC实现：数据指纹与消息认证](chapters/4.13-哈希与MAC实现.md)
* [4.14 RNG与密钥派生：密码系统的"熵源"](chapters/4.14-RNG与密钥派生.md)

### 总结

* [4.15 从开源到闭源：厂商闭源的背后逻辑](chapters/4.15-从开源到闭源.md)

## 第五章：从零构建——设计一个轻量级HSM

* [5.1 hsm-lite项目概述：教学级PKCS#11实现](chapters/5.1-hsm-lite项目概述.md)
* [5.2 PKCS#11核心接口实现：从代码到理解](chapters/5.2-PKCS11核心接口实现.md)
* [5.3 安全存储与密钥管理：内存模拟设计](chapters/5.3-安全存储与密钥管理.md)
* [5.4 测试程序与编译：验证hsm-lite](chapters/5.4-通信协议与集成.md)

## 第六章：HSM集成实战——从SDK到产品

* [6.1 SDK集成概述：从"自己实现"到"集成现成"](chapters/6.1-SDK集成概述.md)
* [6.2 驱动架构设计：分层思想的现实应用](chapters/6.2-驱动架构设计.md)
* [6.3 通信协议实战：从代码到波形的"变身"](chapters/6.3-通信协议实战.md)
* [6.4 踩坑与修复：真实调试经验](chapters/6.4-踩坑与修复.md)
* [6.5 安全机制实现：PIN与密钥管理](chapters/6.5-安全机制实现.md)
* [6.6 AUTOSAR集成实战：UDS服务的实现](chapters/6.6-AUTOSAR集成实战.md)
* [6.7 TCP命令接口：开发调试的便捷通道](chapters/6.7-TCP命令接口.md)
* [6.8 集成经验总结：从理论到实践的完整闭环](chapters/6.8-集成经验总结.md)