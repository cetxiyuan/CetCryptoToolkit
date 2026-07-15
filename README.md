# CetCryptoToolkit

> 作者：CetXiyuan（璟·汐源忆醉）| 版本：v2.5.0 | 平台：Windows | Qt 5.15.2 (MinGW, 32-bit) | OpenSSL 3.x

CetCryptoToolkit 是一款面向开发者和安全工程师的**密码学工具箱**桌面应用程序，集成了 PKI 证书管理、非对称加密/签名、对称加密、国密算法（SM2/SM3/SM4）等常用密码学操作。

---

## 功能特性

### 🔐 证书管理（PKI）
- 支持三级 PKI 体系：一级根证书 → 二级根证书 → 终端证书
- 支持 RSA / EC / SM2 密钥算法
- 自动生成 `.key` / `.pub` / `.csr` / `.crt` / `.der` / `.p7b` / `.pfx` 全套文件
- 支持自定义 SubjectDN、有效期、证书扩展字段（SAN 等）

### 🔑 非对称加密（AEA）
- RSA / EC / SM2 公钥加密 / 私钥解密
- 11 种摘要算法：MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512 / SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 / SM3
- 数字签名与验签（含 SM2 ZA 值 userId 支持）

### 🔒 对称加密（SEA）
- AES：128 / 192 / 256-bit，支持 ECB / CBC / GCM / CTR 模式
- SM4：128-bit，支持 ECB / CBC 模式（GCM / CTR 暂不支持）
- AES-128-CMAC 消息认证码计算
- 支持文件加解密和 Hex / Base64 格式输入输出

---

## 快速开始

### 环境要求
- Qt 5.15.2 (MinGW 32-bit)
- OpenSSL 3.x（已预置在 `libs/` 目录）

### 构建

```bash
# qmake 构建（推荐）
cd CetCryptoToolkit
qmake CetCryptoToolkit.pro
mingw32-make -j4

# CMake 构建（备选）
cmake -B build -S CetCryptoToolkit
cmake --build build
```

### 运行时依赖
将以下 DLL 放置在可执行文件同目录：
- `libcrypto-3.dll` / `libssl-3.dll`（OpenSSL 3.x，已在 `libs/`）
- Qt 运行时 DLL（通过 `windeployqt` 部署）

---

## 项目结构

```
CetCryptoToolkit/
├── main.cpp
├── version.h                    # 版本号统一定义
├── mainwindow/                  # 主窗口 + CetToolPluginContext
├── modules/
│   ├── opensslhelper/           # OpenSSL 封装核心
│   └── certificatemanager/      # 证书管理模块
├── interfaces/                  # Qt 插件接口定义
└── libs/                        # 预编译 DLL
```

---

## 插件系统

v2.5.0 引入 `CetToolPluginContext` 统一管理插件加载，支持 DLL 完整性校验（SHA256），防止插件被替换。

| 插件 | 功能 |
|------|------|
| CetLicensePlugin | 许可验证（支持 Ed25519 签名、临时授权） |
| CetUpdatePlugin | 软件更新检查 |
| CetLogManagerPlugin | 日志管理 |
| CetProgressPlugin | 进度显示 |
| CetCANPlugin | CAN 总线通信 |

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| `F2` | 打开当前工作目录 |

---

## 版权

Copyright 2008-2035 The CetXiyuan Ltd. All rights reserved.

网站：https://www.cetxiyuan.com/
