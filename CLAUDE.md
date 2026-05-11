# CLAUDE.md

This file provides guidance to Claude (claude.ai/code) when working with code in this repository.

## 项目概述

CetCryptoToolkit 是一个基于 Qt 5.15.2 (MinGW, 32bit) 的密码学工具箱桌面应用，封装 OpenSSL 3.x 提供证书管理、非对称加密、对称加密、摘要/签名等功能。当前版本 2.3.1，公司 CetXiyuan。

## 构建方式

项目同时支持 qmake 和 CMake，**主力构建文件为 qmake**：

```bash
# qmake 构建（推荐）
cd CetCryptoToolkit
qmake CetCryptoToolkit.pro
mingw32-make -j4

# CMake 构建（备选）
cmake -B build -S CetCryptoToolkit
cmake --build build
```

依赖的外部库（已预置在 `CetCryptoToolkit/libs/`）：
- `libcrypto-3.dll` / `libssl-3.dll` — OpenSSL 3.x
- `CetProductWizard.dll` — 产品向导插件（通过 Qt 插件接口加载）

## 代码架构

```
CetCryptoToolkit/
├── main.cpp                    # 入口，高 DPI 设置、样式初始化
├── version.h                   # 版本号统一定义
├── mainwindow/                 # 主窗口（UI + 业务调度）
│   ├── mainwindow.h/cpp        # 所有功能的入口调度层
│   └── mainwindow.ui           # Qt Designer UI 文件
├── modules/                    # 核心功能模块
│   ├── opensslhelper/          # OpenSSL 封装层（最核心）
│   │   ├── opensslhelper.h/cpp # 直接调用 OpenSSL C API
│   └── certificatemanager/     # 证书管理对话框
│       ├── certificatemanager.h/cpp
│       └── certificatemanager.ui
├── interfaces/                 # Qt 插件接口定义（纯虚接口）
│   ├── cetlogmanagerinterface.h    # 日志管理插件
│   ├── cetlicenseinterface.h       # 授权管理插件
│   ├── cetupdateinterface.h        # 更新插件
│   ├── cetprogressinterface.h      # 进度插件
│   └── cetcaninterface.h           # CAN 总线插件
└── libs/                       # 预编译动态库
```

## 核心设计模式

**插件加载**：`MainWindow::loadPlugin()` 在运行时动态加载 `CetProductWizard.dll`，通过 `CetLogManagerInterface`、`CetLicenseInterface`、`CetUpdateInterface`、`CetProgressInterface` 等纯虚接口使用功能，与具体实现解耦。

**双实现路径**：`CertificateManager` 中证书生成有两套实现：
- `genCertificateCode()`：直接调用 OpenSSL C API（默认路径，`USE_OPENSSL_TOOL_HANDLER=0`）
- `genCertificateOpenssl()`：调用外部 `openssl.exe` 工具（调试/兼容路径）

**OpenSSLHelper 职责**：所有 OpenSSL 操作的唯一封装点，包含密钥对生成、证书签发、CSR 流程、AES/SM4 对称加密、RSA/EC/SM2 非对称加密、摘要与签名验证。

## 证书层级结构

默认支持三级 PKI：
1. **一级根证书**（RootCA）— `pathlen:1`，自签
2. **二级根证书**（SubCA）— `pathlen:0`，由 RootCA 签发
3. **终端证书**（EndEntity）— 由 SubCA 签发，含 SAN 扩展

默认输出目录：`<应用目录>/dir-certs/`

## 版本号约定

版本编码 `(X.Y.Z)(CXYQKabcd.CCTKnnn.XYZ)`：
- `CXYQK5152` = Qt 5.15.2
- `CCTK230` = CetCryptoToolkit v2.3.0
- `G512` = 年月日编码（G=2026年，5=5月，12=12日）

修改版本时只需编辑 `version.h` 中的 `VER_MAJOR/VER_MINOR/VER_MICRO` 和 `RELEASE_DATE`。
