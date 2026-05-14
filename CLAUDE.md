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

## HTML 文档要求

### 1. 样式统一
- **页面主体**：白色（`#ffffff`）或浅灰色背景（`#fafafa`），深色文字（`#1e2a3e` 或 `#3b3f46`），禁止深色或黑色背景。
- **代码块**：使用深色背景（推荐 `#1e1e1e`、`#282c34` 或 `#2d2d2d`），搭配语法高亮（关键字、字符串、注释、函数名等使用对比鲜明的亮色）。
- **表格、引用、列表**：保持浅色系，使用柔和的边框和底色（如 `#f6f8fa` 背景，`#e2e8f0` 边框）。
- 页面最大宽度 `1000px`，居中显示，移动端自适应；代码块支持横向滚动（`overflow-x: auto`）。

### 2. 语法高亮
- 必须支持至少以下语言：C、C++、Python、Bash、JavaScript、Markdown、JSON、YAML。
- 推荐使用 **highlight.js** 或 **Prism.js**，并加载对应语言插件。若使用纯 CSS 方案，需覆盖常见 token 类型。
- **重要**：highlight.js 的深色主题 CSS（如 `atom-one-dark`）会覆盖所有 `code` 元素的背景色，导致行内代码也变成深色背景。必须对行内代码加 `!important` 强制覆盖：
  ```css
  #doc-content code:not(pre code) {
    background: #f0f4f8 !important;
    color: #c7254e !important;
  }
  ```
- **重要**：highlight.js 无法识别的语言（如 `.pro`、`.iss` 等）不会着色，代码块文字会继承深色主题的暗色，在深色背景上看不清。必须为 `pre code` 设置默认浅色文字：
  ```css
  #doc-content pre code {
    color: #abb2bf;  /* 默认浅灰，hljs 着色后会覆盖此值 */
  }
  ```

### 3. 一键复制全文
- 每个 HTML 文档顶部或右上角有一个 **[Copy]** 按钮。
- 点击按钮复制**整个文档的正文纯文本**（不含按钮、页脚、YAML Frontmatter 等界面元素，但保留段落结构、列表符号、代码块内的缩进与换行）。
- 复制成功后显示短暂提示（如"✅ 已复制全文"），提示浮层需位于页面底部中央，2 秒后自动消失。

### 4. 代码块独立复制
- 每个 `<pre><code>` 代码块右上角增加一个小型"📋 复制"按钮。
- 点击仅复制该代码块内的文本内容，不影响其他内容。
- 如果无法为每个代码块生成独立按钮，则至少保证全文复制时代码块格式完整（不会丢失缩进或变成连续文本）。

### 5. 修复与优化
- 自动修复常见 Markdown 格式错误：
  - 标题 `#标题` → `# 标题`
  - 列表 `-条目` → `- 条目`
  - 代码块标记未闭合时补全
- 忽略 YAML Frontmatter（`--- ... ---` 块），不显示在正文中；但将其中的 `title` 字段值用于 HTML `<title>` 标签。
- 相对路径资源（如图片）需转换为有效路径，或将图片复制到输出目录并更新引用。
- 每页底部添加一行：`📄 文档转换 · 笔名 CetXiyuan`。

### 6. 输出格式与编码
- 使用 `UTF-8` 编码，文档类型为 `<!DOCTYPE html>`。
- **单个 `.md` 文件**：直接输出完整的 HTML 代码。
- **多个 `.md` 文件**：输出一个独立的 **Python 脚本**（依赖 `markdown` 和 `pygments` 或 `highlight.js` 的本地库），该脚本读取所有 `.md` 文件，按上述要求生成对应的 `.html` 文件。
- html文档统一保存到 `docs/html/` 目录下。
- 若 Markdown 中包含本地图片，脚本须将图片复制到 `docs/html/assets/` 并更新引用路径（保留相对目录结构）。
