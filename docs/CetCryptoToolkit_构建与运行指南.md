# CetCryptoToolkit 构建与运行指南

> 适用版本：CetCryptoToolkit v2.4.0
> 平台：Windows 7 / 10 / 11

---

## 1. 环境要求

| 组件 | 版本 | 说明 |
|------|------|------|
| **Qt** | 5.15.2 | 必须使用此版本 |
| **编译器** | **MinGW 8.1.0 32-bit** | 必须是 32-bit，不可用 64-bit 或 MSVC |
| **OpenSSL** | 3.x（3.0.18） | 已预置在 `libs/` 目录，无需单独安装 |
| **CMake** | 3.16+（可选） | 使用 CMake 构建时需要 |
| **Git** | 任意版本 | 代码管理 |
| **操作系统** | Windows 10/11 | 目标平台 |

> ⚠️ **关键约束**：项目链接的 OpenSSL DLL 为 32-bit 版本，编译器必须选择 MinGW **32-bit**，否则链接时会报架构不匹配错误。

---

## 2. Qt 安装

### 2.1 下载 Qt 在线安装器

从 Qt 官网下载 `qt-unified-windows-x86-online.exe`，或使用离线安装包 `qt-opensource-windows-x86-5.15.2.exe`。

### 2.2 安装时选择组件

在组件选择界面，展开 **Qt 5.15.2**，勾选：

```
Qt 5.15.2
  ✅ MinGW 8.1.0 32-bit        ← 必选
  ✅ Qt Network                 ← 必选（提供 QSslKey / QSslCertificate）
  ✅ Qt Widgets                 ← 必选

开发工具
  ✅ MinGW 8.1.0 32-bit        ← 编译器本体
  ✅ Qt Creator                 ← 推荐 IDE
```

### 2.3 验证安装

```bash
# 在 Qt Creator 的 Terminal 或 MinGW 命令行中执行
qmake --version
# 期望输出：QMake version 3.1 / Using Qt version 5.15.2 in ...mingw81_32...
```

### 2.4 配置环境变量

```batch
set PATH=D:\Qt\Qt5.15.2\5.15.2\mingw81_32\bin;D:\Qt\Qt5.15.2\Tools\mingw810_32\bin;%PATH%
```

---

## 3. 获取源代码

```bash
git clone <仓库地址>
cd CetCryptoToolkit
git checkout master
```

### 目录结构确认

```
CetCryptoToolkit/
├── main.cpp
├── version.h
├── CetCryptoToolkit.pro          # qmake 工程文件（主力）
├── CMakeLists.txt                # CMake 工程文件（备选）
├── app.rc                        # Windows 资源文件
├── mainwindow/                   # 主窗口模块
├── modules/
│   ├── opensslhelper/            # 密码学核心
│   └── certificatemanager/       # 证书管理
├── interfaces/                   # 插件接口定义
├── libs/                         # 预编译 DLL
│   ├── libcrypto-3.dll
│   ├── libssl-3.dll
│   ├── CetProductWizard.dll
│   └── libCetProductWizard.dll.a # MinGW 导入库
├── include/openssl/              # OpenSSL C 头文件
└── plugins/                      # 运行时插件目录
```

---

## 4. 构建步骤

### 4.1 qmake 构建（推荐）

```bash
# 进入源码子目录
cd CetCryptoToolkit

# Release 构建
qmake CetCryptoToolkit.pro -spec win32-g++ CONFIG+=release
mingw32-make -j4

# Debug 构建
qmake CetCryptoToolkit.pro -spec win32-g++ CONFIG+=debug
mingw32-make -j4

# 清理
mingw32-make clean
```

### 4.2 Qt Creator 构建（推荐新手）

1. 打开 Qt Creator → **文件** → **打开文件或项目**
2. 选择 `CetCryptoToolkit/CetCryptoToolkit.pro`
3. 在 Kit 选择界面，选择 **Desktop Qt 5.15.2 MinGW 32-bit**
4. 选择构建配置（Debug / Release）
5. 点击左下角 **构建** 按钮（或 `Ctrl+B`）
6. 点击 **运行**（`Ctrl+R`）

### 4.3 CMake 构建（备选）

```batch
cd CetCryptoToolkit
cmake -B build -S . -G "MinGW Makefiles" ^
    -DCMAKE_PREFIX_PATH=D:/Qt/Qt5.15.2/5.15.2/mingw81_32
cmake --build build --parallel 4
```

> **注意**：CMake 构建文件当前为 Qt Creator 自动生成的模板，未完全配置第三方库路径和插件加载逻辑，建议使用 qmake 构建。

---

## 5. 运行时 DLL 部署

### 5.1 从 Qt Creator 运行

在 Qt Creator 中点击 **Run**（`Ctrl+R`），程序自动从构建目录运行。

### 5.2 部署到独立目录

```bash
# 创建发布目录
mkdir release-deploy
cp release/CetCryptoToolkit.exe release-deploy/
cp libs/libcrypto-3.dll release-deploy/
cp libs/libssl-3.dll release-deploy/

# 使用 windeployqt 自动部署 Qt 运行时
cd release-deploy
windeployqt CetCryptoToolkit.exe

# 手动复制插件 DLL（可选）
mkdir plugins
cp ../plugins/*.dll plugins/
```

完整运行时目录结构：

```
CetCryptoToolkit.exe
libcrypto-3.dll
libssl-3.dll
Qt5Core.dll
Qt5Gui.dll
Qt5Widgets.dll
Qt5Network.dll
platforms\qwindows.dll
styles\qwindowsvistastyle.dll
plugins\                    ← 可选：商业功能插件
Configs\AppMaster.ini       ← 首次运行后自动生成
```

---

## 6. 插件部署（可选）

商业功能插件（授权/更新/日志）放置在以下任一路径：

```
# 优先路径（生产环境）
D:\Program Files (x86)\CetXiyuan\CetToolDLLs\plugins\

# 备用路径（开发/便携模式）
<exe同目录>\plugins\
```

| 插件 DLL | 对应接口 | 功能 |
|---------|---------|------|
| `CetLogManagerPlugin.dll` | CetLogManagerInterface | 日志管理 |
| `CetLicensePlugin.dll` | CetLicenseInterface | 授权验证 |
| `CetUpdatePlugin.dll` | CetUpdateInterface | 软件更新检查 |
| `CetProgressPlugin.dll` | CetProgressInterface | 进度显示 |

> 插件缺失时程序会弹出警告，但核心密码学功能不受影响。

---

## 7. 常见问题

### 编译错误

| 问题 | 原因 | 解决方案 |
|------|------|------|
| `openssl/evp.h: No such file or directory` | OpenSSL 头文件未找到 | 确认 `include/openssl/` 目录存在，检查 `.pro` 中 `INCLUDEPATH` |
| `undefined reference to __imp_EVP_...` | OpenSSL 库架构不匹配 | 确认使用 MinGW **32-bit**，检查 Kit 编译器路径是否包含 `mingw81_32` |
| `cannot find -lcrypto-3` | OpenSSL 导入库缺失 | 确认 `libs/` 下存在 `libcrypto-3.dll` |
| `undefined reference to XXX` | 链接顺序问题 | 确认 `.pro` 中 `LIBS` 配置 |
| `moc_*.cpp` 编译错误 | MOC 生成问题 | `mingw32-make clean` 后重新构建 |

### 运行时错误

| 问题 | 原因 | 解决方案 |
|------|------|------|
| "无法定位程序输入点" | DLL 版本不匹配 | 使用 Qt 5.15.2 MinGW 32-bit 的 DLL |
| "应用程序无法正常启动(0xc000007b)" | 32/64 位 DLL 混用 | 全部使用 32-bit DLL |
| "无法找到 libcrypto-3.dll" | 不在 PATH 中 | 复制 `libs/libcrypto-3.dll` 和 `libs/libssl-3.dll` 到 exe 同目录 |
| "缺少 Qt5Core.dll" | Qt DLL 不在 PATH | 运行 `windeployqt` 或添加 Qt bin 目录到 PATH |
| SM2/SM4/SM3 不可用 | OpenSSL 版本不对 | 确认使用 OpenSSL 3.x（非 1.x） |
| 界面中文显示乱码 | 编码问题 | 已设置 UTF-8 编码，若仍乱码检查源文件编码 |

### Qt Creator 问题

| 问题 | 原因 | 解决方案 |
|------|------|------|
| "Cannot find kit" | Kit 未正确配置 | **工具 → 选项 → Kits**，确认存在 Qt 5.15.2 MinGW 32-bit Kit |
| `qmake` 命令找不到 | PATH 未配置 | 将 `C:\Qt\5.15.2\mingw81_32\bin` 和 `C:\Qt\Tools\mingw810_32\bin` 加入 PATH |

### 许可证激活问题

| 问题 | 原因 | 解决方案 |
|------|------|------|
| 标题显示"已到期" | 许可未激活 | 手动点击"许可→激活"菜单，或等待 30 秒后自动激活 |
| 中央控件灰色不可用 | 许可未激活 | 同上 |
| 插件加载失败弹出警告 | 插件 DLL 缺失 | 正常现象，不影响核心密码学功能 |

---

## 8. 开发调试建议

- 使用 `qDebug()` 输出调试信息，项目定义了 `QT_MESSAGELOGCONTEXT`，日志自动包含文件名和行号
- 按 **F2** 可快速打开程序工作目录，方便查看生成的证书文件
- 证书输出目录：`<工作目录>/dir-certs/`
- 配置文件：`<工作目录>/Configs/AppMaster.ini`
- 启动时日志会输出 SM2/SM3/SM4/CMAC 是否可用
- 证书生成调试：设置 `USE_OPENSSL_TOOL_HANDLER=1` 切换到命令行模式对比结果
