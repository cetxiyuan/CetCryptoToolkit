# CetCryptoToolkit 维护者指南

> 适用版本：CetCryptoToolkit v2.5.0
> 作者：CetXiyuan（璟·汐源忆醉）

---

## 1. 代码风格规范

### 1.1 命名规则

| 元素 | 规范 | 示例 |
|------|------|------|
| 类名 | PascalCase | `OpenSSLHelper`, `CertificateManager`, `MainWindow` |
| 成员变量 | `m_` 前缀 + camelCase | `m_openSSLHelper`, `m_certManager` |
| 局部变量 | camelCase | `keyPair`, `outputDir`, `sslCert` |
| 方法名 | camelCase，动词开头 | `genKeyPair()`, `loadCA()`, `saveToFile()` |
| Qt 槽函数 | `on_<widget>_<signal>` | `on_genCertPushButton_clicked()` |
| 宏常量 | UPPER_SNAKE_CASE | `CAROOT_DEF_DIR`, `USE_OPENSSL_TOOL_HANDLER` |
| 枚举值 | UPPER_SNAKE_CASE | `CERT_EndEntity`, `SYM_GCM` |
| 头文件保护 | `#ifndef FILENAME_H` | `#ifndef OPENSSLHELPER_H` |

### 1.2 缩进与格式

- **缩进**：4 个空格（不使用 Tab）
- **大括号**：K&R 风格（左大括号在行尾）

```cpp
if (certificate.isNull()) {
    qCritical() << "sslCert.isNull():" << m_openSSLHelper->lastErrors();
    return QSslCertificate();
}

// switch 使用大括号包裹需要声明局部变量的 case 块
switch (type) {
case CERT_EndEntity: {
    QString fileName = commonName;
    // ...
    break;
}
default: break;
}
```

### 1.3 注释风格

```cpp
/**
 * 生成密钥对
 * @param algorithm 算法名称："RSA" / "EC" / "SM2"
 * @param keySize RSA用"2048-bit"，EC用"prime256v1"
 * @param passphrase 私钥加密密码，空=不加密
 * @return QPair<公钥, 私钥>，失败时均为 null
 */
QPair<QSslKey, QSslKey> genKeyPair(const QString &algorithm, ...);
```

### 1.4 资源管理

使用 `goto cleanup` 模式确保所有资源正确释放：

```cpp
bool success = false;
EVP_PKEY_CTX *ctx = nullptr;
EVP_PKEY *pkey = nullptr;
// ... 所有变量声明在函数开头

success = true;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return result;
```

### 1.5 对象所有权注意事项

**OpenSSLHelper 的所有权转移**：`MainWindow` 创建 `OpenSSLHelper`，并将其指针传给 `CertificateManager`。`CertificateManager::~CertificateManager()` 会执行 `delete m_openSSLHelper`，即 **CertificateManager 接管了 OpenSSLHelper 的所有权**。MainWindow 在析构时不应再次 delete，Qt 父子关系（CertificateManager 的 parent 是 MainWindow）会确保正确的析构顺序。

**插件接口对象**：v2.5.0 起，插件接口（`CetLicenseInterface`、`CetUpdateInterface` 等）由 `CetToolPluginContext` 统一管理。`CetToolPluginContext` 作为 `MainWindow` 的子对象，其生命周期由 Qt 父子关系自动管理。`CetToolPluginContext::loadPlugin()` 支持 DLL SHA256 完整性校验，防止插件被替换。

### 1.6 错误处理

```cpp
#define SSL_APPEND_ERROR(msg) { \
    char openssl_err[1024]; \
    ERR_error_string_n(ERR_get_error(), openssl_err, sizeof(openssl_err)); \
    appendError(tr("%1 (OpenSSL: %2)").arg(msg).arg(openssl_err)); \
}
```

---

## 2. 版本控制工作流

### 2.1 分支策略

| 分支 | 用途 |
|------|------|
| `master` | 当前开发分支，日常开发提交 |
| `main` | 稳定发布分支，PR 目标分支 |

### 2.2 Commit 消息格式

```
<类型>: <简短描述>

类型：Fixed（修复Bug）/ Updated（功能更新）/ 发布正式版（新版本）
```

示例：

```
Fixed: 上电首次自动激活改成 30 秒
Updated: 许可2.0对应的插件包
发布正式版 V2.5.0
重构 mainwindow 使用 CetToolPluginContext
Updated: 支持临时授权、停用/拒绝状态，拒绝后停止重试
```

---

## 3. 发布流程

### 3.1 修改版本号

编辑 `version.h`：

```cpp
#define VER_MAJOR               2       /* 主版本号 */
#define VER_MINOR               5       /* 次版本号 */
#define VER_MICRO               0       /* 小版本号 */
#define RELEASE_DATE            "(3.0.18)(CXYQK5152.CCTK250.G716)"
// CXYQK5152 = CetXiyuan QT Kernel 5.15.2
// CCTK250 = CetCryptoToolkit v2.5.0
// G716 = G(2026年-20) 7(7月) 16(9日=16-7)

#define PATCH_PACKET            "7152"  // 开发版使用：月+日+序号
```

确保 `IS_RELEASE_VERSION` 为 `1`（正式版）。

### 3.2 编译与打包

```bash
# 编译 Release 版本
qmake CetCryptoToolkit.pro CONFIG+=release
mingw32-make clean
mingw32-make -j4

# 打包
mkdir Output
cp release/CetCryptoToolkit.exe Output/
cp libs/libcrypto-3.dll Output/
cp libs/libssl-3.dll Output/
cd Output
windeployqt CetCryptoToolkit.exe
mkdir plugins
cp ../plugins/*.dll plugins/
```

### 3.3 打标签

```bash
git tag -a v2.5.0 -m "发布正式版 V2.5.0"
git push origin master
git push origin v2.5.0
```

---

## 4. 测试方法

### 4.1 功能测试清单

#### 证书管理

| 测试项 | 操作 | 验证点 |
|------|------|------|
| 一级根证书(CetXiyuan) | 选择→生成证书 | `rootCA-CetXiyuan.crt.pem` 生成 |
| 一级根证书(Custom) | 选择→修改DN→生成 | `rootCA-Custom.crt.pem` 生成 |
| 二级根证书 | 选择→生成 | `subCA-Generic.crt.pem` 生成 |
| 终端证书 | 选择→设置CN→生成 | 终端证书+链+PFX 全部生成 |
| 证书配置对话框 | 点击配置按钮 | CertificateManager 弹出 |

#### 非对称加密

| 测试项 | 验证点 |
|------|------|
| RSA 加密→解密 | 解密结果 = 原始数据 |
| EC 加密→解密 | 解密结果 = 原始数据 |
| 文件模式 | 文件读写正常 |

#### 摘要与签名

| 测试项 | 验证点 |
|------|------|
| SHA256 摘要 | 对比 `openssl dgst` 命令 |
| SM3 摘要 | 摘要值正确（SM3 不涉及 userId） |
| RSA 签名→验签 | 验签成功 |
| SM2 签名→验签 | 验签成功（需填入 userId，摘要算法选 SM3 时 userId 输入框自动显示） |

#### 对称加密

| 测试项 | 验证点 |
|------|------|
| AES-CBC 加解密 | 解密正确 |
| AES-GCM 加解密 | GCM 认证加密正常 |
| SM4-CBC 加解密 | SM4 仅支持 ECB/CBC，解密正常 |
| AES-128-CMAC | CMAC 值正确 |
| ECB 模式 | IV 输入框隐藏 |

### 4.2 OpenSSL 命令行交叉验证

```bash
# 临时切换到命令行路径
#define USE_OPENSSL_TOOL_HANDLER     (1)  // 在 certificatemanager.h 中

# 对比两种路径的生成结果
```

### 4.3 自动化测试

当前项目**不包含自动化单元测试**。建议后续添加：
- **Qt Test**（`QTestLib`）：信号/槽、GUI 组件
- **Google Test**：OpenSSLHelper 纯计算逻辑

建议优先测试的核心方法：

```cpp
void testGenKeyPair() {
    OpenSSLHelper helper;
    auto keyPair = helper.genKeyPair("RSA", "2048-bit", "");
    QVERIFY(!keyPair.first.isNull());
    QVERIFY(!keyPair.second.isNull());
}

void testDigest() {
    OpenSSLHelper helper;
    QByteArray hash = helper.digest(QByteArray::fromHex("616263"), "SHA256"); // "abc"
    QCOMPARE(hash.toHex(),
        QByteArray("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}
```

---

## 5. 调试技巧

### 5.1 qDebug() 日志

项目已开启 `QT_MESSAGELOGCONTEXT`，日志自动包含文件名和行号：

```cpp
qDebug() << "key" << key.toHex() << "data" << data.toHex();
qWarning() << "[license:activate] next time(ms):" << auto_timing_msec;
qCritical() << "sslCert.isNull():" << m_openSSLHelper->lastErrors();
qInfo() << "SM2 is in default provider";
```

### 5.2 OpenSSL 错误输出

`SSL_APPEND_ERROR` 宏自动捕获 OpenSSL 错误栈。通过 `m_openSSLHelper->lastErrors()` 获取。

### 5.3 推荐工具

| 工具 | 用途 |
|------|------|
| **Dependency Walker** | 检查 DLL 依赖 |
| **Process Monitor** | 监控文件/注册表访问 |
| **OpenSSL 命令行** | 交叉验证密码学结果 |
| **Qt Creator** | IDE 和调试器 |

---

## 6. 证书管理操作指南

### 6.1 PKI 证书体系

PKI（公钥基础设施）支持**三级证书体系**：

```
一级根证书（RootCA）    → pathlen:1，自签
  └── 二级根证书（SubCA） → pathlen:0，RootCA 签发
        └── 终端证书（EndEntity） → SubCA 签发，含 SAN
```

### 6.2 快速生成完整证书

**第一步：生成一级根证书**

1. 「证书类型」选择 **一级根证书(CetXiyuan)** 或 **一级根证书(Custom)**
2. 点击「配置」→ 设置密钥类型（RSA-2048 推荐或 SM2）、有效期（建议 3650 天）
3. 点击「生成证书」

**第二步：生成二级根证书**

1. 「证书类型」选择 **二级根证书**
2. 确认「签发者」显示为一级根证书
3. 有效期建议 1825 天（5年）
4. 点击「生成证书」

**第三步：生成终端证书**

1. 「证书类型」选择 **终端证书**
2. 「配置」中重点设置：CommonName（域名）、SAN（DNS/IP）、有效期（建议 365 天）
3. 确认「签发者」显示为二级根证书
4. 点击「生成证书」

### 6.3 输出文件说明

| 文件名 | 格式 | 用途 |
|--------|------|------|
| `<name>.key.pem` | PEM | 私钥，**妥善保管，不可泄露** |
| `<name>.pub.pem` | PEM | 公钥 |
| `<name>.csr.pem` | PEM | 证书签名请求 |
| `<name>.crt.pem` | PEM | 证书（可用记事本打开） |
| `<name>.crt.der` | DER | 证书（二进制） |
| `ca-chain-<name>.pem` | PEM | 证书链 |
| `ca-chain-<name>.p7b` | PKCS#7 | 证书链（Windows 可双击导入） |
| `full-bundle-<name>.pfx` | PKCS#12 | 证书+私钥+证书链（密码 `pfxpassword`） |

### 6.4 PFX 和 P7B 的使用场景

**PFX（PKCS#12）**：包含证书+私钥+完整证书链。用于导入 Windows 证书存储、IIS、Nginx（需先转换）、Java KeyStore。Windows 下双击 `.pfx` 按向导操作。

**P7B（PKCS#7）**：仅含证书链（不含私钥）。用于部署证书链让客户端验证信任链。Windows 下双击 `.p7b` 可导入证书存储。

### 6.5 配置对话框参数

| 参数 | 说明 | 示例 |
|------|------|------|
| 密钥类型 | 非对称算法 | RSA-2048、EC prime256v1、SM2 |
| 有效期（天） | 证书有效天数 | 365、1825、3650 |
| CommonName (CN) | 证书主体名称 | `example.com`、`My Root CA` |
| 证书扩展字段 | X.509 v3 扩展 | 见下方 |

**SAN 配置示例**：

```
# 单域名
subjectAltName=DNS:example.com

# 多域名 + IP
subjectAltName=DNS:example.com,DNS:www.example.com,IP:192.168.1.100

# 通配符域名
subjectAltName=DNS:*.example.com
```

### 6.6 证书验证

```bash
# 验证证书链
openssl verify -CAfile ca-chain-<name>.pem <name>.crt.pem

# 查看证书详情
openssl x509 -in <name>.crt.pem -text -noout
```

---

## 7. 常见修改场景

### 7.1 增加新的密钥算法

在 `opensslhelper.cpp` 的 `supportedKeyAlgorithms` 添加条目：

```cpp
static QList<QPair<QString, int>> supportedKeyAlgorithms = {
    {"RSA",     EVP_PKEY_RSA},
    {"EC",      EVP_PKEY_EC},
    {"SM2",     EVP_PKEY_SM2},
    {"Ed25519", EVP_PKEY_ED25519},  // 新增
};
```

然后在 `genKeyPair()` 添加对应分支。

### 7.2 增加新的对称加密模式

1. `SymMode` 枚举添加新值（如 `SYM_CFB`）
2. `supportedSymModes` 列表添加条目
3. `aesCipher()` 添加对应 `EVP_aes_*_cfb()` 分支
4. `on_seaEncryptModeComboBox_currentTextChanged()` 添加 IV 处理

### 7.3 修改证书默认有效期

编辑 `mainwindow.cpp`：

```cpp
void MainWindow::on_certTypeComboBox_currentTextChanged(const QString &arg1)
{
    // ...
    } else if (arg1.contains(TEXT_RootCACustom)) {
        m_certManager->setValidDays(365 * 10);  // 改为 10 年
    }
}
```

### 7.4 修改许可证激活间隔上限

```cpp
QTimer::singleShot(auto_timing_msec, this, [=]() {
    auto_timing_active = true;
    auto_timing_msec = auto_timing_msec * 2;
    // 添加上限
    if (auto_timing_msec > 2 * 60 * 60 * 1000)
        auto_timing_msec = 2 * 60 * 60 * 1000;
    // ...
});
```

### 7.5 在 API 和命令行路径间切换

编辑 `certificatemanager.h`：

```cpp
#define USE_OPENSSL_TOOL_HANDLER     (0)  // 0=API路径, 1=命令行路径
```

### 7.6 添加 CRL 分发点字段

在 `certificatemanager.ui` 添加 `crlLineEdit`，然后在终端证书分支：

```cpp
QString crlUrl = ui->crlLineEdit->text();
if (!crlUrl.isEmpty())
    extensions.append(QString("crlDistributionPoints=URI:%1").arg(crlUrl));
```

### 7.7 修改 AES IV 生成逻辑

编辑 `aesGenerateIV()`：将 GCM 模式的 IV 从 12 字节改为 16 字节，同步修改 `on_seaEncryptModeComboBox_currentTextChanged()` 中的默认 IV 值。

### 7.8 插件集成（CetToolPluginContext）

v2.5.0 起，新项目的插件集成使用 `CetToolPluginContext`：

```cpp
// mainwindow.cpp 构造函数初始化列表中
m_toolPluginCtx(new CetToolPluginContext(HASH_CetProductWizard_DLL, this))

// 构造函数体中调用
m_toolPluginCtx->initFeatures(ui->logManagerMenu, ui->licenseMenu,
    PRODUCT_NAME, CETCRYPTOTOOLKIT_VERSION, APP_NAME, APP_VERSION);
// 可选：传入 std::function<void(bool)> 回调处理激活结果
```

`CetToolPluginContext` 内置 DLL 完整性校验（SHA256），构造函数传入编译时计算的 DLL 哈希值，运行时对比防止插件被替换。

---

## 8. 目录说明

| 目录 | 说明 |
|------|------|
| `dir-certs/` | 证书输出目录（运行时自动创建） |
| `dir-asymmetrics/` | 非对称加密数据目录 |
| `dir-symmetrics/` | 对称加密数据目录 |
| `Configs/` | 配置文件目录（AppMaster.ini） |
| `Record/` | 日志记录目录 |
| `plugins/` | Qt 插件 DLL 备用搜索路径 |
