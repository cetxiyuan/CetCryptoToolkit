# CetCryptoToolkit 架构设计

> 作者：CetXiyuan（璟·汐源忆醉）
> 版本：v2.6.0
> 平台：Windows，Qt 5.15.2 (MinGW, 32-bit)，OpenSSL 3.x

---

## 1. 项目定位

CetCryptoToolkit 是一款面向开发者和安全工程师的**密码学工具箱**桌面应用程序，集成了证书管理（PKI）、非对称加密/签名、对称加密、国密算法（SM2/SM3/SM4）等常用密码学操作，提供图形界面和底层 OpenSSL C API 双重访问路径。

---

## 2. 整体架构

### 架构图

```
┌──────────────────────────────────────────────────────────────┐
│                        main.cpp                              │
│   高 DPI 适配 / 样式初始化 / QApplication 入口               │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│                    MainWindow（主窗口）                        │
│  • UI 调度层，持有并协调所有功能模块                           │
│  • 持有 OpenSSLHelper、CertificateManager 实例                │
│  • 配置持久化：Configs/AppMaster.ini（QSettings）             │
└─────┬────────────┬───────────────────────┬────────────────────┘
      │            │                       │
      ▼            ▼                       ▼
┌──────────┐ ┌──────────────────┐ ┌─────────────────────────┐
│OpenSSL   │ │CertificateManager│ │  CetToolPluginContext   │
│Helper    │ │（证书管理对话框） │ │  （插件统一管理 v2.5.0）│
│（核心）  │ │  调用 OpenSSL-   │ │  • 完整性校验(SHA256)   │
│          │ │  Helper 完成签发 │ │  • 插件加载与生命周期   │
└──────────┘ └──────────────────┘ └──────────┬──────────────┘
                                            │
                    ┌────────────────────────┼────────────────────┐
                    ▼                        ▼                    ▼
            ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐
            │ 插件接口层    │   │ 插件接口层    │   │ 插件接口层        │
            │ interfaces/  │   │ interfaces/  │   │ interfaces/      │
            │ License      │   │ Update       │   │ LogManager       │
            │ Progress     │   │              │   │                  │
            └──────────────┘   └──────────────┘   └──────────────────┘
```

### 关键数据流

```
用户操作（UI）
    → MainWindow slot
        → OpenSSLHelper 方法（直接调用 OpenSSL C API）
            → 返回 QByteArray / QSslCertificate / QSslKey
        → 结果写入文件或显示在文本框
```

### 分层说明

| 层次 | 说明 |
|------|------|
| **表示层** | MainWindow + CertificateManager（Qt UI），负责用户交互 |
| **业务调度层** | MainWindow 的 slot 函数，负责数据获取、调用 OpenSSLHelper、结果展示 |
| **密码学核心层** | OpenSSLHelper，封装 OpenSSL 3.x C API，提供统一接口 |
| **基础设施层** | OpenSSL 3.x 动态库、Qt 5.15.2 框架 |
| **插件管理层** | CetToolPluginContext（v2.5.0），统一管理插件加载、SHA256 完整性校验 |
| **插件扩展层** | 通过 Qt 插件机制加载 CetProductWizard.dll，提供日志/许可/更新/进度功能（CAN 插件存在于插件目录，主程序未加载） |

---

## 3. 功能模块详解

### 3.1 OpenSSLHelper（`modules/opensslhelper/`）

所有 OpenSSL 操作的**唯一封装点**，直接调用 OpenSSL 3.x C API。

| 功能类别 | 主要方法 | 说明 |
|---------|---------|------|
| 初始化 | `initOpenSSL()` / `cleanupOpenSSL()` | 单例初始化，加载所有摘要/加密算法 |
| 密钥对生成 | `genKeyPair(algorithm, keySize, passphrase)` | 支持 RSA/EC/SM2，返回 `QPair<公钥, 私钥>` |
| 自签证书 | `genSelfCert(validDays, subjectDN, ...)` | 生成自签名 X.509 证书 |
| CSR | `genCSR()` / `signCSR()` | 生成证书请求 / CA 签发 |
| 证书链 | `genChain()` / `toP7b()` / `toPfx()` | 生成链文件、P7B、PFX（PKCS#12） |
| 格式转换 | `toDer()` | PEM → DER |
| 非对称加解密 | `asymmetricEncrypt()` / `asymmetricDecrypt()` | RSA/EC 公钥加密 / 私钥解密 |
| 摘要 | `digest(data, hashAlgo)` | 支持 MD5/SHA1/SHA256/SHA512/SM3 等 11 种 |
| 签名/验签 | `signData()` / `signVerify()` | RSA/EC/SM2，SM2 需提供 userId |
| AES | `aesEncrypt()` / `aesDecrypt()` | ECB/CBC/GCM/CTR 模式，自动处理 IV+密文+Tag 格式 |
| AES-CMAC | `aes128GenerateCMAC()` | 128 位消息认证码 |
| SM4 | `sm4Encrypt()` / `sm4Decrypt()` | 国密对称加密，仅支持 ECB/CBC |
| SM2 辅助 | `sm2PubKeyToDer()` / `sm2SignToDer()` | 裸公钥/签名转 DER |
| 错误处理 | `lastErrors()` / `appendError()` | 内部错误队列，含 OpenSSL 错误字符串 |

**支持的算法参数：**
- RSA 密钥长度：512 / 1024 / 2048 / 3072 / 4096 / 8192-bit
- EC 曲线：prime256v1 / secp256k1 / secp384r1 / secp521r1
- 国密：SM2（公钥）/ SM3（摘要）/ SM4（对称）

**openssl.exe 备用路径**：以 `openssl` 前缀命名的方法族（`opensslGenKeyPair` 等）通过 PowerShell 调用系统的 `openssl.exe`（`opensslGenChain` 直接使用 PowerShell `Get-Content`），由宏 `USE_OPENSSL_TOOL_HANDLER=0/1` 控制是否启用。注意：
- `opensslGenKeyPair` **仅支持 RSA 和 EC**，不支持 SM2
- `opensslGenSelfCert` 硬编码了 CA 扩展字段（`pathlen:1`），不支持自定义扩展
- `opensslGenSelfCert` 的 `hashAlgo` 参数：实现内部会自动加前导短横线（`"-%1"`），因此实际应传 `sha256`（不带横线），否则拼出 `--sha256` 无效；形参默认值写作 `"-sha256"` 系历史遗留

---

### 3.2 CertificateManager（`modules/certificatemanager/`）

证书配置对话框（`QDialog`），提供证书生成的 UI 界面和流程编排。

**证书类型枚举：**

| 枚举值 | 含义 | pathlen | 签发者 |
|-------|------|---------|-------|
| `CERT_RootCACetXiyuan` | 一级根证书（CetXiyuan 预置） | 1 | 自签 |
| `CERT_RootCACustom` | 一级根证书（自定义） | 1 | 自签 |
| `CERT_SubordinateCA` | 二级根证书 | 0 | RootCA 签发 |
| `CERT_EndEntity` | 终端证书 | — | SubCA 签发 |

**默认扩展字段**（`CAROOT_DEF_CERTEXTS` / `CASUB_DEF_CERTEXTS` / `ENDENTITY_DEF_CERTEXTS` 宏，certificatemanager.h）：
- RootCA：`basicConstraints=critical,CA:TRUE,pathlen:1` + `keyUsage=critical,keyCertSign,cRLSign` + `subjectKeyIdentifier=hash` + `authorityKeyIdentifier=keyid:always,issuer:always`
- SubCA：`basicConstraints=critical,CA:TRUE,pathlen:0` + `keyUsage=critical,keyCertSign,cRLSign` + `subjectKeyIdentifier=hash` + `authorityKeyIdentifier=keyid:always,issuer:always`
- EndEntity：`basicConstraints=critical,CA:FALSE` + `keyUsage=digitalSignature,keyEncipherment` + `subjectKeyIdentifier=hash` + `authorityKeyIdentifier=keyid:always,issuer:always` + `extendedKeyUsage=serverAuth,clientAuth` + `subjectAltName=DNS:example.com,IP:127.0.0.1`

**输出文件（以 EndEntity 为例）：**

| 文件名 | 格式 | 用途 |
|--------|------|------|
| `<name>.key.pem` | PEM | 私钥，妥善保管 |
| `<name>.pub.pem` | PEM | 公钥 |
| `<name>.csr.pem` | PEM | 证书请求（CSR） |
| `<name>.crt.pem` | PEM | 证书 |
| `<name>.crt.der` | DER | 证书（二进制） |
| `ca-chain-<name>.pem` | PEM | 证书链（SubCA+RootCA） |
| `ca-chain-<name>.p7b` | PKCS#7 | 证书链（Windows 可双击导入） |
| `full-bundle-<name>.pfx` | PKCS#12 | 证书+私钥+证书链（UI 默认密码 `123456`，可在界面修改） |

---

### 3.3 MainWindow（`mainwindow/`）

主窗口是所有功能的 **UI 调度层**，使用 QGroupBox 分为三个主要功能区：

#### 证书管理页
- 证书类型选择（EndEntity / SubCA / RootCA）
- 签发者显示
- 证书参数配置（点击按钮弹出 CertificateManager 对话框）
- 生成证书，输出到选定目录

#### 非对称加密页（AEA）
- 私钥/公钥导入（文本输入或文件读取）
- 支持 RSA/EC/SM2 加解密
- 摘要计算（11 种算法）
- 签名与验签（含 SM2 的 userId 参数）

#### 对称加密页（SEA）
- 算法选择：AES / SM4
- 模式选择：ECB / CBC / GCM / CTR（SM4 仅支持 ECB/CBC）
- 密钥输入（Hex 格式，AES 支持 128/192/256-bit，SM4 固定 128-bit）
- IV 输入（Hex 格式，ECB 模式自动隐藏）
- 加密/解密操作
- AES-128-CMAC 计算

---

### 3.4 CetToolPluginContext（`mainwindow/cettoolplugincontext.h`）

**v2.5.0 新增**，统一管理所有功能插件的加载、SHA256 完整性校验和生命周期。

- **构造时**：传入 `CetProductWizard.dll` 的编译时 SHA256 哈希，运行时校验防止 DLL 被替换
- **`initFeatures()`**：一次性初始化所有功能插件，自动连接菜单和信号
- **访问器**：`logManager()` / `license()` / `updater()` / `progress()` 返回对应接口指针
- **`loadPlugin()`**：带完整性校验的 DLL 加载，校验失败返回 nullptr；加载失败时返回 `QPluginLoader` 详细错误（v2.6.0 改进，避免误报为缺少插件本身）
- **试用提醒**（v2.5.1 新增）：内部持有 `TrialReminder`（由 CetProductWizard.dll 提供），支持试用期到期提醒。注意：`CetToolPluginContext` 的实现编译于外部库 `CetToolDLLs/CetToolLibs/CetProductWizard/`（mainwindow/ 下仅保留头文件，通过 `-lCetProductWizard` 链接）

### 3.5 插件接口层（`interfaces/`）

动态加载路径：

```
优先路径：D:/Program Files (x86)/CetXiyuan/CetToolDLLs/plugins/
备用路径：./plugins/
```

| 接口 | DLL | 功能 |
|------|-----|------|
| `CetLogManagerInterface` | `CetLogManagerPlugin.dll` | 日志管理窗口 |
| `CetLicenseInterface` | `CetLicensePlugin.dll` | 授权验证（签名算法由插件内部实现，源码不在本仓库） |
| `CetUpdateInterface` | `CetUpdatePlugin.dll` | 软件更新检查 |
| `CetProgressInterface` | `CetProgressPlugin.dll` | 进度显示 |
| — | `CetCANPlugin.dll` | CAN 总线通信 |

> 插件缺失时仅弹出警告，不影响核心密码学功能使用。

---

## 4. 核心类/组件

### 4.1 MainWindow（主窗口）

**文件**：`mainwindow/mainwindow.h`、`mainwindow/mainwindow.cpp`

**继承关系**：`QMainWindow`

**职责**：应用程序主窗口，所有功能操作的调度中心。

| 类型 | 成员 | 说明 |
|------|------|------|
| **私有方法** | `getData(isFile, fileName, inBase64)` | 从文件或文本获取原始数据 |
| **protected 方法** | `keyPressEvent(QKeyEvent *event)` | 快捷键处理（F2 打开当前目录） |
| **槽函数** | `on_outputDirToolButton_clicked()` | 选择证书输出目录 |
| **槽函数** | `on_certTypeComboBox_currentTextChanged()` | 证书类型切换时更新 CN/有效期/扩展 |
| **槽函数** | `on_genCertPushButton_clicked()` | 触发证书生成流程 |
| **槽函数** | `on_aeaPrivateToolButton_clicked()` / `on_aeaPublicToolButton_clicked()` | 选择私钥/公钥文件 |
| **槽函数** | `on_aeaDataToolButton_clicked()` | 选择数据文件 |
| **槽函数** | `on_aeaEncryptPushButton_clicked()` | 非对称加密 |
| **槽函数** | `on_aeaDecryptPushButton_clicked()` | 非对称解密 |
| **槽函数** | `on_aeaDigestPushButton_clicked()` | 计算数据摘要 |
| **槽函数** | `on_aeaDigestComboBox_currentTextChanged()` | 摘要算法切换 |
| **槽函数** | `on_aeaSignPushButton_clicked()` | 数据签名 |
| **槽函数** | `on_aeaVerifySignPushButton_clicked()` | 签名验证 |
| **槽函数** | `on_seaDataToolButton_clicked()` 等 | 对称区数据/加解密文件选择 |
| **槽函数** | `on_seaEncryptPushButton_clicked()` | 对称加密（AES/SM4） |
| **槽函数** | `on_seaDecryptPushButton_clicked()` | 对称解密（AES/SM4） |
| **槽函数** | `on_seaEncryptModeComboBox_currentTextChanged()` | 加解密模式切换（ECB/CBC/...） |
| **槽函数** | `on_seaKeyLineEdit_textChanged()` / `on_seaAlgoComboBox_currentTextChanged()` | 密钥输入与算法切换 |
| **槽函数** | `on_aes128cmacPushButton_clicked()` | AES-128-CMAC 计算 |

**构造/析构**：

| 类型 | 成员 | 说明 |
|------|------|------|
| **构造** | `MainWindow(QWidget *parent)` | 初始化 UI 控件、加载插件、连接信号/槽、读取配置 |
| **析构** | `~MainWindow()` | 释放插件接口、配置对象、UI 资源 |

**重要属性**：

| 属性 | 类型 | 说明 |
|------|------|------|
| `m_privateKey` | `QSslKey` | 当前非对称加密的私钥 |
| `m_publicKey` | `QSslKey` | 当前非对称加密的公钥 |
| `m_openSSLHelper` | `OpenSSLHelper *const` | 密码学核心层对象 |
| `m_certManager` | `CertificateManager *const` | 证书管理对话框 |
| `m_toolPluginCtx` | `CetToolPluginContext *const` | 插件统一管理（v2.5.0） |
| `m_settings` | `QSettings *const` | 配置存储（Configs/AppMaster.ini，UTF-8） |

### 4.2 OpenSSLHelper（密码学核心封装）

**文件**：`modules/opensslhelper/opensslhelper.h/cpp`

**继承关系**：`QObject`

**职责**：封装 OpenSSL 3.x C API，是项目最核心的类。

**公开枚举**：

```cpp
enum SymMode {
    SYM_ECB,    // 电子密码本
    SYM_CBC,    // 密码分组链接
    SYM_GCM,    // 伽罗瓦计数器（认证加密）
    SYM_CTR     // 计数器模式
};
```

**密钥生成**：

```cpp
QPair<QSslKey, QSslKey> genKeyPair(
    const QString &algorithm,      // "RSA" / "EC" / "SM2"
    const QString &keySize = "2048-bit",
    const QString &passphrase = ""
);
```

**证书生成与签发**：

```cpp
QSslCertificate genSelfCert(validDays, subjectDN, privateKey, extensions, hashAlgo="sha256", passphrase="");
QString genCSR(subjectDN, privateKey, extensions={}, passphrase="");
QSslCertificate signCSR(validDays, csrPem, caCert, caPrivateKey, extensions={}, hashAlgo="sha256", passphrase="");
```

**证书格式转换**：

```cpp
QByteArray genChain(subCACert, rootCACert);
QByteArray toP7b(chainPem);
QByteArray toPfx(cert, privateKey, chainPem, passphrase="");
QByteArray toDer(pemData);
```

**摘要与签名**：

```cpp
QByteArray digest(data, hashAlgo);
QByteArray signDigest(digest, privateKey, hashAlgo="sha256", passphrase="", userId=QByteArray());
QByteArray signData(data, privateKey, hashAlgo="sha256", passphrase="", userId=QByteArray());
bool signVerify(data, signature, publicKey, hashAlgo="sha256", userId=QByteArray());
```

**对称与非对称加解密**：

```cpp
static QByteArray asymmetricEncrypt(data, publicKey);
static QByteArray asymmetricDecrypt(data, privateKey);
static QByteArray aesEncrypt(plaintext, key, mode=SYM_ECB, iv={});
static QByteArray aesDecrypt(ciphertext, key, mode=SYM_ECB);
static QByteArray aes128GenerateCMAC(data, key);
static QByteArray aesGenerateKey(keySize=32);
static QByteArray aesGenerateIV(mode);
QByteArray sm4Encrypt(plaintext, key, mode, iv);
QByteArray sm4Decrypt(ciphertext, key, mode, iv);
QByteArray sm2PubKeyToDer(rawPubKey);
QByteArray sm2SignToDer(rawSignKey);
```

**支持列表查询**：

```cpp
static QStringList supportKeyAlgorithmNames();   // {"RSA", "EC", "SM2"}
static QStringList supportDigestNames();          // MD5/SHA1/SHA2/SHA3/SM3
static QStringList supportECCurveNames();         // prime256v1/secp256k1/secp384r1/secp521r1
static QStringList supportRSABitsNames();         // 512-bit ~ 8192-bit
static QStringList supportSymModesNames();        // ECB/CBC/GCM/CTR
static SymMode symModeFromName(name);
```

**错误管理**：

```cpp
QString lastErrors() const;
void clearErrors();
void appendError(const QString &error);
```

### 4.3 CertificateManager（证书管理对话框）

**文件**：`modules/certificatemanager/certificatemanager.h/cpp`

**继承关系**：`QDialog`

| 类型 | 成员 | 说明 |
|------|------|------|
| **枚举** | `CertType { CERT_EndEntity=0, CERT_SubordinateCA, CERT_RootCACustom, CERT_RootCACetXiyuan }` | 四种证书类型 |
| **公开方法** | `genCertificate(type, outputDir)` → `bool` | 统一的证书生成入口 |
| **公开方法** | `genCertificateCode(type, outputDir, cn, subjectDN, extMessage)` | API 代码路径（默认） |
| **公开方法** | `genCertificateOpenssl(type, outputDir, cn, subjectDN, extMessage)` | 命令行路径 |
| **公开方法** | `setCommonName(cn)` / `setValidDays(days)` / `setCertExts(exts)` | 配置方法 |
| **信号** | `issuerChanged(int type)` | 签发者变更通知 |
| **属性** | `m_subCAKeyPair` / `m_rootCAKeyPair` | CA 密钥对缓存 |
| **属性** | `m_subCACert` / `m_rootCACert` | CA 证书缓存 |

### 4.4 插件接口类

**CetLicenseInterface** — 许可管理：

| 方法 | 说明 |
|------|------|
| `initialize(productId)` | 通过产品 ID 初始化 |
| `activate()` → `int` | 静默激活，返回 `ACTIVATE_CANCEL(0)` / `ACTIVATE_OK(1)` / `ACTIVATE_ER(2)` |
| `activateWindow()` → `int` | 弹窗激活 |
| `resultString()` → `QString` | 激活结果描述 |
| `solidKey()` → `QString` | 设备固钥 |

**CetUpdateInterface** — 更新管理：

| 方法 | 说明 |
|------|------|
| `checkUpdate(appName, appVersion, callback)` | 检查新版本 |
| `inUpdating(newVersion)` → `bool` | 是否正在更新 |

**CetLogManagerInterface** — 日志管理：`show()` 显示控制窗口。

**CetProgressInterface** — 进度显示：空接口，预留扩展。

---

## 5. 关键数据流

### 5.1 证书生成流程（以终端证书为例）

```
用户点击"生成证书"按钮
    │
    ▼
MainWindow::on_genCertPushButton_clicked()
    │
    ▼
CertificateManager::genCertificate(type, outputDir)
    │  收集 UI 输入（国家/省份/城市/组织/部门/CN/邮箱）→ 构建 Subject DN
    │
    ├── [USE_OPENSSL_TOOL_HANDLER=0] genCertificateCode()
    │       │
    │       ├── 1. OpenSSLHelper::genKeyPair("RSA"/"EC"/"SM2", keySize, pass)
    │       │       └── EVP_PKEY_keygen_init() → EVP_PKEY_generate() → QPair<QSslKey, QSslKey>
    │       │
    │       ├── 2. OpenSSLHelper::genCSR(subjectDN, privateKey, extensions, pass)
    │       │       └── X509_REQ_new() → 设置主题/公钥/扩展 → X509_REQ_sign_ctx() → PEM CSR
    │       │
    │       ├── 3. OpenSSLHelper::signCSR(validDays, csrPem, caCert, caKey, extensions, hashAlgo)
    │       │       └── 解析 CSR → 创建 X509 → 设置序列号/有效期/扩展 → X509_sign_ctx()
    │       │
    │       ├── 4. 保存证书文件（PEM/DER 双格式）
    │       │
    │       ├── 5. genChain(subCACert, rootCACert) → ca-chain.pem
    │       ├── 6. toP7b(chainPem) → ca-chain.p7b
    │       └── 7. toPfx(cert, privateKey, chainPem, pfxPass) → full-bundle.pfx
    │
    └── 显示结果弹窗
```

### 5.2 对称加密流程（AES/SM4）

```
用户点击"加密"按钮
    │
    ▼
MainWindow::on_seaEncryptPushButton_clicked()
    │
    ├── 1. getData(isFile, fileName, inBase64)
    │       ├── 文件模式：QFile::readAll()
    │       └── 文本模式：QByteArray::fromHex(text)
    │
    ├── 2. 从 UI 获取 key/IV/mode
    │       key = QByteArray::fromHex(seaKeyLineEdit)
    │       iv  = QByteArray::fromHex(seaIvLineEdit)
    │       mode = OpenSSLHelper::symModeFromName(comboBox)
    │
    ├── 3. 执行加密
    │       AES: aesEncrypt(data, key, mode, iv)
    │       │   返回格式：GCM=IV+密文+Tag | 其他=IV+密文
    │       SM4: sm4Encrypt(data, key, mode, iv)
    │           返回格式：仅密文（无 IV 前缀，需单独管理 IV）
    │
    └── 4. 输出（Base64/Hex/文件）
```

### 5.3 许可激活流程

```
应用启动
    │
    ▼
CetToolPluginContext::initFeatures()
    │
    ├── 1. 自检 CetProductWizard.dll SHA256 完整性
    ├── 2. 加载 CetLicensePlugin.dll（QPluginLoader）
    ├── 3. initialize(PRODUCT_NAME)
    ├── 4. 上电 30 秒后首次自动激活
    └── 5. 定时激活（间隔 10min→20min→40min... 翻倍递增，上限 24h；超限后重置回 10min）
         ├── 许可正常：持续定时激活
         ├── 临时授权：记录状态，到期前提醒
         └── 拒绝/停用：停止自动重试
```

---

## 6. 依赖关系

### 6.1 外部库依赖

| 库 | 版本 | 用途 | 链接方式 |
|------|------|------|------|
| **OpenSSL** | 3.x | 所有密码学运算 | 动态链接 `libcrypto-3.dll` / `libssl-3.dll` |
| **Qt** | 5.15.2 | GUI 框架、网络、文件操作 | 动态链接 |
| **CetProductWizard** | — | 产品向导框架 + SHA256 校验基准 DLL | 编译时链接 `-lCetProductWizard` |

### 6.2 Qt 模块依赖

```
QT += core gui network widgets
```

| 模块 | 用途 |
|------|------|
| `QtCore` | QObject、QByteArray、QTimer、QProcess |
| `QtGui` | QKeyEvent、高 DPI 支持 |
| `QtWidgets` | QMainWindow、QDialog、QMessageBox、QFileDialog |
| `QtNetwork` | QSslCertificate、QSslKey（Qt 内置 SSL 类型） |

### 6.3 构建依赖树

```
CetCryptoToolkit.pro（qmake 主入口）
├── mainwindow/mainwindow.pri
│   └── mainwindow.h/cpp/ui
├── modules/modules.pri
│   ├── opensslhelper/opensslhelper.pri
│   │   └── opensslhelper.h/cpp
│   └── certificatemanager/certificatemanager.pri
│       └── certificatemanager.h/cpp/ui
├── interfaces/interfaces.pri
│   └── *.h（纯头文件，无 .cpp）
└── LIBS: -lCetProductWizard -lcrypto-3 -lssl-3
```

### 6.4 内部模块依赖

```
main.cpp
  └── mainwindow.h
        ├── opensslhelper.h ────────── openssl/*.h (OpenSSL C API)
        ├── certificatemanager.h ────── opensslhelper.h
        └── cettoolplugincontext.h ──── cetlicenseinterface.h
                                       cetlogmanagerinterface.h
                                       cetupdateinterface.h
                                       cetprogressinterface.h
```

`CertificateManager` 依赖 `OpenSSLHelper`，`CetToolPluginContext` 管理所有插件接口，`MainWindow` 依赖所有模块。

---

## 7. 配置与目录约定

| 路径 | 用途 |
|------|------|
| `Configs/AppMaster.ini` | 应用配置（QSettings，UTF-8 编码） |
| `dir-certs/` | 证书输出目录 |
| `dir-asymmetrics/` | 非对称加密文件目录 |
| `dir-symmetrics/` | 对称加密文件目录 |
| `libs/` | 预编译 DLL（OpenSSL 3.x、CetProductWizard） |
| `plugins/` | Qt 插件 DLL 搜索目录（备用路径） |

---

## 8. 国密算法支持说明

OpenSSL 3.x 默认 provider 已内置国密支持，程序启动时检测并打印：

```
SM2 is in default provider
SM3 is in default provider
SM4 is in default provider
CMAC is in default provider
```

SM2 签名特殊性：需要传入 `userId`（默认为标准值 `1234567812345678`），这是 SM2 签名算法的 ZA 值计算必须项，与 RSA/EC 签名接口有所不同。

若未打印国密日志，说明 OpenSSL 版本不支持国密，需升级至 3.0.18+。

---

## 9. 设计决策与取舍

### 9.1 双实现路径：OpenSSL API vs openssl.exe 命令行

**决策**：证书生成保留两套实现，通过 `USE_OPENSSL_TOOL_HANDLER` 宏切换（默认 `0`，即 API 路径）。

**理由**：
- **API 路径**：直接调用 OpenSSL C API，性能更高，无需外部进程，不依赖 `openssl.exe` 路径
- **命令行路径**：用于调试和验证，API 路径出问题时对比命令行结果

**取舍**：双代码路径的维护成本，但 API 路径更适合生产部署。

### 9.2 插件化的功能扩展

**决策**：日志/许可/更新/进度功能通过 Qt 插件机制（`QPluginLoader`）实现，v2.5.0 引入 `CetToolPluginContext` 统一管理（CAN 插件独立存在，主程序未加载）。

**理由**：解耦主程序与商业功能，各模块独立开发升级。基础版/Custom 版/全功能版通过不同插件组合实现。插件缺失仅警告，不影响核心密码学功能。`CetToolPluginContext` 提供编译时 SHA256 校验，防止插件 DLL 被替换或篡改，增强安全性。

### 9.3 三级 PKI 证书体系

RootCA（pathlen:1）→ SubCA（pathlen:0）→ EndEntity，严格限制证书链深度。终端证书支持 SAN 扩展。

---

## 10. 扩展点

### 10.1 新算法支持

| 扩展点 | 位置 | 说明 |
|------|------|------|
| 新增密钥算法 | `supportedKeyAlgorithms` 静态列表 | 添加条目即可出现在 UI |
| 新增摘要算法 | `supportedDigests` 静态列表 | OpenSSL 3.x 支持的 EVP_MD 都可添加 |
| 新增 EC 曲线 | `supportedEcCurves` 静态列表 | 需 OpenSSL 支持该曲线 NID |
| 新增对称算法 | `opensslhelper.cpp` 添加新方法 | 如 SM4-GCM |

### 10.2 插件接口扩展

- `CetProgressInterface` 当前为空接口，可添加进度条、取消操作
- 所有接口通过 Qt 插件机制加载新 DLL

### 10.3 UI/功能扩展

| 扩展点 | 位置 | 说明 |
|------|------|------|
| 新增证书类型 | `CertType` 枚举 + `genCertificateCode()` switch | 中间 CA 层级 |
| 新增加密模式 | `SymMode` 枚举 | XTS、CFB、OFB 等 |
| 证书吊销 | CRL 生成方法 | 代码已注释，可供参考 |
| OCSP 响应 | 注释中有 `OCSP=URI:...` 示例 | OCSP stapling |
