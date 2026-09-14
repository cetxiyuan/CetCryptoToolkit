# CetCryptoToolkit API 参考

> 适用版本：CetCryptoToolkit v2.6.0
> 核心类：`OpenSSLHelper`
> 文件：`modules/opensslhelper/opensslhelper.h/cpp`

---

## 1. 全局宏与常量（version.h）

### 1.1 版本信息

```cpp
#define IS_RELEASE_VERSION      ( 0 )   // 正式版=1，开发版=0（当前仓库为开发版）
#define APP_NAME                "CetCryptoToolkit"
#define PRODUCT_ICON            "favorite.ico"

#define VER_MAJOR               2       // 主版本号
#define VER_MINOR               6       // 次版本号
#define VER_MICRO               0       // 小版本号

#define RELEASE_DATE            "(3.0.18)(CXYQK5152.CCTK260.G832)"
// G832: G=2026年, 8=8月, 32=24日 (32-8=24), 即2026-08-24

#define PATCH_PACKET            "8281"  // 月+日+序号（开发版使用）
#define COMPANY_NAME            "CetXiyuan"
```

### 1.2 版本工具宏

```cpp
#define VERSION_CHECK(major, minor, micro)  (((major)<<16)|((minor)<<8)|((micro)<<0))
#define VERSION_STRING(major, minor, micro) __STR(major) "." __STR(minor) "." __STR(micro)
#define DIRECT_STRING(major, minor, micro)  __STR(major) __STR(minor) __STR(micro)
#define __STR(var)   #var

#if (IS_RELEASE_VERSION > 0)
#define TIP_VERSION             RELEASE_DATE
#define APP_VERSION             VERSION_STRING(VER_MAJOR, VER_MINOR, VER_MICRO)  // "2.6.0"
#else
#define TIP_VERSION             RELEASE_DATE " Patch-" PATCH_PACKET
#define APP_VERSION             VERSION_STRING(VER_MAJOR, VER_MINOR, VER_MICRO) "." PATCH_PACKET  // "2.6.0.8281"
#endif

/* 文件/产品版本（app.rc 使用） */
#define FILE_VERSION            VER_MAJOR,VER_MINOR,VER_MICRO
#define FILE_VERSION_STR        APP_VERSION
#define PRODUCT_VERSION         FILE_VERSION
#define PRODUCT_VERSION_STR     FILE_VERSION_STR
#define ORIGINAL_NAME           APP_NAME ".exe"

#define FILE_DESCRIPTION        APP_NAME " based on Qt 5.15.2 (MinGW, 32 bit)"
#define LEGAL_COPYRIGHT         "Copyright 2008-2035 The " COMPANY_NAME " Ltd. All rights reserved."
#define PRODUCT_NAME            APP_NAME DIRECT_STRING(VER_MAJOR, VER_MINOR, 0)
#define ORGANIZATION_DOMAIN     "https://www.cetxiyuan.com/"
```

---

## 2. OpenSSLHelper — 密码学核心封装

**文件**：`modules/opensslhelper/opensslhelper.h/cpp`
**继承**：`QObject`

### 2.1 枚举

```cpp
enum SymMode {
    SYM_ECB,    // 电子密码本模式（不推荐用于多块数据）
    SYM_CBC,    // 密码分组链接模式
    SYM_GCM,    // 伽罗瓦计数器模式（认证加密，含 Tag）
    SYM_CTR     // 计数器模式（流式加密）
};
```

### 2.2 生命周期

```cpp
explicit OpenSSLHelper(QObject *parent = nullptr);  // 构造时自动调用 initOpenSSL()
~OpenSSLHelper();                                    // 析构时自动调用 cleanupOpenSSL()

static void initOpenSSL();      // 加载所有算法和字符串，单例模式
static void cleanupOpenSSL();   // EVP_cleanup() + CRYPTO_cleanup_all_ex_data()
```

启动时自动检测并打印国密支持：

```
SM2 is in default provider
SM3 is in default provider
SM4 is in default provider
CMAC is in default provider
```

### 2.3 密钥生成

```cpp
QPair<QSslKey, QSslKey> genKeyPair(
    const QString &algorithm,       // "RSA" / "EC" / "SM2"
    const QString &keySize = "2048-bit",
    const QString &passphrase = ""  // 非空时用 AES-256-CBC 加密私钥（PKCS#8）
);
```

- **返回值**：`QPair<公钥, 私钥>`，失败时两个 QSslKey 均为 null
- **RSA** 密钥大小：512 / 1024 / 2048 / 3072 / 4096 / 8192-bit
- **EC** 曲线：prime256v1 / secp256k1 / secp384r1 / secp521r1
- **SM2**：固定 256-bit 曲线，keySize 参数忽略

### 2.4 证书生成与签发

```cpp
// 生成自签证书
QSslCertificate genSelfCert(
    int validDays,                    // 有效天数
    const QString &subjectDN,         // "/C=CN/ST=Fujian/O=CetXiyuan/CN=Root CA"
    const QSslKey &privateKey,        // 签名用私钥
    const QStringList &extensions,    // X.509 v3 扩展列表
    const QString &hashAlgo = "sha256",
    const QString &passphrase = ""
);

// 生成 CSR（PEM 格式返回）
QString genCSR(
    const QString &subjectDN,
    const QSslKey &privateKey,
    const QStringList &extensions = {},
    const QString &passphrase = ""
);

// CA 签发 CSR
QSslCertificate signCSR(
    int validDays,
    const QString &csrPem,            // PEM 格式 CSR
    const QSslCertificate &caCert,    // CA 证书
    const QSslKey &caPrivateKey,      // CA 私钥
    const QStringList &extensions = {},
    const QString &hashAlgo = "sha256",
    const QString &passphrase = ""
);
```

> SM2 密钥使用这些方法时，内部自动启用 SM3 作为签名摘要算法。

### 2.5 证书格式转换

```cpp
QByteArray genChain(const QSslCertificate &subCACert, const QSslCertificate &rootCACert);
// PEM 拼接：SubCA + RootCA

QByteArray toP7b(const QByteArray &chainPem);
// PEM → PKCS#7（DER 编码）

QByteArray toPfx(
    const QSslCertificate &cert,
    const QSslKey &privateKey,
    const QByteArray &chainPem,       // 证书链 PEM
    const QString &passphrase = ""    // PFX 保护密码
);
// 生成 PKCS#12（证书+私钥+证书链）

QByteArray toDer(const QByteArray &pemData);
// PEM → DER，自动识别内容类型（私钥/公钥/CSR/证书）
```

### 2.6 摘要与签名

```cpp
// 计算摘要（11 种算法：MD5/SHA1/SHA224/SHA256/SHA384/SHA512/SHA3系列/SM3）
QByteArray digest(const QByteArray &data, const QString &hashAlgo);

// 对摘要值签名
QByteArray signDigest(
    const QByteArray &digest,
    const QSslKey &privateKey,
    const QString &hashAlgo = "sha256",
    const QString &passphrase = "",
    const QByteArray &userId = ""     // SM2：默认 "1234567812345678"
);
// RSA：RSA_PKCS1_PADDING；SM2：EVP_PKEY_CTX_set1_id()

// 对原始数据签名（内部先摘要再签名）
QByteArray signData(
    const QByteArray &data,
    const QSslKey &privateKey,
    const QString &hashAlgo = "sha256",
    const QString &passphrase = "",
    const QByteArray &userId = ""
);

// 验证签名
bool signVerify(
    const QByteArray &data,
    const QByteArray &signature,      // 需 DER 格式（SM2 签名以 0x30 开头）
    const QSslKey &publicKey,
    const QString &hashAlgo = "sha256",
    const QByteArray &userId = ""
);
```

### 2.7 非对称加解密

```cpp
static QByteArray asymmetricEncrypt(const QByteArray &data, const QSslKey &publicKey);
// RSA：RSA_PKCS1_OAEP_PADDING + SHA-256 MGF1
// EC/SM2：默认参数

static QByteArray asymmetricDecrypt(const QByteArray &data, const QSslKey &privateKey);
```

### 2.8 AES 对称加解密

```cpp
static QByteArray aesEncrypt(
    const QByteArray &plaintext,
    const QByteArray &key,            // 16/24/32 字节 → AES-128/192/256
    SymMode mode = SYM_ECB,
    const QByteArray &iv = QByteArray()
);
// 输出格式：ECB/CBC/CTR = IV(16B) + 密文, GCM = IV(12B) + 密文 + Tag(16B)

static QByteArray aesDecrypt(
    const QByteArray &ciphertext,     // 需与加密输出格式一致
    const QByteArray &key,
    SymMode mode = SYM_ECB
);
// GCM 模式自动分离 IV/密文/Tag 并验证完整性

static QByteArray aes128GenerateCMAC(const QByteArray &data, const QByteArray &key);
static QByteArray aesGenerateKey(int keySize = 32);     // 随机密钥
static QByteArray aesGenerateIV(SymMode mode);          // 随机 IV（GCM=12B, 其他=16B）
```

### 2.9 SM4 对称加解密

```cpp
QByteArray sm4Encrypt(const QByteArray &plaintext, const QByteArray &key,
                       SymMode mode, const QByteArray &iv);
// 仅支持 SYM_ECB 和 SYM_CBC（GCM/CTR 返回空）
// 返回值：仅密文（不含 IV 前缀）

QByteArray sm4Decrypt(const QByteArray &ciphertext, const QByteArray &key,
                       SymMode mode, const QByteArray &iv);
// 仅支持 SYM_ECB 和 SYM_CBC
// ciphertext 不含 IV 前缀，需单独传入加密时使用的 IV
```

- SM4 固定 16 字节密钥（128-bit）
- **SM4 仅支持 ECB 和 CBC 两种模式**（不支持 GCM/CTR，选择 GCM/CTR 将返回空）
- **SM4 解密必须手动传入 IV**，与 AES 不同（AES 自动从密文前缀解析）
- **SM4 密文不含 IV 前缀**，需单独管理 IV（与 AES 不同）

### 2.10 SM2 格式转换

```cpp
QByteArray sm2PubKeyToDer(const QByteArray &rawPubKey);  // 裸公钥(64B, X+Y，内部自动补 0x04 前缀) → DER
QByteArray sm2SignToDer(const QByteArray &rawSignKey);   // 裸签名(r||s, 64B) → DER
```

- SM2 裸签名首字节不是 `0x30`（DER 格式标识），需用 `sm2SignToDer()` 转换后才能验签

### 2.11 支持列表查询

```cpp
static QStringList supportKeyAlgorithmNames();   // {"RSA", "EC", "SM2"}
static QStringList supportDigestNames();          // {MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SM3}
static QStringList supportECCurveNames();         // {prime256v1, secp256k1, secp384r1, secp521r1}
static QStringList supportRSABitsNames();         // {512-bit, 1024-bit, 2048-bit, 3072-bit, 4096-bit, 8192-bit}
static QStringList supportSymModesNames();        // {ECB, CBC, GCM, CTR}

static int keyAlgorithmFromName(const QString &name);    // → EVP_PKEY_*
static int ecCurveFromName(const QString &name);         // → NID_*
static int rsaBitsFromName(const QString &name);         // → 512/1024/...
static SymMode symModeFromName(const QString &name);     // → SymMode
```

### 2.12 证书文件读写

```cpp
static QList<QSslCertificate> loadCertificates(const QString &filePath);
static bool saveCertificate(const QSslCertificate &cert, const QString &filePath);
static QList<QSslCertificate> loadPKCS12(const QByteArray &pkcs12Data,
                                          const QString &passphrase,
                                          QSslKey *privateKey = nullptr);
static QSslKey loadPublicKey(const QString &filePath);
static bool savePublicKey(const QSslKey &publicKey, const QString &filePath);
static QSslKey loadPrivateKey(const QString &filePath);
static bool savePrivateKey(const QSslKey &privateKey, const QString &filePath);
```

> **注意**：`loadPKCS12` 提取私钥时固定按 `QSsl::Rsa` 解析，对于 EC/SM2 密钥可能返回 null 的 QSslKey。非 RSA 密钥建议从单独的私钥文件加载。
> `loadPrivateKey` / `loadPublicKey` 自动尝试 RSA 和 EC 两种算法解析（先 RSA 后 EC）。

### 2.13 错误管理

```cpp
QString lastErrors() const;         // 获取错误信息（含 OpenSSL 原始错误栈）
void clearErrors();                 // 清空错误队列
void appendError(const QString &error);
```

> 错误队列存储于私有成员 `QList<QString> m_errors`。

### 2.14 OpenSSL 命令行工具封装（public）

调用外部 `openssl.exe` 的封装（`CertificateManager::genCertificateOpenssl()` 即 `USE_OPENSSL_TOOL_HANDLER=1` 调试路径依赖此组 API）：

```cpp
bool opensslGenKeyPair(const QString &algorithm,  // "RSA"/"EC"
                       const QString &keySize,    // RSA:2048/3072/4096, EC:256/384/521
                       const QString &privKeyPath,
                       const QString &pubKeyPath = "",
                       const QString &passphrase = "");
bool opensslGenSelfCert(int validDays, const QString &subjectDN,
                        const QString &keyPath, const QString &outPath,
                        const QString &hashAlgo = "-sha256",   // 注意：实现内部自动补 "-"，实际应传 "sha256"
                        const QString &passphrase = "");
bool opensslGenCSR(const QString &subjectDN, const QString &keyPath,
                   const QString &outPath, const QStringList &extensions,
                   const QString &passphrase = "");
bool opensslSignCSR(int validDays, const QString &csrPath,
                    const QString &caPath, const QString &caKeyPath,
                    const QString &outPath, const QStringList &extensions,
                    const QString &hashAlgo = "-sha256",
                    const QString &passphrase = "");
bool opensslGenChain(const QString &subCAPath,     // 证书链 = 一级根证书 + 二级根证书
                     const QString &rootCAPath, const QString &outPath);
bool opensslToP7b(const QString &chainPath, const QString &outPath);
bool opensslToPfx(const QString &pemPath,          // PFX = 证书链 + 终端私钥 + 终端证书
                  const QString &pemKeyPath, const QString &chainPath,
                  const QString &outPath, const QString &passphrase = "");
bool opensslToDer(const QString &pemPath, const QString &outPath);
bool opensslTool(const QString &program, const QStringList &arguments);  // 通用命令行调用
bool opensslTest(void);
```

### 2.15 私有辅助方法

| 方法 | 说明 |
|------|------|
| `parseSubjectDN(subjectDN)` → `X509_NAME*` | 解析 "/CN=.../O=..." 格式 DN |
| `addExtensions(ca, cert, req, exts)` → `bool` | 为 X509/X509_REQ 添加扩展 |
| `getOpenSSLError()` → `QString` | 获取 OpenSSL 错误栈 |
| `aesCipher(mode, key)` → `const EVP_CIPHER*`（static） | 密钥长度自动选择 AES-128/192/256 |
| `digestFromName(name)` → `const EVP_MD*`（static） | 算法名（"sha256" 等）→ EVP_MD |
| `qcertToX509(cert)` → `X509*`（static） | QSslCertificate → X509 |
| `qsslkeyToEVP(key)` → `EVP_PKEY*`（static） | QSslKey → EVP_PKEY |
| `callbackPassword(...)` → `int`（static） | PEM 密码回调 |

---

## 3. CertificateManager

**文件**：`modules/certificatemanager/certificatemanager.h/cpp`
**继承**：`QDialog`

### 3.1 枚举

```cpp
enum CertType {
    CERT_EndEntity = 0,     // 终端证书 → SubCA 签发
    CERT_SubordinateCA,     // 二级根证书 → RootCA 签发
    CERT_RootCACustom,      // 一级根证书（自定义 DN）
    CERT_RootCACetXiyuan,   // 一级根证书（CetXiyuan 预置 DN）
};
Q_ENUM(CertType)
```

### 3.2 构造

```cpp
explicit CertificateManager(OpenSSLHelper *openSSLHelper, QWidget *parent = nullptr);
```

- 自动加载已存在的 CA 证书
- 不存在时 2 秒后自动生成 `CERT_RootCACetXiyuan`
- 1 秒后发射 `issuerChanged` 信号

### 3.3 证书生成

```cpp
bool genCertificate(int type, const QString &outputDir);
// 统一入口，内部根据 USE_OPENSSL_TOOL_HANDLER 选择路径

QSslCertificate genCertificateCode(int type, const QString &outputDir,
    const QString &commonName, const QString &subjectDN, QString &extMessage);
// API 代码路径（默认）

QSslCertificate genCertificateOpenssl(int type, const QString &outputDir,
    const QString &commonName, const QString &subjectDN, QString &extMessage);
// 命令行路径
```

### 3.4 配置与文件保存

```cpp
void setCommonName(const QString &cn);        // 自动调整密钥参数
void setValidDays(int days);
void setCertExts(const QString &exts);
bool saveToFile(const QByteArray &data, const QString &filePath);
void saveCertificateFiles(keyPair, csrData, sslCert, outputDir, cn);
void saveCertificateCAFiles(keyPair, caCert, outputDir, caName);
```

### 3.5 信号与槽

```cpp
Q_SIGNALS:
    void issuerChanged(int type);  // 签发者变更 → MainWindow 更新 UI

private slots:
    void on_keyTypeComboBox_currentTextChanged(const QString &arg1);
    // 密钥类型切换：RSA 显示位数字段 / EC 显示曲线字段 / SM2 锁定摘要为 SM3
```

### 3.6 常量

```cpp
#define CAROOT_DEF_COMMONNAME   "CetXiyuan Root CA Signing Authority"
#define CAROOT_CUS_COMMONNAME   "CetXiyuan Custom Root CA Signing Authority"
#define CASUB_DEF_COMMONNAME    "CetXiyuan Subordinate CA Signing Authority"
#define USE_OPENSSL_TOOL_HANDLER (0)  // 0=API路径, 1=openssl.exe路径（编译期宏，修改需重新编译）

// 默认输出目录（应用目录下）
#define CAROOT_DEF_DIR  QCoreApplication::applicationDirPath() + "/dir-certs"
#define CASUB_DEF_DIR   CAROOT_DEF_DIR

// 预定义证书扩展（RootCA/SubCA/EndEntity 各一套，内容见第 7 节）
#define CAROOT_DEF_CERTEXTS ...
#define CASUB_DEF_CERTEXTS ...
#define ENDENTITY_DEF_CERTEXTS ...
```

### 3.7 私有成员（摘要）

| 成员 | 类型 | 说明 |
|------|------|------|
| `m_openSSLHelper` | `OpenSSLHelper *const` | 密码学核心（外部传入） |
| `m_rootCAKeyPair` / `m_subCAKeyPair` | `QPair<QSslKey,QSslKey>` | 根/二级 CA 密钥对 |
| `m_rootCACert` / `m_subCACert` | `QSslCertificate` | 根/二级 CA 证书 |
| 私有方法 `loadCA(cert, keyPair, dir, tier, caname)` | | 启动时从 dir-certs 加载已有 CA |

---

## 4. MainWindow

**文件**：`mainwindow/mainwindow.h/cpp`
**继承**：`QMainWindow`

### 4.1 数据获取

```cpp
QByteArray getData(bool isFile, const QString &fileName, bool inBase64 = false);
// 统一数据入口：文件→QFile::readAll() | 文本→fromHex() | Base64→fromBase64()
```

### 4.2 插件管理（CetToolPluginContext）

v2.5.0 起，插件加载由 `CetToolPluginContext` 统一管理：

```cpp
// mainwindow.h
CetToolPluginContext *const m_toolPluginCtx;
```

```cpp
// mainwindow.cpp 构造函数初始化列表
m_toolPluginCtx(new CetToolPluginContext(HASH_CetProductWizard_DLL, this))

// 构造函数体中调用
m_toolPluginCtx->initFeatures(ui->logManagerMenu, ui->licenseMenu,
    PRODUCT_NAME, tr(CETCRYPTOTOOLKIT_VERSION), APP_NAME, APP_VERSION);
// 可选传入 std::function<void(bool)> 回调处理激活结果
```

通过 `m_toolPluginCtx->license()` / `m_toolPluginCtx->updater()` 等访问器获取插件接口。

### 4.3 重要属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `m_openSSLHelper` | `OpenSSLHelper *const` | 密码学核心 |
| `m_certManager` | `CertificateManager *const` | 证书管理对话框 |
| `m_toolPluginCtx` | `CetToolPluginContext *const` | 插件统一管理（v2.5.0） |
| `m_privateKey` / `m_publicKey` | `QSslKey` | 非对称加解密密钥 |
| `m_settings` | `QSettings *const` | INI 配置（UTF-8） |

---

## 5. CetToolPluginContext

**文件**：`mainwindow/cettoolplugincontext.h`
**继承**：`QWidget`
**v2.5.0 新增**

统一管理所有功能插件的加载、完整性校验和生命周期。

### 5.1 构造与初始化

```cpp
explicit CetToolPluginContext(const QString &selfHash, QWidget *parent = nullptr);
// selfHash: CetProductWizard.dll 的 SHA256 哈希，用于运行时完整性校验

void initFeatures(QMenu *logManagerMenu,
                  QMenu *licenseMenu,
                  const QString &productName,
                  const QString &versionTitle,
                  const QString &appName,
                  const QString &appVersion,
                  std::function<void(bool activated)> onActivated = nullptr);
// 一次性初始化所有功能插件，连接菜单和信号
```

### 5.2 接口访问器

```cpp
CetLogManagerInterface *logManager() const;
CetLicenseInterface   *license()   const;
CetUpdateInterface    *updater()   const;
CetProgressInterface  *progress()  const;
```

### 5.2.1 试用提醒（v2.5.1 新增）

```cpp
// cettoolplugincontext.h 私有成员
TrialReminder *m_trialReminder = nullptr;
// 由 CetProductWizard.dll 内部实现，提供试用期到期提醒功能
```

### 5.3 带校验的插件加载

```cpp
QObject *loadPlugin(const QString &dllName, QString *errInfo = nullptr);
// 加载 DLL 前先验证 DLL 文件哈希是否与编译时记录一致
// 校验失败返回 nullptr，errInfo 包含错误描述
```

### 5.4 完整性校验（私有）

```cpp
// private static — 由构造和 loadPlugin 内部调用
static bool selfIntegrityCheck(const QString &expectedHash);
// 运行时计算 CetProductWizard.dll 的 SHA256，与编译时哈希对比
// 防止 DLL 被替换或篡改
```

---

## 6. 插件接口

三个接口均为**普通 C++ 抽象类**（非 `QObject` 派生），带虚析构与 `Q_DECLARE_INTERFACE` 导出宏，定义在 `interfaces/` 目录。

### CetLicenseInterface

```cpp
enum ActivateResult { ACTIVATE_CANCEL = 0, ACTIVATE_OK, ACTIVATE_ER };

virtual void initialize(const QString &productId) = 0;
virtual int activate() = 0;           // 静默激活
virtual int activateWindow() = 0;     // 弹窗激活
virtual QString resultString() = 0;   // 结果描述
virtual QString solidKey() = 0;       // 设备固钥
```

### CetUpdateInterface

```cpp
typedef void (*callback_t)(void);

virtual void checkUpdate(const QString &appName, const QString &appVersion,
    callback_t callback = nullptr) = 0;  // 回调如 QCoreApplication::quit
virtual bool inUpdating(QString &newVersion) = 0;
```

### CetLogManagerInterface

```cpp
virtual void show() = 0;  // 显示日志控制窗口
```

---

## 7. 证书扩展字段格式

每行一条，支持的关键扩展：

```
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:example.com,IP:192.168.1.100
crlDistributionPoints=URI:http://example.com/crl
certificatePolicies=1.2.3.4
```

> **提示**：以 `#` 开头的行被视为注释，将被 `addExtensions()` 自动跳过。

---

## 8. 预定义目录

```cpp
#define DIR_CERTS        QCoreApplication::applicationDirPath() + "/dir-certs"
#define DIR_ASYMMETRICS  QCoreApplication::applicationDirPath() + "/dir-asymmetrics"
#define DIR_SYMMETRICS   QCoreApplication::applicationDirPath() + "/dir-symmetrics"
```

---

## 9. 使用示例

### 9.1 RSA 密钥对 + 签名验签

```cpp
OpenSSLHelper helper;
auto kp = helper.genKeyPair("RSA", "2048-bit");
QByteArray sig = helper.signData("data", kp.second, "sha256");
bool ok = helper.signVerify("data", sig, kp.first, "sha256");
```

### 9.2 AES-256-GCM 加解密

```cpp
QByteArray key = OpenSSLHelper::aesGenerateKey(32);
QByteArray iv  = OpenSSLHelper::aesGenerateIV(OpenSSLHelper::SYM_GCM);
QByteArray cipher = OpenSSLHelper::aesEncrypt("plaintext", key, OpenSSLHelper::SYM_GCM, iv);
QByteArray plain  = OpenSSLHelper::aesDecrypt(cipher, key, OpenSSLHelper::SYM_GCM);
```

### 9.3 SM2 签名

```cpp
auto kp = helper.genKeyPair("SM2");
QByteArray sig = helper.signData("data", kp.second, "sm3", "", "1234567812345678");
bool ok = helper.signVerify("data", sig, kp.first, "sm3", "1234567812345678");
```

### 9.4 SM4-CBC 加解密

```cpp
QByteArray key  = QByteArray::fromHex("0123456789ABCDEF0123456789ABCDEF");
QByteArray iv   = QByteArray::fromHex("00000000000000000000000000000000");
QByteArray data = "Hello, SM4!";

QByteArray cipher = helper.sm4Encrypt(data, key, OpenSSLHelper::SYM_CBC, iv);
QByteArray plain  = helper.sm4Decrypt(cipher, key, OpenSSLHelper::SYM_CBC, iv);
```

### 9.5 三级 PKI 证书生成

```cpp
OpenSSLHelper helper;

// 1. 一级根证书
auto rootKP = helper.genKeyPair("RSA", "2048-bit");
auto rootCert = helper.genSelfCert(3650, "/C=CN/O=CetXiyuan/CN=Root CA",
    rootKP.second, {"basicConstraints=critical,CA:TRUE,pathlen:1"}, "sha256");

// 2. 二级根证书
auto subKP = helper.genKeyPair("RSA", "2048-bit");
QString subCsr = helper.genCSR("/C=CN/O=CetXiyuan/CN=Sub CA", subKP.second,
    {"basicConstraints=critical,CA:TRUE,pathlen:0"});
auto subCert = helper.signCSR(1825, subCsr, rootCert, rootKP.second,
    {"basicConstraints=critical,CA:TRUE,pathlen:0"}, "sha256");

// 3. 终端证书
auto endKP = helper.genKeyPair("RSA", "2048-bit");
QStringList endExts = {"basicConstraints=CA:FALSE",
    "keyUsage=digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth,clientAuth",
    "subjectAltName=DNS:example.com,IP:127.0.0.1"};
QString endCsr = helper.genCSR("/C=CN/O=CetXiyuan/CN=example.com", endKP.second, endExts);
auto endCert = helper.signCSR(365, endCsr, subCert, subKP.second, endExts, "sha256");

// 4. 打包 PFX
QByteArray pfx = helper.toPfx(endCert, endKP.second,
    helper.genChain(subCert, rootCert), "password");
```

### 9.6 SM2 证书签发

```cpp
QPair<QSslKey, QSslKey> keyPair = helper.genKeyPair("SM2");
QSslCertificate rootCert = helper.genSelfCert(
    3650, "/C=CN/O=CetXiyuan/CN=SM2 Root CA",
    keyPair.second,
    {"basicConstraints=critical,CA:TRUE,pathlen:1"},
    "sm3"   // 使用 SM3 签名
);
```

---

## 10. 国密算法详细说明

### 10.1 概述

国密算法是中国国家密码管理局（OSCCA）制定的密码标准，CetCryptoToolkit 通过 OpenSSL 3.x 提供完整支持：

| 算法 | 类型 | 对应国际算法 | 密钥长度 | 说明 |
|------|------|------------|---------|------|
| **SM2** | 非对称加密/签名 | ECC（椭圆曲线） | 256-bit | 基于 SM2 椭圆曲线 |
| **SM3** | 摘要（哈希） | SHA-256 | — | 输出 256-bit 摘要 |
| **SM4** | 对称加密 | AES-128 | 128-bit | 分组密码 |

### 10.2 SM2 签名特殊性

SM2 签名与 RSA/EC 的关键区别：**必须传入 `userId`**（用于计算 ZA 值）。

```cpp
QByteArray data   = "待签名数据";
QByteArray userId = "1234567812345678";  // GB/T 35276 标准默认值

QByteArray signature = helper.signData(data, privateKey, "sm3", "", userId);
bool ok = helper.signVerify(data, signature, publicKey, "sm3", userId);
```

> ⚠️ 与第三方系统对接时，双方必须使用相同的 `userId`，否则验签必然失败。

### 10.3 SM2 签名格式转换

SM2 签名输出为 DER 格式（首字节 `0x30`）。若收到裸格式（r||s，64字节）：

```cpp
QByteArray rawSign = ...; // 64字节（r 32字节 + s 32字节）
if (rawSign.at(0) != 0x30) {
    rawSign = helper.sm2SignToDer(rawSign);  // 转为 DER
}
bool ok = helper.signVerify(data, rawSign, publicKey, "sm3", userId);
```

### 10.4 SM2 公钥格式转换

```cpp
QByteArray rawPubKey = ...;         // 64字节（X + Y，不含 0x04 前缀，内部自动补齐）
QByteArray derPubKey = helper.sm2PubKeyToDer(rawPubKey);
```

### 10.5 SM4 各模式说明

> ⚠️ **SM4 当前仅支持 ECB 和 CBC 两种模式**（OpenSSL 3.x 的 SM4 实现尚不支持 GCM/CTR）。

| 模式 | IV 长度 | 密文格式 | 特点 |
|------|--------|---------|------|
| ECB | 不需要 | 仅密文 | 最简单，不推荐用于敏感数据 |
| CBC | 16字节 | 仅密文（IV 单独管理） | 常用，需要 padding |

> ⚠️ **SM4 与 AES 的关键差异**：
> 1. AES 解密时 IV 从密文前缀自动解析；SM4 密文不含 IV，解密时**必须**手动传入 IV
> 2. SM4 不支持 GCM/CTR 模式，选择 GCM/CTR 将导致加密失败（返回空）

### 10.6 SM4-CBC 示例

```cpp
QByteArray key  = QByteArray::fromHex("0123456789ABCDEF0123456789ABCDEF");
QByteArray iv   = QByteArray::fromHex("00000000000000000000000000000000"); // CBC 用 16字节
QByteArray data = "Hello, SM4!";

// CBC 加密（返回纯密文，不含 IV）
QByteArray cipher = helper.sm4Encrypt(data, key, OpenSSLHelper::SYM_CBC, iv);

// CBC 解密（必须传入加密时使用的同一个 IV）
QByteArray plain  = helper.sm4Decrypt(cipher, key, OpenSSLHelper::SYM_CBC, iv);
```

### 10.7 SM3 摘要

与其他摘要接口完全一致：

```cpp
QByteArray hash = helper.digest(data, "SM3");
// 输出：32字节（256-bit），与 SHA-256 等长但算法不同
```

### 10.8 与第三方系统对接注意事项

1. **SM2 userId 必须协商一致**：建议约定为 `"1234567812345678"`（GB/T 35276 标准默认值）
2. **SM2 签名格式确认**：部分系统使用裸格式（64字节 r||s），需调用 `sm2SignToDer()` 转换
3. **SM4 IV 传递方式**：本工具在密文中内嵌 IV 前缀，若对方 IV 单独传递需手动拆分
4. **SM3 摘要长度**：32字节，与 SHA-256 相同但算法不同，不可混用
5. **SM2 证书链验证**：需对方系统支持 SM2 的 X.509 证书
6. **OpenSSL 版本要求**：需 1.1.1+ 版本才支持国密，推荐 3.0+
