# API 参考手册

> 适用版本：CetCryptoToolkit v2.3.x
> 核心类：`OpenSSLHelper`
> 文件：`modules/opensslhelper/opensslhelper.h/cpp`

---

## 一、概述

`OpenSSLHelper` 是 CetCryptoToolkit 中所有密码学操作的唯一封装层，直接调用 OpenSSL 3.x C API。所有上层模块均通过此类完成密码学运算。

---

## 二、初始化

| 方法 | 说明 |
|------|------|
| `static void initOpenSSL()` | 初始化 OpenSSL，加载所有算法。单例模式，构造函数自动调用 |
| `static void cleanupOpenSSL()` | 清理全局资源，析构函数自动调用 |

---

## 三、密钥对生成

### `genKeyPair()`

```cpp
QPair<QSslKey, QSslKey> genKeyPair(
    const QString &algorithm,       // "RSA" / "EC" / "SM2"
    const QString &keySize,         // RSA: "2048-bit"; EC: "prime256v1"; SM2: 忽略
    const QString &passphrase       // 私钥加密密码，空字符串表示不加密
);
```

返回 `QPair<公钥, 私钥>`，失败时返回空 QSslKey。

**支持的算法**：
- RSA：512 / 1024 / 2048 / 3072 / 4096 / 8192-bit
- EC：prime256v1 / secp256k1 / secp384r1 / secp521r1
- SM2：固定 256-bit 曲线

---

## 四、证书操作

### `genSelfCert()` — 自签证书

```cpp
QSslCertificate genSelfCert(
    int validDays,              // 有效期天数
    const QString &subjectDN,   // "/C=CN/O=CetXiyuan/CN=Root CA"
    const QSslKey &privateKey,
    const QStringList &extensions,
    const QString &hashAlgo,    // "sha256" / "sm3"
    const QString &passphrase
);
```

### `genCSR()` / `signCSR()` — CSR 签发

```cpp
QString genCSR(subjectDN, privateKey, extensions, passphrase);
QSslCertificate signCSR(validDays, csrPem, caCert, caPrivateKey, extensions, hashAlgo, passphrase);
```

### 证书格式转换

| 方法 | 说明 |
|------|------|
| `genChain(subCACert, rootCACert)` | 拼接证书链 PEM |
| `toP7b(chainPem)` | PEM 转 PKCS#7（.p7b） |
| `toPfx(cert, privateKey, chainPem, passphrase)` | 打包 PKCS#12（.pfx） |
| `toDer(pemData)` | PEM 转 DER |

---

## 五、摘要与签名

### `digest()` — 计算摘要

```cpp
QByteArray digest(const QByteArray &data, const QString &hashAlgo);
```

支持：MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512 / SHA3系列 / SM3

### `signData()` / `signVerify()` — 签名验签

```cpp
QByteArray signData(data, privateKey, hashAlgo, passphrase, userId);
bool signVerify(data, signature, publicKey, hashAlgo, userId);
```

SM2 签名需传入 `userId`（默认 `"1234567812345678"`）。

---

## 六、非对称加解密

```cpp
static QByteArray asymmetricEncrypt(data, publicKey);
static QByteArray asymmetricDecrypt(data, privateKey);
```

支持 RSA / EC / SM2。

---

## 七、AES 对称加解密

### `aesEncrypt()` / `aesDecrypt()`

```cpp
static QByteArray aesEncrypt(plaintext, key, mode, iv);
static QByteArray aesDecrypt(ciphertext, key, mode);
```

**密钥长度**：16/24/32 字节 = AES-128/192/256
**密文格式**：
- GCM：`IV(12B) + 密文 + Tag(16B)`
- 其他：`IV(16B) + 密文`

> ✅ AES 解密无需传入 IV，自动从密文前缀解析。

### 辅助方法

| 方法 | 说明 |
|------|------|
| `aes128GenerateCMAC(data, key)` | 计算 CMAC 消息认证码 |
| `aesGenerateKey(keySize=32)` | 生成随机密钥 |
| `aesGenerateIV(mode)` | 生成随机 IV |

---

## 八、SM4 对称加解密

```cpp
QByteArray sm4Encrypt(plaintext, key, mode, iv);
QByteArray sm4Decrypt(ciphertext, key, mode, iv);
```

密钥固定 16 字节（128-bit）。

> ⚠️ SM4 解密必须手动传入 IV，与 AES 不同。

---

## 九、SM2 辅助方法

| 方法 | 说明 |
|------|------|
| `sm2PubKeyToDer(rawPubKey)` | 裸公钥（65字节）转 DER |
| `sm2SignToDer(rawSign)` | 裸签名（64字节）转 DER |

---

## 十、枚举与名称转换

### 算法名称列表（用于 UI）

```cpp
static QStringList supportKeyAlgorithmNames();   // RSA/EC/SM2
static QStringList supportDigestNames();          // MD5/SHA1/.../SM3
static QStringList supportECCurveNames();         // prime256v1/secp384r1...
static QStringList supportRSABitsNames();         // 512-bit/2048-bit...
static QStringList supportSymModesNames();        // ECB/CBC/GCM/CTR
```

### 名称转数值

```cpp
static int keyAlgorithmFromName(name);   // EVP_PKEY_* 常量
static int ecCurveFromName(name);         // NID_* 常量
static int rsaBitsFromName(name);         // 位数整数
static SymMode symModeFromName(name);     // SymMode 枚举
```

---

## 十一、错误处理

```cpp
QString lastErrors() const;   // 获取错误信息（含 OpenSSL 原始错误）
void clearErrors();           // 清空错误队列
```

---

## 十二、使用示例

### RSA 密钥对 + 签名验签

```cpp
OpenSSLHelper helper;
auto kp = helper.genKeyPair("RSA", "2048-bit");
QByteArray sig = helper.signData("data", kp.second, "sha256");
bool ok = helper.signVerify("data", sig, kp.first, "sha256");
```

### AES-256-GCM 加解密

```cpp
QByteArray key = OpenSSLHelper::aesGenerateKey(32);
QByteArray iv  = OpenSSLHelper::aesGenerateIV(OpenSSLHelper::SYM_GCM);
QByteArray cipher = OpenSSLHelper::aesEncrypt("plaintext", key, OpenSSLHelper::SYM_GCM, iv);
QByteArray plain  = OpenSSLHelper::aesDecrypt(cipher, key, OpenSSLHelper::SYM_GCM);
```

### SM2 签名

```cpp
auto kp = helper.genKeyPair("SM2");
QByteArray sig = helper.signData("data", kp.second, "sm3", "", "1234567812345678");
bool ok = helper.signVerify("data", sig, kp.first, "sm3", "1234567812345678");
```

### 三级 PKI 证书

```cpp
auto rootKP = helper.genKeyPair("RSA", "2048-bit");
auto rootCert = helper.genSelfCert(3650, "/C=CN/O=CetXiyuan/CN=Root CA",
    rootKP.second, {"basicConstraints=critical,CA:TRUE,pathlen:1"}, "sha256");

auto subKP = helper.genKeyPair("RSA", "2048-bit");
QString subCsr = helper.genCSR("/C=CN/O=CetXiyuan/CN=Sub CA", subKP.second, {});
auto subCert = helper.signCSR(1825, subCsr, rootCert, rootKP.second, {}, "sha256");

auto endKP = helper.genKeyPair("RSA", "2048-bit");
QString endCsr = helper.genCSR("/C=CN/O=CetXiyuan/CN=example.com", endKP.second,
    {"subjectAltName=DNS:example.com"});
auto endCert = helper.signCSR(365, endCsr, subCert, subKP.second, {}, "sha256");

QByteArray pfx = helper.toPfx(endCert, endKP.second, helper.genChain(subCert, rootCert), "password");
```

---

*本手册由 CetXiyuan（璟·汐源忆醉）编写维护。*
