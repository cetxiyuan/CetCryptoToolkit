
#include "opensslhelper.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#include <QRandomGenerator>
#include <QTemporaryFile>
#include <QProcess>
#include <QFile>
#include <QCoreApplication>
#include <QDir>

#include <QDebug>

// 错误处理宏
#define SSL_APPEND_ERROR(msg) { \
    char openssl_err[1024]; \
    ERR_error_string_n(ERR_get_error(), openssl_err, sizeof(openssl_err)); \
    appendError(QString("%1 (OpenSSL: %2)").arg(msg).arg(openssl_err)); \
}

#define SHELL_EXE "powershell"

//============== 初始化与清理 =================

OpenSSLHelper::OpenSSLHelper(QObject *parent)
    : QObject(parent)
{
    initOpenSSL();
}

OpenSSLHelper::~OpenSSLHelper()
{
    cleanupOpenSSL();
}

void OpenSSLHelper::initOpenSSL()
{
    static bool initialized = false;
    if (!initialized) {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
        initialized = true;
    }
}

void OpenSSLHelper::cleanupOpenSSL()
{
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}


//============== 密钥生成 =================

QPair<QSslKey, QSslKey> OpenSSLHelper::generateRSAKeyPair(int bits)
{
    clearErrors();

    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    QPair<QSslKey, QSslKey> keyPair;

#if (USE_OPENSSL_TOOL_HANDLER > 0)
    //opensslTest();
#endif

    if (bits < 512 || bits > 16384) {
        appendError(tr("Invalid RSA key size: %1 (must be 512-16384)").arg(bits));
        return keyPair;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        SSL_APPEND_ERROR("Failed to create EVP_PKEY_CTX");
        return keyPair;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        SSL_APPEND_ERROR("Failed to initialize key generation");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        SSL_APPEND_ERROR("Failed to set RSA key length");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        SSL_APPEND_ERROR("Failed to generate RSA key");
        goto cleanup;
    }

    keyPair = getSslKeyPair(pkey, QSsl::Rsa);
    if (keyPair.first.isNull() || keyPair.second.isNull())
        SSL_APPEND_ERROR("Failed to convert generated key pair to QSslKey");

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);

    return keyPair;
}

QPair<QSslKey, QSslKey> OpenSSLHelper::generateECCKeyPair(int nid)
{
    clearErrors();

    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    QPair<QSslKey, QSslKey> keyPair;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        SSL_APPEND_ERROR("Failed to create EVP_PKEY_CTX");
        return keyPair;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        SSL_APPEND_ERROR("Failed to initialize key generation");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        SSL_APPEND_ERROR("Failed to set ECC curve");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        SSL_APPEND_ERROR("Failed to generate ECC key");
        goto cleanup;
    }

    keyPair = getSslKeyPair(pkey, QSsl::Ec);
    if (keyPair.first.isNull() || keyPair.second.isNull())
        SSL_APPEND_ERROR("Failed to convert generated key pair to QSslKey");

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);

    return keyPair;
}


//============== 证书生成 =================

QSslCertificate OpenSSLHelper::createSelfSignedCA(const QSslKey &privateKey,
                                            const QString &subjectDN,
                                            int validityDays)
{
    // 提前声明所有变量（避免goto跳过初始化）
    QSslCertificate cert;
    EVP_PKEY *pkey = nullptr;
    X509 *x509 = nullptr;
    ASN1_INTEGER *serial = nullptr;
    X509_NAME *name = nullptr;
    unsigned char *der_buf = nullptr;
    BIO *bio = nullptr;
    QVariantMap extensions;
    BIO *certBio = nullptr;
    char *certDataPtr = nullptr;  // 用于BIO_get_mem_data
    long certDataLen = 0;         // 用于BIO_get_mem_data

    // 检查私钥有效性
    if (privateKey.isNull()) {
        appendError("Invalid private key");
        return cert;
    }

    // 转换QSslKey到EVP_PKEY
    bio = BIO_new_mem_buf(privateKey.toPem().constData(), privateKey.toPem().size());
    if (!bio) {
        SSL_APPEND_ERROR("Failed to create BIO for private key");
        goto cleanup;
    }
    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        SSL_APPEND_ERROR("Failed to convert QSslKey to EVP_PKEY");
        goto cleanup;
    }

    // 创建X509证书结构
    x509 = X509_new();
    if (!x509) {
        SSL_APPEND_ERROR("Failed to create X509 structure");
        goto cleanup;
    }
    // 设置证书版本（X509v3）
    if (!X509_set_version(x509, 2)) {
        SSL_APPEND_ERROR("Failed to set certificate version");
        goto cleanup;
    }

    // 生成20字节（160位）随机序列号
    serial = ASN1_INTEGER_new();
    if (!serial) {
        SSL_APPEND_ERROR("Failed to allocate serial number");
        goto cleanup;
    }
    unsigned char buf[20];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        SSL_APPEND_ERROR("Failed to generate random serial");
        goto cleanup;
    }
    buf[0] &= 0x7F; // 确保最高位为0（正数）
    if (!ASN1_STRING_set(serial, buf, sizeof(buf)) || 
        !X509_set_serialNumber(x509, serial)) 
    {
        SSL_APPEND_ERROR("Failed to set 160-bit serial number");
        goto cleanup;
    }

    // 设置有效期（自当前时间开始）
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) || 
        !X509_gmtime_adj(X509_get_notAfter(x509), validityDays * 86400)) 
    {
        SSL_APPEND_ERROR("Failed to set validity period");
        goto cleanup;
    }

    // 设置主题和颁发者（自签名）
    name = parseSubjectName(subjectDN);
    if (!name || !X509_set_subject_name(x509, name) || 
        !X509_set_issuer_name(x509, name)) 
    {
        SSL_APPEND_ERROR("Failed to set subject/issuer name");
        goto cleanup;
    }

    // 设置公钥
    if (!X509_set_pubkey(x509, pkey)) {
        SSL_APPEND_ERROR("Failed to set public key");
        goto cleanup;
    }

    // 添加CA扩展
    // 基本约束 (必须)
    extensions["basicConstraints"] = "critical,CA:TRUE";
    // 密钥用法 (必须)
    extensions["keyUsage"] = "critical,keyCertSign,cRLSign";
    // 主题密钥标识符
    extensions["subjectKeyIdentifier"] = "hash";
    // 颁发者密钥标识符 (自签名时指向自己)
    extensions["authorityKeyIdentifier"] = "keyid:always,issuer";
    extensions["nsComment"] = "Root_CA_CetXiyuan";
    if (!addExtensions(x509, extensions)) {
        SSL_APPEND_ERROR("Failed to add CA extensions");
        goto cleanup;
    }

    // 自签名（SHA-256）
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        SSL_APPEND_ERROR("Failed to sign certificate");
        goto cleanup;
    }

    // 转换为 PEM 格式
    certBio = BIO_new(BIO_s_mem());
    if (!certBio || !PEM_write_bio_X509(certBio, x509)) {
        SSL_APPEND_ERROR("Failed to export certificate");
        goto cleanup;
    }

    certDataLen = BIO_get_mem_data(certBio, &certDataPtr);
    if (certDataLen > 0 && certDataPtr) {
        cert = QSslCertificate(QByteArray(certDataPtr, certDataLen));
    } else {
        SSL_APPEND_ERROR("Failed to get certBio data from BIO");
    }

cleanup:
    // 统一释放资源
    if (serial) ASN1_INTEGER_free(serial);
    if (name) X509_NAME_free(name);
    if (der_buf) OPENSSL_free(der_buf);
    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (certBio) BIO_free(certBio);
    if (bio) BIO_free(bio);

    return cert;
}

// 主题名称解析 (参考openssl/apps/lib/dn.c)
X509_NAME *OpenSSLHelper::parseSubjectName(const QString &subjectDN)
{
    X509_NAME *name = X509_NAME_new();
    if (!name) {
        appendError("Failed to allocate X509_NAME");
        return nullptr;
    }

    const QMap<QString, int> oid_map = {
        {"C", NID_countryName},
        {"ST", NID_stateOrProvinceName},
        {"L", NID_localityName},
        {"O", NID_organizationName},
        {"OU", NID_organizationalUnitName},
        {"CN", NID_commonName},
        {"emailAddress", NID_pkcs9_emailAddress}
    };

    const QStringList rdns = subjectDN.split("/", Qt::SkipEmptyParts);
    for (const QString &rdn : rdns) {
        const int eq_pos = rdn.indexOf("=");
        if (eq_pos <= 0) continue;
        const QString type = rdn.left(eq_pos);
        const QString value = rdn.mid(eq_pos + 1);

        if (!oid_map.contains(type)) {
            appendError(QString("Unsupported DN attribute: %1").arg(type));
            continue;
        }

        if (!X509_NAME_add_entry_by_NID(name, oid_map[type], MBSTRING_UTF8,
                                      reinterpret_cast<const unsigned char*>(value.toUtf8().data()),
                                      value.toUtf8().length(), -1, 0)) {
            SSL_APPEND_ERROR(tr("Failed to add DN entry: %1=%2").arg(type).arg(value));
        }
    }
    return name;
}

//============== 证书签名请求 =================

/**
 * 返回 PEM 格式的 证书请求
 */
QByteArray OpenSSLHelper::makeCertificateRequest(const QSslKey &privateKey,
                                                const QString &subjectDN)
{
    clearErrors();

    // 声明所有需要清理的资源
    QByteArray csrData;
    X509_REQ *req = nullptr;
    X509_NAME *name = nullptr;
    BIO *bio = nullptr;
    EVP_PKEY *pkey = nullptr;
    BIO *csrBio = nullptr;
    char *data = nullptr;
    long len = 0;

    // 参数校验
    if (privateKey.isNull()) {
        appendError("Private key is null");
        goto cleanup;
    }

    // 创建 CSR 请求
    req = X509_REQ_new();
    if (!req) {
        SSL_APPEND_ERROR("Failed to create X509_REQ");
        goto cleanup;
    }

    // 设置版本 (X509v3)
    if (X509_REQ_set_version(req, 0L) != 1) { // V1 版本
        SSL_APPEND_ERROR("Failed to set CSR version");
        goto cleanup;
    }

    // 设置主题
    name = parseSubjectName(subjectDN);
    if (!name || !X509_REQ_set_subject_name(req, name)) {
        SSL_APPEND_ERROR("Failed to set subject name");
        goto cleanup;
    }

    // 设置公钥
    bio = BIO_new_mem_buf(privateKey.toPem().constData(), privateKey.toPem().length());
    if (!bio) {
        SSL_APPEND_ERROR("Failed to create BIO");
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        SSL_APPEND_ERROR("Failed to read private key");
        goto cleanup;
    }

    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        SSL_APPEND_ERROR("Failed to set public key");
        goto cleanup;
    }

    // 签名 CSR
    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
        SSL_APPEND_ERROR("Failed to sign CSR");
        goto cleanup;
    }

    // 转换为 PEM 格式
    csrBio = BIO_new(BIO_s_mem());
    if (!csrBio || !PEM_write_bio_X509_REQ(csrBio, req)) {
        SSL_APPEND_ERROR("Failed to export CSR BIO");
        goto cleanup;
    }

    len = BIO_get_mem_data(csrBio, &data);
    if (len > 0 && data) {
        csrData = QByteArray(data, len);
    } else {
        SSL_APPEND_ERROR("Failed to get CSR data from BIO");
    }

cleanup:
    // 统一释放资源（逆序初始化顺序）
    if (csrBio) BIO_free(csrBio);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio) BIO_free(bio);
    if (name) X509_NAME_free(name);
    if (req) X509_REQ_free(req);

    return csrData;
}

QSslCertificate OpenSSLHelper::signCertificateRequest(const QByteArray &csrData,
                                                const QSslCertificate &caCert,
                                                const QSslKey &caPrivateKey,
                                                int validDays)
{
    // 1. 提前声明所有变量（包括会在goto后使用的变量）
    QSslCertificate cert;
    BIO *csrBio = nullptr;
    X509_REQ *req = nullptr;
    EVP_PKEY *reqPubKey = nullptr;
    X509 *x509 = nullptr;
    ASN1_INTEGER *serial = nullptr;
    X509 *caX509 = nullptr;
    EVP_PKEY *caPKey = nullptr;
    BIO *caKeyBio = nullptr;
    BIO *certBio = nullptr;
    const unsigned char *caData = nullptr;
    unsigned char buf[16] = {0};
    char *certDataPtr = nullptr;  // 用于BIO_get_mem_data
    long certDataLen = 0;         // 用于BIO_get_mem_data
    QVariantMap extensions;

    // 2. 参数验证
    if (csrData.isEmpty()) {
        appendError("CSR data is empty");
        return cert;
    }
    if (caCert.isNull()) {
        appendError("CA certificate is invalid");
        return cert;
    }
    if (caPrivateKey.isNull()) {
        appendError("CA private key is invalid");
        return cert;
    }
    if (validDays <= 0) {
        appendError("Invalid validity period");
        return cert;
    }

    // 3. 加载并解析CSR
    csrBio = BIO_new_mem_buf(csrData.constData(), csrData.size());
    if (!csrBio) {
        SSL_APPEND_ERROR("Failed to create CSR BIO");
        goto cleanup;
    }

    req = PEM_read_bio_X509_REQ(csrBio, nullptr, nullptr, nullptr);
    if (!req) {
        SSL_APPEND_ERROR("Failed to parse CSR");
        goto cleanup;
    }

    // 4. 验证CSR签名
    reqPubKey = X509_REQ_get_pubkey(req);
    if (!reqPubKey) {
        SSL_APPEND_ERROR("Failed to extract CSR public key");
        goto cleanup;
    }

    if (X509_REQ_verify(req, reqPubKey) != 1) {
        SSL_APPEND_ERROR("CSR signature verification failed");
        goto cleanup;
    }

    // 5. 创建证书模板
    x509 = X509_new();
    if (!x509) {
        SSL_APPEND_ERROR("Failed to create X509 certificate");
        goto cleanup;
    }

    // 设置证书版本 (X509v3)
    X509_set_version(x509, 2);

    if (!reqPubKey || X509_set_pubkey(x509, reqPubKey) != 1) {
        SSL_APPEND_ERROR("Failed to set public key");
        goto cleanup;
    }

    // 复制CSR主题到证书
    if (X509_set_subject_name(x509, X509_REQ_get_subject_name(req)) != 1) {
        SSL_APPEND_ERROR("Failed to set subject name");
        goto cleanup;
    }

    // 6. 设置CA信息
    caData = reinterpret_cast<const unsigned char*>(caCert.toDer().constData());
    caX509 = d2i_X509(nullptr, &caData, caCert.toDer().size());
    if (!caX509) {
        SSL_APPEND_ERROR("Failed to parse CA certificate");
        goto cleanup;
    }

    if (X509_set_issuer_name(x509, X509_get_subject_name(caX509)) != 1) {
        SSL_APPEND_ERROR("Failed to set issuer name");
        goto cleanup;
    }

    // 设置有效期
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), validDays * 86400)) {
        SSL_APPEND_ERROR("Failed to set validity period");
        goto cleanup;
    }

    // 7. 生成序列号
    serial = ASN1_INTEGER_new();
    if (!serial) {
        SSL_APPEND_ERROR("Failed to allocate serial number");
        goto cleanup;
    }

    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        SSL_APPEND_ERROR("Failed to generate random serial");
        goto cleanup;
    }
    buf[0] &= 0x7F; // 确保是正数

    if (!ASN1_STRING_set(serial, buf, sizeof(buf)) || 
        !X509_set_serialNumber(x509, serial)) {
        SSL_APPEND_ERROR("Failed to set serial number");
        goto cleanup;
    }

    // 9. 添加扩展
    extensions["basicConstraints"] = "CA:FALSE";
    extensions["keyUsage"] = "digitalSignature,keyEncipherment";
    extensions["subjectKeyIdentifier"] = "hash";
    extensions["authorityKeyIdentifier"] = "keyid,issuer";
    extensions["extendedKeyUsage"] = "serverAuth,clientAuth";
    if (!addExtensions(x509, extensions)) {
        appendError("Failed to add extensions");
        goto cleanup;
    }

    // 10. 使用CA私钥签名
    caKeyBio = BIO_new_mem_buf(caPrivateKey.toPem().constData(), caPrivateKey.toPem().length());
    caPKey = PEM_read_bio_PrivateKey(caKeyBio, nullptr, nullptr, nullptr);
    if (!caPKey) {
        SSL_APPEND_ERROR("Failed to read CA private key");
        goto cleanup;
    }

    if (X509_sign(x509, caPKey, EVP_sha256()) <= 0) {
        SSL_APPEND_ERROR("Failed to sign certificate");
        goto cleanup;
    }

    // 11. 转换为QSslCertificate
    certBio = BIO_new(BIO_s_mem());
    if (!certBio || !PEM_write_bio_X509(certBio, x509)) {
        SSL_APPEND_ERROR("Failed to export certificate");
        goto cleanup;
    }

    certDataLen = BIO_get_mem_data(certBio, &certDataPtr);
    if (certDataLen > 0 && certDataPtr) {
        cert = QSslCertificate(QByteArray(certDataPtr, certDataLen));
    } else {
        SSL_APPEND_ERROR("Failed to get certBio data from BIO");
    }

cleanup:
    // 12. 资源释放（按创建顺序的逆序）
    if (reqPubKey) EVP_PKEY_free(reqPubKey);
    if (caPKey) EVP_PKEY_free(caPKey);
    if (serial) ASN1_INTEGER_free(serial);
    if (caX509) X509_free(caX509);
    if (x509) X509_free(x509);
    if (req) X509_REQ_free(req);
    if (csrBio) BIO_free(csrBio);
    if (caKeyBio) BIO_free(caKeyBio);
    if (certBio) BIO_free(certBio);

    return cert;
}

QByteArray OpenSSLHelper::toDerCSR(const QByteArray &pemCsr)
{
    BIO *bio = BIO_new_mem_buf(pemCsr.constData(), pemCsr.size());
    if (!bio) {
        qCritical() << "Failed to create BIO";
        return QByteArray();
    }

    // 1. 读取 PEM 格式的 CSR
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!req) {
        qCritical() << "Invalid PEM CSR";
        return QByteArray();
    }

    // 2. 转换为 DER 格式
    unsigned char *derData = nullptr;
    int derLen = i2d_X509_REQ(req, &derData);
    if (derLen <= 0) {
        qCritical() << "Failed to convert PEM to DER";
        X509_REQ_free(req);
        return QByteArray();
    }

    // 3. 复制到 QByteArray
    QByteArray derCsr(reinterpret_cast<char*>(derData), derLen);

    // 4. 清理内存
    OPENSSL_free(derData);
    X509_REQ_free(req);

    return derCsr;
}

bool OpenSSLHelper::addExtensions(X509 *cert, const QVariantMap &extensions)
{
    if (!cert || extensions.isEmpty())
        return false;

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    // 优先处理 subjectKeyIdentifier（AKI依赖它）
    if (extensions.contains("subjectKeyIdentifier")) {
        const QString &value = extensions["subjectKeyIdentifier"].toString();
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(
            NULL, &ctx, NID_subject_key_identifier, value.toLatin1().data()
        );
        if (!ext || X509_add_ext(cert, ext, -1) != 1) {
            appendError("Failed to add subjectKeyIdentifier");
            if (ext) X509_EXTENSION_free(ext);
            return false;
        }
        X509_EXTENSION_free(ext);
    }

    // 处理其他扩展
    for (auto it = extensions.begin(); it != extensions.end(); ++it) {
        const QString &key = it.key();
        if (key.compare("subjectKeyIdentifier", Qt::CaseInsensitive) == 0)
            continue; // 已处理

        const QVariant &value = it.value();
        X509_EXTENSION *ext = nullptr;
        bool isCritical = false;
        if (key.compare("basicConstraints", Qt::CaseInsensitive) == 0) {
            ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints,
                                    value.toString().toLatin1().data());
            isCritical = true;
        } else if (key.compare("keyUsage", Qt::CaseInsensitive) == 0) {
            ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                                    value.toString().toLatin1().data());
            isCritical = true;
        } else if (key.compare("authorityKeyIdentifier", Qt::CaseInsensitive) == 0) {
            ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier,
                                    "keyid:always");
        } else if (key.compare("extendedKeyUsage", Qt::CaseInsensitive) == 0) {
            ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage,
                                    value.toString().toLatin1().data());
            isCritical = true;
        } else if (key.compare("nsComment", Qt::CaseInsensitive) == 0) {
            ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_netscape_comment,
                                    value.toString().toLatin1().data());
        }
        if (ext) {
            if (isCritical && X509_EXTENSION_set_critical(ext, 1) != 1) {
                appendError(tr("Failed to set critical flag for %1").arg(key));
                X509_EXTENSION_free(ext);
                return false;
            }
            if (X509_add_ext(cert, ext, -1) != 1) {
                appendError(tr("Failed to add extension: %1").arg(key));
                X509_EXTENSION_free(ext);
                return false;
            }
            X509_EXTENSION_free(ext);
        }
    }

    return true;
}

//============== 签名与验证 =================

QByteArray OpenSSLHelper::signData(const QByteArray &data,
                                  const QSslKey &privateKey,
                                  const EVP_MD *md)
{
    clearErrors();
    
    if (data.isEmpty()) {
        appendError("Data to sign is empty");
        return QByteArray();
    }

    if (privateKey.isNull()) {
        appendError("Private key is null");
        return QByteArray();
    }

    if (!md) {
        md = EVP_sha256();
    }

    BIO *bio = BIO_new_mem_buf(privateKey.toPem().constData(), privateKey.toPem().length());
    if (!bio) {
        appendError("Failed to create BIO");
        return QByteArray();
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        appendError("Failed to read private key");
        return QByteArray();
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        appendError("Failed to create EVP_MD_CTX");
        EVP_PKEY_free(pkey);
        return QByteArray();
    }

    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) != 1) {
        appendError("Failed to initialize signing");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return QByteArray();
    }

    if (EVP_DigestSignUpdate(mdctx, data.constData(), data.size()) != 1) {
        appendError("Failed to update signing");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return QByteArray();
    }

    size_t siglen = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &siglen) != 1) {
        appendError("Failed to get signature length");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return QByteArray();
    }

    QByteArray signature(siglen, 0);
    if (EVP_DigestSignFinal(mdctx, (unsigned char*)signature.data(), &siglen) != 1) {
        appendError("Failed to finalize signing");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return QByteArray();
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool OpenSSLHelper::verifySignature(const QByteArray &data,
                                  const QByteArray &signature,
                                  const QSslKey &publicKey,
                                  const EVP_MD *md)
{
    clearErrors();
    
    if (data.isEmpty()) {
        appendError("Data to verify is empty");
        return false;
    }

    if (signature.isEmpty()) {
        appendError("Signature is empty");
        return false;
    }

    if (publicKey.isNull()) {
        appendError("Public key is null");
        return false;
    }

    if (!md) {
        md = EVP_sha256();
    }

    BIO *bio = BIO_new_mem_buf(publicKey.toPem().constData(), publicKey.toPem().length());
    if (!bio) {
        appendError("Failed to create BIO");
        return false;
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        appendError("Failed to read public key");
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        appendError("Failed to create EVP_MD_CTX");
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1) {
        appendError("Failed to initialize verification");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyUpdate(mdctx, data.constData(), data.size()) != 1) {
        appendError("Failed to update verification");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    int result = EVP_DigestVerifyFinal(mdctx, (const unsigned char*)signature.constData(), signature.size());

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    if (result != 1) {
        appendError("Signature verification failed");
        return false;
    }

    return true;
}

//============== 证书管理 =================

QList<QSslCertificate> OpenSSLHelper::loadCertificates(const QString &filePath)
{
    QList<QSslCertificate> certs;
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Failed to open certificate file:" << filePath;
        return certs;
    }

    QByteArray data = file.readAll();
    file.close();

    BIO *bio = BIO_new_mem_buf(data.constData(), data.size());
    if (!bio) {
        qWarning() << "Failed to create BIO for certificate data";
        return certs;
    }

    X509 *x509 = NULL;
    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        BIO *certBio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(certBio, x509);

        char *certData = NULL;
        long certLen = BIO_get_mem_data(certBio, &certData);
        QByteArray pemCert(certData, certLen);

        certs.append(QSslCertificate(pemCert));
        qDebug() << "Loaded certificate:" << certs.last().subjectInfo(QSslCertificate::CommonName);

        BIO_free(certBio);
        X509_free(x509);
    }

    BIO_free(bio);

    if (certs.isEmpty()) {
        qWarning() << "No valid certificates found in file:" << filePath;
    } else {
        qDebug() << "Successfully loaded" << certs.size() << "certificates";
    }

    return certs;
}

bool OpenSSLHelper::saveCertificate(const QSslCertificate &cert, const QString &filePath)
{
    if (cert.isNull()) {
        qWarning() << "Invalid certificate provided for saving";
        return false;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Failed to open file for writing:" << filePath;
        return false;
    }

    QByteArray pem = cert.toPem();
    if (file.write(pem) != pem.size()) {
        qWarning() << "Failed to write certificate data to file:" << filePath;
        file.close();
        return false;
    }

    file.close();
    qDebug() << "Successfully saved certificate to:" << filePath;
    return true;
}

QList<QSslCertificate> OpenSSLHelper::loadPKCS12(const QByteArray &pkcs12Data,
                                               const QString &passphrase,
                                               QSslKey *privateKey)
{
    QList<QSslCertificate> certs;

    if (pkcs12Data.isEmpty()) {
        qWarning() << "PKCS12 data is empty!";
        return certs;
    }

    // 1. 创建 BIO 内存缓冲区
    BIO *bio = BIO_new_mem_buf(pkcs12Data.constData(), pkcs12Data.size());
    if (!bio) {
        qWarning() << "Failed to create BIO for PKCS12 data";
        return certs;
    }

    // 2. 解析 PKCS12 数据
    PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio); // 立即释放 BIO，避免内存泄漏
    if (!p12) {
        qWarning() << "Failed to parse PKCS12 data (invalid format or corrupted)";
        return certs;
    }

    // 3. 提取证书和私钥
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    if (PKCS12_parse(p12, passphrase.toLatin1().constData(), &pkey, &cert, &ca) != 1) {
        qWarning() << "Failed to parse PKCS12:"
                   << "Invalid passphrase or corrupted data";
        PKCS12_free(p12);
        return certs;
    }
    PKCS12_free(p12); // 解析成功后立即释放 PKCS12

    // 4. 转换主证书（Leaf Certificate）
    if (cert) {
        BIO *certBio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(certBio, cert);

        char *certData = NULL;
        long certLen = BIO_get_mem_data(certBio, &certData);
        QByteArray pemCert(certData, certLen);

        certs.append(QSslCertificate(pemCert));
        qDebug() << "Loaded main certificate:"
                << certs.last().subjectInfo(QSslCertificate::CommonName);

        BIO_free(certBio);
        X509_free(cert);
    } else {
        qWarning() << "No main certificate found in PKCS12!";
    }

    // 5. 转换 CA 证书链（Intermediate Certificates）
    if (ca) {
        const int caCount = sk_X509_num(ca);
        qDebug() << "Found" << caCount << "CA certificates in chain";
        
        for (int i = 0; i < caCount; i++) {
            X509 *caCert = sk_X509_value(ca, i);
            BIO *caBio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(caBio, caCert);

            char *caData = NULL;
            long caLen = BIO_get_mem_data(caBio, &caData);
            QByteArray pemCaCert(caData, caLen);

            certs.append(QSslCertificate(pemCaCert));
            qDebug() << "Loaded CA certificate:"
                    << certs.last().subjectInfo(QSslCertificate::CommonName);

            BIO_free(caBio);
        }
        sk_X509_free(ca);
    } else {
        qDebug() << "No CA certificates in PKCS12";
    }

    // 6. 转换私钥（Private Key）
    if (privateKey && pkey) {
        BIO *keyBio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(keyBio, pkey, NULL, NULL, 0, NULL, NULL);

        char *keyData = NULL;
        long keyLen = BIO_get_mem_data(keyBio, &keyData);
        QByteArray pemKey(keyData, keyLen);

        *privateKey = QSslKey(pemKey, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
        if (privateKey->isNull()) {
            qWarning() << "Failed to convert private key to QSslKey";
        } else {
            qDebug() << "Successfully loaded private key";
        }

        BIO_free(keyBio);
    } else if (privateKey && !pkey) {
        qWarning() << "Requested private key extraction, but none found in PKCS12!";
    }

    // 7. 清理资源
    if (pkey)
        EVP_PKEY_free(pkey);

    if (certs.isEmpty()) {
        qWarning() << "No valid certificates extracted from PKCS12!";
    } else {
        qDebug() << "Successfully loaded" << certs.size() << "certificates from PKCS12";
    }

    return certs;
}

QSslKey OpenSSLHelper::loadPublicKey(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Failed to open public key file:" << filePath;
        return QSslKey();
    }

    QByteArray pemData = file.readAll();
    file.close();

    QSslKey publicKey(pemData, QSsl::Rsa, QSsl::Pem, QSsl::PublicKey);
    if (publicKey.isNull())
        publicKey = QSslKey(pemData, QSsl::Ec, QSsl::Pem, QSsl::PublicKey);

    if (publicKey.isNull()) {
        qWarning() << "Failed to parse public key from file:" << filePath;
    } else {
        qDebug() << "Successfully loaded public key";
    }

    return publicKey;
}

bool OpenSSLHelper::savePublicKey(const QSslKey &publicKey, const QString &filePath)
{
    if (publicKey.isNull()) {
        qWarning() << "Invalid public key provided for saving";
        return false;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Failed to open file for writing:" << filePath;
        return false;
    }

    QByteArray pem = publicKey.toPem();
    if (file.write(pem) != pem.size()) {
        qWarning() << "Failed to write public key to file:" << filePath;
        file.close();
        return false;
    }

    file.close();
    qDebug() << "Successfully saved public key to:" << filePath;
    return true;
}

QSslKey OpenSSLHelper::loadPrivateKey(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Failed to open private key file:" << filePath;
        return QSslKey();
    }

    QByteArray pemData = file.readAll();
    file.close();

    QSslKey privateKey(pemData, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    if (privateKey.isNull())
        privateKey = QSslKey(pemData, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);

    if (privateKey.isNull()) {
        qWarning() << "Failed to parse private key from file:" << filePath;
    } else {
        qDebug() << "Successfully loaded private key";
    }

    return privateKey;
}

bool OpenSSLHelper::savePrivateKey(const QSslKey &privateKey, const QString &filePath)
{
    if (privateKey.isNull()) {
        qWarning() << "Invalid private key provided for saving";
        return false;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Failed to open file for writing:" << filePath;
        return false;
    }

    QByteArray pem = privateKey.toPem();
    if (file.write(pem) != pem.size()) {
        qWarning() << "Failed to write private key to file:" << filePath;
        file.close();
        return false;
    }

    file.close();
    qDebug() << "Successfully saved private key to:" << filePath;
    return true;
}


//============== 工具函数 =================

QString OpenSSLHelper::lastErrors() const
{
    return m_errors.last();
}

void OpenSSLHelper::clearErrors()
{
    m_errors.clear();
}

void OpenSSLHelper::appendError(const QString &error)
{
    m_errors.append(error);
}

QPair<QSslKey, QSslKey> OpenSSLHelper::getSslKeyPair(EVP_PKEY *pkey, QSsl::KeyAlgorithm algo)
{
    BIO *pubBio = nullptr;
    BIO *privBio = nullptr;
    char *pubData = nullptr;
    char *privData = nullptr;
    long pubLen = 0;
    long privLen = 0;
    QPair<QSslKey, QSslKey> keyPair;

    // 处理公钥
    pubBio = BIO_new(BIO_s_mem());
    if (!pubBio) {
        appendError("Failed to create BIO for public key");
        goto cleanup_exit;
    }

    if (PEM_write_bio_PUBKEY(pubBio, pkey) <= 0) {
        appendError("Failed to write public key");
        goto cleanup_exit;
    }

    pubLen = BIO_get_mem_data(pubBio, &pubData);
    keyPair.first = QSslKey(QByteArray(pubData, pubLen), algo, QSsl::Pem, QSsl::PublicKey);
    if (keyPair.first.isNull()) {
        appendError("Failed to create QSslKey for public key");
        goto cleanup_exit;
    }

    // 处理私钥
    privBio = BIO_new(BIO_s_mem());
    if (!privBio) {
        appendError("Failed to create BIO for private key");
        goto cleanup_exit;
    }

    if (PEM_write_bio_PrivateKey(privBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0) {
        appendError("Failed to write private key");
        goto cleanup_exit;
    }

    privLen = BIO_get_mem_data(privBio, &privData);
    keyPair.second = QSslKey(QByteArray(privData, privLen), algo, QSsl::Pem, QSsl::PrivateKey);
    if (keyPair.second.isNull()) {
        appendError("Failed to create QSslKey for private key");
    }

cleanup_exit:
    if (pubBio) BIO_free(pubBio);
    if (privBio) BIO_free(privBio);

    return keyPair;
}

/**
 * 使用 openssl 工具操作的代码集
 */
bool OpenSSLHelper::opensslGenKeyPair(const QString &algorithm, // "RSA"/"EC"
                                    int keySize, // RSA:2048/3072/4096, EC:256/384/521
                                    const QString &privKeyPath,
                                    const QString &pubKeyPath,
                                    const QString &passphrase)
{
    // 参数校验
    if (algorithm.isEmpty() || privKeyPath.isEmpty() || pubKeyPath.isEmpty()) {
        qCritical() << "Invalid parameters";
        return false;
    }

    // 根据算法类型构建pkeyopt参数
    QString pkeyoptValue;
    if (algorithm.toUpper() == "RSA") {
        if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
            qWarning() << "Invalid RSA key size, defaulting to 2048";
            keySize = 2048;
        }
        pkeyoptValue = tr("rsa_keygen_bits:%1").arg(keySize);
    } else if (algorithm.toUpper() == "EC") {
        QString curve;
        switch (keySize) {
            case NID_X9_62_prime256v1: curve = "prime256v1"; break;
            case NID_secp256k1: curve = "secp256k1"; break;  // 或 prime256v1 (NIST P-256)
            case NID_secp384r1: curve = "secp384r1"; break;
            case NID_secp521r1: curve = "secp521r1"; break;
            default:
                qWarning() << "Invalid EC key size, defaulting to 256";
                curve = "secp256k1";
        }
        pkeyoptValue = tr("ec_paramgen_curve:%1").arg(curve);
    }
    else {
        qCritical() << "Unsupported algorithm:" << algorithm;
        return false;
    }

    // 私钥生成
    QStringList privKeyArgs = {"genpkey",
                "-algorithm", algorithm,
                "-pkeyopt", pkeyoptValue,
                "-out", tr("\"%1\"").arg(privKeyPath),
            };
    if (!passphrase.isEmpty())
        privKeyArgs << "-aes256" << "-pass" << "pass:" + passphrase;

    if (!opensslTool("openssl", privKeyArgs)) {
        qCritical() << "Failed to generate private key";
        return false;
    }

    if (!pubKeyPath.isEmpty()) {
        // 从私钥提取公钥
        QStringList pubKeyArgs = {"pkey", 
                                "-in", tr("\"%1\"").arg(privKeyPath),
                                "-pubout",
                                "-out", tr("\"%1\"").arg(pubKeyPath),
                              };
        if (!passphrase.isEmpty())
            pubKeyArgs << "-passin" << "pass:" + passphrase;
        if (!opensslTool("openssl", pubKeyArgs)) {
            qCritical() << "Failed to extract public key";
            return false;
        }
    }

    return true;
}

bool OpenSSLHelper::opensslGenCertCA(int validDays,
                                   const QString &subjectDN,
                                   const QString &keyPath,
                                   const QString &outPath,
                                   const QString &hashAlgo,
                                   const QString &passphrase)
{
    QStringList arguments = {
            "req",
            "-x509",
            "-new",
            "-key", tr("\"%1\"").arg(keyPath),
            hashAlgo,
            "-days", QString::number(validDays),
            "-out", tr("\"%1\"").arg(outPath),
            "-subj", tr("\"%1\"").arg(subjectDN),
            "-config", "NUL",
            "-addext", "\"subjectKeyIdentifier=hash\"",
            "-addext", "\"authorityKeyIdentifier=keyid:always,issuer\"",
            "-addext", "\"basicConstraints=critical,CA:TRUE,pathlen:1\"",
            "-addext", "\"keyUsage=critical,keyCertSign,cRLSign\""
        };
    if (!passphrase.isEmpty())
        arguments << "-passin" << "pass:" + passphrase;

    return opensslTool("openssl", arguments);
}

bool OpenSSLHelper::opensslGenCSR(const QString &subjectDN, 
                        const QString &keyPath, 
                        const QString &outPath,
                        const QStringList &addexts,
                        const QString &passphrase)
{
    QStringList arguments = {
           "req",
           "-new",
           "-key", tr("\"%1\"").arg(keyPath),
           "-out", tr("\"%1\"").arg(outPath),
           "-subj", tr("\"%1\"").arg(subjectDN),
           "-config", "NUL",
       };
    for (const QString &addext : addexts)
        arguments << "-addext" << tr("\"%1\"").arg(addext);
    if (!passphrase.isEmpty())
        arguments << "-passin" << "pass:" + passphrase;

    return opensslTool("openssl", arguments);
}

bool OpenSSLHelper::opensslSignCSR(int validDays,
                                 const QString &csrPath,
                                 const QString &caPath,
                                 const QString &caKeyPath,
                                 const QString &outPath,
                                 const QStringList &addexts,
                                 const QString &hashAlgo,
                                 const QString &passphrase)
{
    QTemporaryFile configFile("./temp_cet_config");
    if (!configFile.open())
        qCritical() << "Failed to create temp config file";

    for (const QString &addext : addexts)
        configFile.write(addext.toUtf8() + "\n");
    configFile.close();

    QStringList arguments = {
            "x509",
            "-req",
            "-in", tr("\"%1\"").arg(csrPath),
            "-CA", tr("\"%1\"").arg(caPath),
            "-CAkey", tr("\"%1\"").arg(caKeyPath),
            "-CAcreateserial",
            hashAlgo,
            "-days", QString::number(validDays),
            "-out", tr("\"%1\"").arg(outPath),
            "-extfile", tr("\"%1\"").arg(configFile.fileName()),
        };
    if (!passphrase.isEmpty())
        arguments << "-passin" << "pass:" + passphrase;

    return opensslTool("openssl", arguments);
}

// [证书链=一级根证书+二级根证书]
bool OpenSSLHelper::opensslGenChain(const QString &interCAPath, 
                        const QString &rootCAPath, 
                        const QString &outPath)
{
    // Get-Content -Path interCAPath, rootCAPath | Out-File -FilePath outPath -Encoding ASCII
    // 等价于 Linux: cat interCA.crt.pem rootCA.crt.pem > chain.pem
    QString command = tr("-Path \"%1\", \"%2\" | Out-File -FilePath \"%3\" -Encoding ASCII")
                        .arg(interCAPath, rootCAPath, outPath);
    return opensslTool("Get-Content", QStringList() << command);
}

bool OpenSSLHelper::opensslToP7b(const QString &chainPath, const QString &outPath)
{
    // openssl crl2pkcs7 -nocrl -certfile chain.pem -out chain.p7b
    return opensslTool("openssl", {
            "crl2pkcs7",
            "-nocrl",
            "-certfile", tr("\"%1\"").arg(chainPath),
            "-out", tr("\"%1\"").arg(outPath),
        });
}

// [PFX文件=证书链+终端私钥+终端证书] [密码=pfxpassword]
bool OpenSSLHelper::opensslToPfx(const QString &pemPath, 
                        const QString &pemKeyPath,
                        const QString &chainPath, 
                        const QString &outPath, 
                        const QString &passphrase)
{
    QStringList arguments = {"pkcs12",
            "-export",
            "-in", tr("\"%1\"").arg(pemPath),
            "-inkey", tr("\"%1\"").arg(pemKeyPath),
            "-certfile", tr("\"%1\"").arg(chainPath),
            "-out", tr("\"%1\"").arg(outPath),
            "-passout", "pass:", passphrase,
            };

    if (!opensslTool("openssl", arguments)) {
        qCritical() << "Failed to generate opensslToPfx";
        return false;
    }

    return true;
}

bool OpenSSLHelper::opensslToDer(const QString &pemPath, const QString &outPath)
{
    QStringList arguments;
    QFile file(pemPath);
    if (!file.open(QIODevice::ReadOnly)) {
        qCritical() << "Cannot open PEM file:" << pemPath;
        return false;
    }

    QByteArray data = file.read(64); // 读取前64字节判断类型
    file.close();

    // 证书类型(X509)
    if (data.contains("BEGIN CERTIFICATE")) {
        arguments << "x509" << "-in" << tr("\"%1\"").arg(pemPath) 
                  << "-outform" << "der" << "-out" << tr("\"%1\"").arg(outPath);
    } else if (data.contains("BEGIN RSA PRIVATE KEY") || data.contains("BEGIN PRIVATE KEY")) {
        arguments << "rsa" << "-in" << tr("\"%1\"").arg(pemPath) 
                  << "-outform" << "der" << "-out" << tr("\"%1\"").arg(outPath);
    } else if (data.contains("BEGIN PUBLIC KEY")) {
        arguments << "rsa" << "-pubin" << "-in" << tr("\"%1\"").arg(pemPath) 
                  << "-outform" << "der" << "-out" << tr("\"%1\"").arg(outPath);
    } else if (data.contains("BEGIN EC PRIVATE KEY")) {
        arguments << "ec" << "-in" << tr("\"%1\"").arg(pemPath) 
                  << "-outform" << "der" << "-out" << tr("\"%1\"").arg(outPath);
    } else if (data.contains("BEGIN EC PUBLIC KEY")) {
        arguments << "ec" << "-pubin" << "-in" << tr("\"%1\"").arg(pemPath) 
                  << "-outform" << "der" << "-out" << tr("\"%1\"").arg(outPath);
    } else {
        qCritical() << "Unsupported PEM format:" << pemPath;
        return false;
    }

    return opensslTool("openssl", arguments);
}

bool OpenSSLHelper::opensslTool(const QString &program, const QStringList &arguments)
{
    QProcess process;
    process.setWorkingDirectory(QCoreApplication::applicationDirPath());

    qDebug() << "Executing:" << qPrintable(program) << qPrintable(arguments.join(" "));

    QStringList args = { "-NoProfile", "-Command", program, arguments.join(" ") };
    process.start(SHELL_EXE, args);
    if (!process.waitForFinished(30000)) { // 30秒超时
        qCritical() << "Process timeout:" << program << arguments;
        process.kill();
        return false;
    }

    if (process.exitCode() != 0) {
        qCritical() << "Process failed:" 
                    << process.readAllStandardError()
                    << "\nExit code:" << process.exitCode();
        return false;
    }

    return true;
}

bool OpenSSLHelper::opensslTest(void)
{
    // CA一级根证书
    /**
     * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
          -aes256 -pass pass:rootcapass -out certs/rootCA.key.pem
     */
    opensslTool("openssl", {
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:4096",
            "-aes256",
            "-pass", "pass:rootcapass",
            "-out", "certs/rootCA.key.pem",
        });

    /**
     * openssl req -x509 -new -key certs/rootCA.key.pem -passin pass:rootcapass \
          -sha256 -days 3650 -out certs/rootCA.crt.pem \
          -subj "/C=CN/ST=Fujian/O=cetxiyuan.com/CN=Root CA By CetXiyuan" \
          -config NUL \
          -addext "subjectKeyIdentifier=hash" \
          -addext "authorityKeyIdentifier=keyid:always,issuer" \
          -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
          -addext "keyUsage=critical,keyCertSign,cRLSign"
     */
    opensslTool("openssl", {
        "req",
        "-x509",
        "-new",
        "-key", "certs/rootCA.key.pem",
        "-passin", "pass:rootcapass",
        "-sha256",
        "-days", "3650",
        "-out", "certs/rootCA.crt.pem",
        "-subj", "\"/C=CN/ST=Fujian/O=cetxiyuan.com/CN=Root CA By CetXiyuan\"",
        "-config", "NUL",
        "-addext", "\"subjectKeyIdentifier=hash\"",
        "-addext", "\"authorityKeyIdentifier=keyid:always,issuer\"",
        "-addext", "\"basicConstraints=critical,CA:TRUE,pathlen:1\"",
        "-addext", "\"keyUsage=critical,keyCertSign,cRLSign\""
    });

    // CA二级根证书
    /**
     * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
          -aes256 -pass pass:intercapass -out certs/interCA.key.pem
     */
    opensslTool("openssl", {
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:3072",
            "-aes256",
            "-pass", "pass:intercapass",
            "-out", "certs/interCA.key.pem",
        });

    /**
     * openssl req -new -key certs/interCA.key.pem -passin pass:intercapass \
            -out certs/interCA.csr.pem \
            -subj "/C=CN/ST=Fujian/O=cetxiyuan.com/CN=Intermediate CA By CetXiyuan" \
            -config NUL \
            -addext "subjectKeyIdentifier=hash" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" 
     */
    opensslTool("openssl", {
            "req",
            "-new",
            "-key", "certs/interCA.key.pem",
            "-passin", "pass:intercapass",
            "-out", "certs/interCA.csr.pem",
            "-subj", "\"/C=CN/ST=Fujian/O=cetxiyuan.com/CN=Intermediate CA By CetXiyuan\"",
            "-config", "NUL",
            "-addext", "\"subjectKeyIdentifier=hash\"",
            "-addext", "\"basicConstraints=critical,CA:TRUE,pathlen:0\"",
            "-addext", "\"keyUsage=critical,keyCertSign,cRLSign\""
        });

    QTemporaryFile configFile("./temp_config");
    if (!configFile.open()) {
        qCritical() << "Failed to create temp config file";
    }

    QString configContent = 
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always,issuer\n"
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n";
    configFile.write(configContent.toUtf8());
    configFile.close();

    /**
     * openssl x509 -req -in certs/interCA.csr.pem -CA certs/rootCA.crt.pem \
            -CAkey certs/rootCA.key.pem -passin pass:rootcapass -CAcreateserial \
            -out certs/interCA.crt.pem -days 1825 -sha256 \
            -extfile F:/sharefolder/cetqtlearn/CetCryptoToolkit/CetCryptoToolkit/temp_config.QfOfqi
     */
    opensslTool("openssl", {
            "x509",
            "-req",
            "-in", "certs/interCA.csr.pem",
            "-CA", "certs/rootCA.crt.pem",
            "-CAkey", "certs/rootCA.key.pem",
            "-passin", "pass:rootcapass",
            "-CAcreateserial",
            "-out", "certs/interCA.crt.pem",
            "-days", "1825",
            "-sha256",
            "-extfile", configFile.fileName(),
        });

    // 终端证书
    /**
     * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out certs/terminal.key.pem
     */
    opensslTool("openssl", {
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048",
            "-out", "certs/terminal.key.pem",
        });

    /**
     * openssl req -new -key certs/terminal.key.pem \
            -out certs/terminal.csr.pem \
            -subj "/C=CN/ST=Fujian/O=CetTerminal/CN=cetterminal.example.com" \
            -config NUL \
            -addext "subjectKeyIdentifier=hash" \
            -addext "basicConstraints=CA:FALSE" \
            -addext "keyUsage=digitalSignature,keyEncipherment" \
            -addext "extendedKeyUsage=clientAuth,serverAuth" \
            -addext "subjectAltName=DNS:cetterminal.example.com,DNS:www.cetterminal.example.com,IP:172.16.90.86,IP:127.0.0.1"
     */
    opensslTool("openssl", {
            "req",
            "-new",
            "-key", "certs/terminal.key.pem",
            "-out", "certs/terminal.csr.pem",
            "-subj", "\"/C=CN/ST=Fujian/O=CetTerminal/CN=cetterminal.example.com\"",
            "-config", "NUL",
            "-addext", "\"subjectKeyIdentifier=hash\"",
            "-addext", "\"basicConstraints=CA:FALSE\"",
            "-addext", "\"keyUsage=digitalSignature,keyEncipherment\"",
            "-addext", "\"extendedKeyUsage=clientAuth,serverAuth\"",
            "-addext", "\"subjectAltName=DNS:cetterminal.example.com,DNS:www.cetterminal.example.com,IP:172.16.90.86,IP:127.0.0.1\"",
        });
    
    QTemporaryFile configFile1("./temp_config");
    if (!configFile1.open()) {
        qCritical() << "Failed to create temp config file";
    }
    
    QString configContent1 = 
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth,serverAuth\n"
        "subjectAltName=DNS:cetterminal.example.com,DNS:www.cetterminal.example.com,IP:172.16.90.86,IP:127.0.0.1";
    configFile1.write(configContent1.toUtf8());
    configFile1.close();

    /**
     * openssl x509 -req -in certs/terminal.csr.pem -CA certs/interCA.crt.pem \
            -CAkey certs/interCA.key.pem -passin pass:intercapass -CAcreateserial \
            -out certs/terminal.crt.pem -days 365 -sha256 \
            -extfile F:/sharefolder/cetqtlearn/CetCryptoToolkit/CetCryptoToolkit/temp_config.hJFDKV
     */
    opensslTool("openssl", {
            "x509",
            "-req",
            "-in", "certs/terminal.csr.pem",
            "-CA", "certs/interCA.crt.pem",
            "-CAkey", "certs/interCA.key.pem",
            "-passin", "pass:intercapass",
            "-CAcreateserial",
            "-out", "certs/terminal.crt.pem",
            "-days", "365",
            "-sha256",
            "-extfile", configFile1.fileName(),
        });

    return true;
}


#if 0
//============== 使用示例 =================

#include "opensslhelper.h"
#include <QDebug>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    OpenSSLHelper helper;
    
    // 生成证书链
    if (!helper.generateCertificateChain("/path/to/certs", "rootPass123", "interPass123")) {
        qCritical() << "Failed to generate certificate chain";
        return 1;
    }
    // 转换格式示例
    QStringList pemFiles = {
        "/path/to/certs/rootCA.crt.pem",
        "/path/to/certs/intermediateCA.crt.pem",
        "/path/to/certs/client.crt.pem",
        "/path/to/certs/client.key.pem"
    };
    foreach (const QString &pemFile, pemFiles) {
        QString derFile = pemFile.left(pemFile.lastIndexOf('.')) + ".der";
        if (!helper.convertPemToDer(pemFile, derFile)) {
            qCritical() << "Failed to convert:" << pemFile;
        }
    }
    qDebug() << "All operations completed successfully";
    return 0;
}


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    OpenSSLHelper helper;

    // 生成 RSA 密钥对
    QSslKey rsaPrivateKey = helper.generateRSAKey(2048);
    if (rsaPrivateKey.isNull()) {
        qCritical() << "Failed to generate RSA key:" << helper.lastErrors();
        return -1;
    }

    // 生成 ECC 密钥对
    QSslEllipticCurve curve = helper.getCurveByName("prime256v1");
    QSslKey ecPrivateKey = helper.generateECKey(curve);
    if (ecPrivateKey.isNull()) {
        qCritical() << "Failed to generate EC key:" << helper.lastErrors();
        return -1;
    }

    // 生成自签名证书
    QVariantMap extensions;
    extensions["basicConstraints"] = "CA:TRUE";
    extensions["keyUsage"] = "keyCertSign,cRLSign";
    extensions["subjectAltName"] = QStringList() << "DNS:example.com" << "DNS:www.example.com";

    QSslCertificate selfSignedCert = helper.generateSelfSignedCert(
        rsaPrivateKey,
        "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=example.com",
        365,
        extensions
    );

    if (selfSignedCert.isNull()) {
        qCritical() << "Failed to generate self-signed certificate:" << helper.lastErrors();
        return -1;
    }

    // 保存证书
    if (!OpenSSLHelper::saveCertificate(selfSignedCert, "selfsigned.crt")) {
        qCritical() << "Failed to save certificate";
        return -1;
    }

    // 数据签名与验证
    QByteArray data = "Hello, OpenSSL!";
    QByteArray signature = helper.signData(data, rsaPrivateKey);
    if (signature.isEmpty()) {
        qCritical() << "Failed to sign data:" << helper.lastErrors();
        return -1;
    }

    bool verified = helper.verifySignature(data, signature, selfSignedCert.publicKey());
    qDebug() << "Signature verified:" << verified;

    // 生成 CSR
    QByteArray csr = helper.generateCSR(
        ecPrivateKey,
        "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/CN=example.com",
        {{"subjectAltName", QStringList() << "DNS:example.com"}}
    );

    if (csr.isEmpty()) {
        qCritical() << "Failed to generate CSR:" << helper.lastErrors();
        return -1;
    }

    qDebug() << "CSR generated:\n" << csr;

    return a.exec();
}

#endif

