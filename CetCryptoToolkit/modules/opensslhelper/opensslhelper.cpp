
#include "opensslhelper.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include <openssl/provider.h>

#include <openssl/core_names.h>  // 包含参数常量定义
#include <openssl/param_build.h> // OpenSSL 3.0 参数构建

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
    appendError(tr("%1 (OpenSSL: %2)").arg(msg).arg(openssl_err)); \
}

#define SHELL_EXE "powershell"

static QList<QPair<QString, int>> supportedKeyAlgorithms = {
    {"RSA",         EVP_PKEY_RSA},
    {"EC",          EVP_PKEY_EC},
    {"SM2",         EVP_PKEY_SM2},
};

static QList<QPair<QString, const EVP_MD *>> supportedDigests = {
    {"MD5",         EVP_md5()},
    {"SHA1",        EVP_sha1()},
    {"SHA224",      EVP_sha224()},
    {"SHA256",      EVP_sha256()},
    {"SHA384",      EVP_sha384()},
    {"SHA512",      EVP_sha512()},
    {"SHA3-224",    EVP_sha3_224()},
    {"SHA3-256",    EVP_sha3_256()},
    {"SHA3-384",    EVP_sha3_384()},
    {"SHA3-512",    EVP_sha3_512()},
    {"SM3",         EVP_sm3()},
};

static QList<QPair<QString, int>> supportedEcCurves = {
    {"prime256v1",      NID_X9_62_prime256v1},
    {"secp256k1",       NID_secp256k1},
    {"secp384r1",       NID_secp384r1},
    {"secp521r1",       NID_secp521r1},
};

static QList<QPair<QString, int>> supportedRsaBits = {
    {"512-bit",         512},
    {"1024-bit",        1024},
    {"2048-bit",        2048},
    {"3072-bit",        3072},
    {"4096-bit",        4096},
    {"8192-bit",        8192},
};

static QList<QPair<QString, OpenSSLHelper::SymMode>> supportedSymModes = {
    {"ECB",             OpenSSLHelper::SYM_ECB},
    {"CBC",             OpenSSLHelper::SYM_CBC},
    {"GCM",             OpenSSLHelper::SYM_GCM},
    {"CTR",             OpenSSLHelper::SYM_CTR},
};


OpenSSLHelper::OpenSSLHelper(QObject *parent) : QObject(parent)
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
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                          OPENSSL_INIT_ADD_ALL_CIPHERS |
                          OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
        OpenSSL_add_all_digests();
        // 检查 SM2（公钥算法）
        if (EVP_PKEY_is_a(NULL, "SM2"))
            qInfo() << "SM2 is in default provider";

        // 检查 SM3（摘要算法）
        if (EVP_MD_is_a(NULL, "SM3"))
            qInfo() << "SM3 is in default provider";

        // 检查 SM4（对称加密算法）
        if (EVP_CIPHER_is_a(NULL, "SM4"))
            qInfo() << "SM4 is in default provider";

        // 检查 CMAC（对称加密算法）
        if (EVP_CIPHER_is_a(NULL, "CMAC"))
            qInfo() << "CMAC is in default provider";

        initialized = true;
    }
}

void OpenSSLHelper::cleanupOpenSSL()
{
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

int OpenSSLHelper::callbackPassword(char *buf, int size, int rwflag, void *userdata)
{
    Q_UNUSED(rwflag);

    QByteArray *passBytes = static_cast<QByteArray *>(userdata);
    if (!passBytes || passBytes->isEmpty()) 
        return 0;

    int len = qMin(size, passBytes->length());
    memcpy(buf, passBytes->constData(), len);

    return len;
}

QPair<QSslKey, QSslKey> OpenSSLHelper::genKeyPair(const QString &algorithm,
                                                const QString &keySize,
                                                const QString &passphrase)
{
    // 所有变量定义在函数开头
    EVP_PKEY_CTX *ctx = nullptr;
    EVP_PKEY *pkey = nullptr;
    BIO *pubBio = nullptr;
    BIO *privBio = nullptr;
    char *pubData = nullptr;
    char *privData = nullptr;
    long pubLen = 0;
    long privLen = 0;
    QPair<QSslKey, QSslKey> keyPair;
    bool success = false;
    QSsl::KeyAlgorithm algoType = QSsl::Rsa;
    QByteArray pass = passphrase.toUtf8();
    const char *alg_name = nullptr;
    OSSL_PARAM params[3];
    int param_count = 0;
    char curve_name[32] = {0};
    int key_type = EVP_PKEY_NONE;

    key_type = keyAlgorithmFromName(algorithm);
    if (key_type == -1) {
        appendError("Failed to determine key type");
        return keyPair;
    }

    // 1. 确定算法类型和参数
    if (EVP_PKEY_RSA == key_type) {
        alg_name = "RSA";
        algoType = QSsl::Rsa;
        int bits = keySize.toInt();
        if (bits != 2048 && bits != 3072 && bits != 4096) bits = 2048;
        params[param_count++] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    }
    else if ((EVP_PKEY_EC == key_type) || (EVP_PKEY_SM2 == key_type)) {
        alg_name = "EC";
        algoType = QSsl::Ec;

        // 处理曲线名称
        if (EVP_PKEY_SM2 == key_type) {
            strncpy(curve_name, "SM2", sizeof(curve_name)-1);
        } else {
            strncpy(curve_name, keySize.toUtf8().constData(), sizeof(curve_name)-1);
        }

        params[param_count++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0);
    }
    else {
        qWarning("Unsupported algorithm: %s", qUtf8Printable(algorithm));
        goto cleanup;
    }
    params[param_count] = OSSL_PARAM_construct_end();

    // 2. 创建密钥生成上下文
    ctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name, nullptr);
    if (!ctx) {
        qWarning("Failed to create key generation context");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        qWarning("Failed to initialize key generation");
        goto cleanup;
    }

    // 3. 设置密钥参数
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        qWarning("Failed to set key parameters");
        goto cleanup;
    }

    // 4. 生成密钥对
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        qWarning("Failed to generate key pair");
        goto cleanup;
    }

    // 5. 验证SM2密钥（使用新API）
    if (EVP_PKEY_SM2 == key_type) {
        // OpenSSL 3.0+ 推荐方式
        if (!EVP_PKEY_get_group_name(pkey, curve_name, sizeof(curve_name), nullptr)) {
            qWarning("Failed to get curve name from generated key");
            goto cleanup;
        }

        if (strcmp(curve_name, "SM2") != 0) {
            qWarning("Generated key is not SM2 (curve: %s)", curve_name);
            goto cleanup;
        }
    }

    // 6. 创建BIO缓冲区
    pubBio = BIO_new(BIO_s_mem());
    privBio = BIO_new(BIO_s_mem());
    if (!pubBio || !privBio) {
        qWarning("Failed to create BIO buffers");
        goto cleanup;
    }

    // 7. 写入公钥（PEM格式）
    if (PEM_write_bio_PUBKEY(pubBio, pkey) <= 0) {
        qWarning("Failed to write public key");
        goto cleanup;
    }

    // 8. 写入私钥
    if (!pass.isEmpty()) {
        // 加密私钥（PKCS#8格式）
        if (!PEM_write_bio_PKCS8PrivateKey(
                privBio, 
                pkey,
                EVP_aes_256_cbc(),
                pass.constData(),
                pass.size(),
                nullptr,
                nullptr)) {
            qWarning("Failed to write encrypted private key");
            goto cleanup;
        }
    } else {
        // 未加密私钥
        if (!PEM_write_bio_PrivateKey(
                privBio,
                pkey,
                nullptr,
                nullptr,
                0,
                nullptr,
                nullptr)) {
            qWarning("Failed to write private key");
            goto cleanup;
        }
    }

    // 9. 获取BIO数据
    pubLen = BIO_get_mem_data(pubBio, &pubData);
    privLen = BIO_get_mem_data(privBio, &privData);
    if (pubLen <= 0 || privLen <= 0) {
        qWarning("Failed to get key data from BIO");
        goto cleanup;
    }

    // 10. 创建QSslKey对象
    keyPair.first = QSslKey(QByteArray(pubData, pubLen), algoType, QSsl::Pem, QSsl::PublicKey);
    keyPair.second = QSslKey(QByteArray(privData, privLen), algoType, QSsl::Pem, QSsl::PrivateKey, pass);
    
    if (keyPair.first.isNull() || keyPair.second.isNull()) {
        qWarning("Failed to create QSslKey objects");
        goto cleanup;
    }

    success = true;

cleanup:
    // 释放资源
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (pubBio) BIO_free(pubBio);
    if (privBio) BIO_free(privBio);

    if (!success) {
        keyPair = QPair<QSslKey, QSslKey>();
    }

    return keyPair;
}

QSslCertificate OpenSSLHelper::genSelfCert(int validDays,
                                        const QString &subjectDN,
                                        const QSslKey &privateKey,
                                        const QStringList &extensions,
                                        const QString &hashAlgo,
                                        const QString &passphrase)
{
    // 所有变量定义集中在此
    X509 *x509 = nullptr;
    EVP_PKEY *pkey = nullptr;
    BIO *bio = nullptr;
    BIGNUM *bn = nullptr;
    ASN1_INTEGER *serial = nullptr;
    X509_NAME *name = nullptr;
    BUF_MEM *mem = nullptr;
    EVP_MD *md = nullptr;
    EVP_MD_CTX *md_ctx = nullptr;
    QSslCertificate certificate;
    QByteArray pass = passphrase.toUtf8();
    QByteArray pemData = privateKey.toPem(pass);
    bool isEncrypted = pemData.contains("ENCRYPTED");
    const char *digest_name = nullptr;
    int ret = 0;
    int key_type = EVP_PKEY_NONE;

    // 1. 参数验证
    if (validDays <= 0 || subjectDN.isEmpty() || privateKey.isNull()) {
        appendError(tr("Invalid parameters: validDays=%1, subjectDN='%2', keyNull=%3")
                   .arg(validDays).arg(subjectDN).arg(privateKey.isNull()));
        goto cleanup;
    }

    // 2. 创建X509证书结构
    if (!(x509 = X509_new())) {
        appendError("X509_new() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 3. 设置证书版本 (v3)
    if (!X509_set_version(x509, 2)) {
        appendError("X509_set_version() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 4. 生成随机序列号
    if (!(bn = BN_new()) || !BN_rand(bn, 160, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        appendError("BN_rand() failed: " + getOpenSSLError());
        goto cleanup;
    }
    if (!(serial = ASN1_INTEGER_new()) || !BN_to_ASN1_INTEGER(bn, serial)) {
        appendError("BN_to_ASN1_INTEGER() failed: " + getOpenSSLError());
        goto cleanup;
    }
    if (!X509_set_serialNumber(x509, serial)) {
        appendError("X509_set_serialNumber() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 5. 设置有效期
    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), validDays * 86400L)) {
        appendError("X509_gmtime_adj() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 6. 设置主题和颁发者DN
    if (!(name = parseSubjectDN(subjectDN))) {
        appendError("parseSubjectDN() failed for '" + subjectDN + "'");
        goto cleanup;
    }
    if (!X509_set_subject_name(x509, name) || !X509_set_issuer_name(x509, name)) {
        appendError("X509_set_subject/issuer_name() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 7. 加载私钥
    if (!(bio = BIO_new_mem_buf(pemData.constData(), pemData.size()))) {
        appendError("BIO_new_mem_buf() failed: " + getOpenSSLError());
        goto cleanup;
    }
    
    pkey = isEncrypted ? 
        PEM_read_bio_PrivateKey(bio, nullptr, callbackPassword, pass.isEmpty() ? nullptr : &pass) :
        PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        appendError("PEM_read_bio_PrivateKey() failed: " + getOpenSSLError());
        goto cleanup;
    }

    key_type = keyAlgorithmFromName(EVP_PKEY_get0_type_name(pkey));
    if (key_type == -1) {
        appendError("Failed to determine key type");
        goto cleanup;
    }

    // 8. 设置公钥
    if ((ret = X509_set_pubkey(x509, pkey)) != 1) {
        appendError(tr("X509_set_pubkey() failed (ret=%1): ").arg(ret) + getOpenSSLError());
        goto cleanup;
    }

    // 9. 添加扩展
    if (!addExtensions(x509, x509, nullptr, extensions)) {
        appendError(tr("addExtensions(%1) failed").arg(extensions.join(" ")));
        goto cleanup;
    }

    // 10. 签名证书
    digest_name = qPrintable(hashAlgo.toLower());
    if (!(md = EVP_MD_fetch(nullptr, digest_name, nullptr))) {
        appendError("EVP_MD_fetch(" + hashAlgo + ") failed: " + getOpenSSLError());
        goto cleanup;
    }

    if (!(md_ctx = EVP_MD_CTX_new())) {
        appendError("EVP_MD_CTX_new() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // SM2特殊签名处理
    if (EVP_PKEY_SM2 == key_type) {
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char*)"SM3", 0),
            OSSL_PARAM_construct_end()
        };

        if (!EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, pkey) ||
            !EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(md_ctx), params)) {
            appendError(tr("SM2 signature init failed: ") + getOpenSSLError());
            goto cleanup;
        }
    } else {
        if (!EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, pkey)) {
            appendError("EVP_DigestSignInit() failed: " + getOpenSSLError());
            goto cleanup;
        }
    }

    if ((ret = X509_sign_ctx(x509, md_ctx)) <= 0) {
        appendError(tr("X509_sign_ctx() failed (ret=%1): ").arg(ret) + getOpenSSLError());
        goto cleanup;
    }

    // 11. 验证证书签名
    if ((ret = X509_verify(x509, pkey)) <= 0) {
        appendError(tr("Certificate verification failed (ret=%1): ").arg(ret) + getOpenSSLError());
        goto cleanup;
    }

    // 12. 导出为PEM格式
    BIO_free(bio);
    if (!(bio = BIO_new(BIO_s_mem())) || !PEM_write_bio_X509(bio, x509)) {
        appendError("PEM_write_bio_X509() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 13. 转换为QSslCertificate
    BIO_get_mem_ptr(bio, &mem);
    if (mem && mem->data && mem->length > 0) {
        certificate = QSslCertificate(QByteArray(mem->data, mem->length), QSsl::Pem);
        if (certificate.isNull()) {
            appendError("QSslCertificate creation failed");
        }
    } else {
        appendError("BIO_get_mem_ptr() failed");
    }

cleanup:
    // 资源清理（逆序）
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (md) EVP_MD_free(md);
    if (bio) BIO_free(bio);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    if (name) X509_NAME_free(name);
    if (serial) ASN1_INTEGER_free(serial);
    if (bn) BN_free(bn);

    return certificate;
}

QString OpenSSLHelper::genCSR(const QString &subjectDN,
                        const QSslKey &privateKey,
                        const QStringList &extensions,
                        const QString &passphrase)
{
    X509_REQ *req = nullptr;
    EVP_PKEY *pkey = nullptr;
    BIO *bio = nullptr;
    X509_NAME *name = nullptr;
    BUF_MEM *mem = nullptr;
    EVP_MD_CTX *md_ctx = nullptr;
    EVP_MD *md = nullptr;
    QByteArray csrPem;
    QByteArray pass = passphrase.toUtf8();
    QByteArray pemData = privateKey.toPem(pass);
    bool isEncrypted = pemData.contains("ENCRYPTED");
    int key_type = EVP_PKEY_NONE;
    int ret = 0;

    if (privateKey.isNull()) {
        appendError(tr("Invalid private key"));
        return QString();
    }

    // 1. 创建CSR请求
    if (!(req = X509_REQ_new())) {
        appendError("X509_REQ_new() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 2. 设置CSR版本
    if (!X509_REQ_set_version(req, 2)) {
        appendError("X509_REQ_set_version() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 3. 加载私钥并检测类型
    if (!(bio = BIO_new_mem_buf(pemData.constData(), pemData.size()))) {
        appendError("BIO_new_mem_buf() failed: " + getOpenSSLError());
        goto cleanup;
    }

    pkey = isEncrypted ? 
        PEM_read_bio_PrivateKey(bio, nullptr, callbackPassword, pass.isEmpty() ? nullptr : &pass) :
        PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);

    if (!pkey) {
        appendError("PEM_read_bio_PrivateKey() failed: " + getOpenSSLError());
        goto cleanup;
    }

    key_type = keyAlgorithmFromName(EVP_PKEY_get0_type_name(pkey));
    if (key_type == -1) {
        appendError("Failed to determine key type");
        goto cleanup;
    }

    md = EVP_MD_fetch(nullptr, (EVP_PKEY_SM2 == key_type)? "SM3" : "SHA256", nullptr);
    if (!md) {
        appendError("EVP_MD_fetch() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 5. 设置主题名称
    if (!(name = parseSubjectDN(subjectDN))) {
        appendError(tr("parseSubjectDN() failed for '%1'").arg(subjectDN));
        goto cleanup;
    }
    if (!X509_REQ_set_subject_name(req, name)) {
        appendError("X509_REQ_set_subject_name() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 6. 设置公钥
    if (!X509_REQ_set_pubkey(req, pkey)) {
        appendError("X509_REQ_set_pubkey() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 7. 添加扩展
    if (!extensions.isEmpty() && !addExtensions(nullptr, nullptr, req, extensions)) {
        appendError(tr("genCSR:addExtensions(%1) failed").arg(extensions.join(" ")));
        goto cleanup;
    }

    // 8. 签名CSR
    if (!(md_ctx = EVP_MD_CTX_new())) {
        appendError("EVP_MD_CTX_new() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // SM2特殊处理
    if (EVP_PKEY_SM2 == key_type) {
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char*)"SM3", 0),
            OSSL_PARAM_construct_end()
        };
        if (!EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, pkey) ||
            !EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(md_ctx), params)) {
            appendError("SM2 signature init failed: " + getOpenSSLError());
            goto cleanup;
        }
    } else {
        if (!EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, pkey)) {
            appendError("EVP_DigestSignInit() failed: " + getOpenSSLError());
            goto cleanup;
        }
    }

    if ((ret = X509_REQ_sign_ctx(req, md_ctx)) <= 0) {
        appendError(tr("X509_REQ_sign_ctx() failed (ret=%1): ").arg(ret) + getOpenSSLError());
        goto cleanup;
    }

    // 9. 导出为PEM格式
    BIO_free(bio);
    if (!(bio = BIO_new(BIO_s_mem())) || !PEM_write_bio_X509_REQ(bio, req)) {
        appendError("PEM_write_bio_X509_REQ() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 10. 获取PEM数据
    BIO_get_mem_ptr(bio, &mem);
    if (mem && mem->data && mem->length > 0) {
        csrPem = QByteArray(mem->data, mem->length);
    } else {
        appendError("BIO_get_mem_ptr() failed");
    }

    cleanup:
    // 资源清理
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (md) EVP_MD_free(md);
    if (name) X509_NAME_free(name);
    if (bio) BIO_free_all(bio);
    if (pkey) EVP_PKEY_free(pkey);
    if (req) X509_REQ_free(req);

    return csrPem;
}

QSslCertificate OpenSSLHelper::signCSR(int validDays, const QString &csrPem,
                                     const QSslCertificate &caCert, 
                                     const QSslKey &caKey,
                                     const QStringList &extensions,
                                     const QString &hashAlgo,
                                     const QString &passphrase)
{
    // 所有变量定义
    X509 *cert = nullptr;
    X509_REQ *req = nullptr;
    EVP_PKEY *ca_pkey = nullptr;
    EVP_PKEY *req_pubkey = nullptr;
    BIO *bio = nullptr;
    BIGNUM *bn = nullptr;
    ASN1_INTEGER *serial = nullptr;
    BUF_MEM *mem = nullptr;
    EVP_MD_CTX *md_ctx = nullptr;
    EVP_MD *md = nullptr;
    QSslCertificate signedCert;
    QByteArray pass = passphrase.toUtf8();
    QByteArray pemData = caKey.toPem(pass);
    bool isEncrypted = pemData.contains("ENCRYPTED");
    int key_type = EVP_PKEY_NONE;
    int ret = 0;
    X509_NAME *issuer = nullptr, *subject = nullptr;

    // 参数校验
    if (caCert.isNull()) {
        appendError("CA certificate is invalid");
        return QSslCertificate();
    }
    if (caKey.isNull()) {
        appendError("CA private key is invalid");
        return QSslCertificate();
    }
    if (csrPem.isEmpty()) {
        appendError("CSR is empty");
        return QSslCertificate();
    }

    // 1. 解析CSR
    if (!(bio = BIO_new(BIO_s_mem()))) {
        appendError("BIO_new() failed: " + getOpenSSLError());
        goto cleanup;
    }
    BIO_write(bio, csrPem.toUtf8().constData(), csrPem.toUtf8().size());
    if (!(req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr))) {
        appendError("PEM_read_bio_X509_REQ() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 2. 加载CA私钥并检测类型
    BIO_free(bio);
    if (!(bio = BIO_new_mem_buf(pemData.constData(), pemData.size()))) {
        appendError("BIO_new_mem_buf() failed: " + getOpenSSLError());
        goto cleanup;
    }

    ca_pkey = isEncrypted ? 
        PEM_read_bio_PrivateKey(bio, nullptr, callbackPassword, pass.isEmpty() ? nullptr : &pass) :
        PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    
    if (!ca_pkey) {
        appendError("PEM_read_bio_PrivateKey() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 3. 确定CA密钥类型
    key_type = keyAlgorithmFromName(EVP_PKEY_get0_type_name(ca_pkey));
    if (key_type == -1) {
        appendError("Failed to determine CA key type");
        goto cleanup;
    }

    // 4. 创建新证书
    if (!(cert = X509_new())) {
        appendError("X509_new() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 5. 设置证书版本
    if (!X509_set_version(cert, 2)) {
        appendError("X509_set_version() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 6. 生成序列号
    if (!(bn = BN_new()) || !BN_rand(bn, 160, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        appendError("BN_rand() failed: " + getOpenSSLError());
        goto cleanup;
    }
    if (!(serial = BN_to_ASN1_INTEGER(bn, nullptr)) || !X509_set_serialNumber(cert, serial)) {
        appendError("Failed to set serial number: " + getOpenSSLError());
        goto cleanup;
    }

    // 7. 设置有效期
    if (!X509_gmtime_adj(X509_get_notBefore(cert), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(cert), validDays * 86400)) {
        appendError("Failed to set validity period: " + getOpenSSLError());
        goto cleanup;
    }

    // 8. 设置颁发者和主题
    issuer = X509_get_subject_name(qcertToX509(caCert));
    subject = X509_REQ_get_subject_name(req);
    if (!issuer || !subject || 
        !X509_set_issuer_name(cert, issuer) || 
        !X509_set_subject_name(cert, subject)) {
        appendError("Failed to set names: " + getOpenSSLError());
        goto cleanup;
    }

    // 9. 设置公钥
    if (!(req_pubkey = X509_REQ_get_pubkey(req)) || !X509_set_pubkey(cert, req_pubkey)) {
        appendError("Failed to set public key: " + getOpenSSLError());
        goto cleanup;
    }

    // 10. 添加扩展
    if (!extensions.isEmpty() && !addExtensions(qcertToX509(caCert), cert, nullptr, extensions)) {
        appendError(tr("signCSR:addExtensions(%1) failed").arg(extensions.join(" ")));
        goto cleanup;
    }

    // 11. 签名证书
    if (!(md = EVP_MD_fetch(nullptr, hashAlgo.toUtf8().constData(), nullptr))) {
        appendError("EVP_MD_fetch() failed: " + getOpenSSLError());
        goto cleanup;
    }

    if (!(md_ctx = EVP_MD_CTX_new())) {
        appendError("EVP_MD_CTX_new() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // SM2特殊处理
    if (EVP_PKEY_SM2 == key_type) {
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char*)"SM3", 0),
            OSSL_PARAM_construct_end()
        };

        if (!EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, ca_pkey) ||
            !EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(md_ctx), params)) {
            appendError("SM2 signature init failed: " + getOpenSSLError());
            goto cleanup;
        }
    } else {
        if (!EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, ca_pkey)) {
            appendError("EVP_DigestSignInit() failed: " + getOpenSSLError());
            goto cleanup;
        }
    }

    if ((ret = X509_sign_ctx(cert, md_ctx)) <= 0) {
        appendError(tr("X509_sign_ctx() failed (ret=%1): ").arg(ret) + getOpenSSLError());
        goto cleanup;
    }

    // 12. 导出为PEM格式
    BIO_free(bio);
    if (!(bio = BIO_new(BIO_s_mem())) || !PEM_write_bio_X509(bio, cert)) {
        appendError("PEM_write_bio_X509() failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 13. 获取PEM数据
    BIO_get_mem_ptr(bio, &mem);
    if (mem && mem->data && mem->length > 0) {
        signedCert = QSslCertificate(QByteArray(mem->data, mem->length), QSsl::Pem);
    } else {
        appendError("BIO_get_mem_ptr() failed");
    }

cleanup:
    // 资源清理
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (md) EVP_MD_free(md);
    if (serial) ASN1_INTEGER_free(serial);
    if (bn) BN_free(bn);
    if (req_pubkey) EVP_PKEY_free(req_pubkey);
    if (bio) BIO_free_all(bio);
    if (cert) X509_free(cert);
    if (req) X509_REQ_free(req);
    if (ca_pkey) EVP_PKEY_free(ca_pkey);

    return signedCert;
}

QByteArray OpenSSLHelper::genChain(const QSslCertificate &subCACert, 
                              const QSslCertificate &rootCACert)
{
    QByteArray chain;
    if (!subCACert.isNull()) chain += subCACert.toPem();
    if (!rootCACert.isNull()) chain += rootCACert.toPem();
    return chain;
}

QByteArray OpenSSLHelper::toP7b(const QByteArray &chainPem)
{
    if (chainPem.isEmpty())
       return QByteArray();

    BIO *bio = BIO_new(BIO_s_mem());
    PKCS7 *p7 = PKCS7_new();
    STACK_OF(X509) *certs = sk_X509_new_null();
    QByteArray p7bData;

    BIO *chainBio = BIO_new_mem_buf(chainPem.constData(), chainPem.size());
    while (X509 *cert = PEM_read_bio_X509(chainBio, nullptr, nullptr, nullptr)) {
        sk_X509_push(certs, cert);
    }
    BIO_free(chainBio);

    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);
    for (int i = 0; i < sk_X509_num(certs); i++) {
        PKCS7_add_certificate(p7, sk_X509_value(certs, i));
    }

    i2d_PKCS7_bio(bio, p7);

    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len > 0) p7bData = QByteArray(data, len);

    PKCS7_free(p7);
    BIO_free(bio);
    sk_X509_pop_free(certs, X509_free);

    return p7bData;
}

QByteArray OpenSSLHelper::toPfx(const QSslCertificate &cert,
                              const QSslKey &privateKey,
                              const QByteArray &chainPem,
                              const QString &passphrase)
{
    // 所有变量定义放在函数开头
    PKCS12 *p12 = nullptr;
    BIO *bio = nullptr;
    BIO *chainBio = nullptr;
    EVP_PKEY *pkey = nullptr;
    STACK_OF(X509) *certs = nullptr;
    X509 *x509 = nullptr;
    X509 *caCert = nullptr;
    char *data = nullptr;
    long len = 0;
    QByteArray pfxData;

    // 初始化证书栈
    certs = sk_X509_new_null();
    if (!certs) {
        appendError("Failed to create certificate stack");
        goto cleanup;
    }

    // 添加主证书
    x509 = qcertToX509(cert);
    if (!x509) {
        appendError("Failed to convert QSslCertificate to X509");
        goto cleanup;
    }
    sk_X509_push(certs, x509);

    // 添加证书链
    chainBio = BIO_new_mem_buf(chainPem.constData(), chainPem.size());
    if (!chainBio) {
        appendError("Failed to create BIO for certificate chain");
        goto cleanup;
    }

    while ((caCert = PEM_read_bio_X509(chainBio, nullptr, nullptr, nullptr))) {
        sk_X509_push(certs, caCert);
    }

    // 转换私钥
    pkey = qsslkeyToEVP(privateKey);
    if (!pkey) {
        appendError("Failed to convert private key");
        goto cleanup;
    }

    // 创建PKCS12结构
    p12 = PKCS12_create(
        passphrase.toUtf8().constData(),                      // 密码
        cert.subjectInfo(QSslCertificate::CommonName).first().toUtf8().constData(), // 友好名称
        pkey,                                                 // 私钥
        x509,                                                 // 主证书
        certs,                                                // CA证书链
        0, 0, 0, 0, 0                                         // 其他参数（默认值）
    );

    if (!p12) {
        appendError("Failed to create PKCS12 structure");
        goto cleanup;
    }

    // 写入BIO
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        appendError("Failed to create BIO for PFX output");
        goto cleanup;
    }

    if (!i2d_PKCS12_bio(bio, p12)) {
        appendError("Failed to write PKCS12 data");
        goto cleanup;
    }

    // 获取PFX数据
    len = BIO_get_mem_data(bio, &data);
    if (len > 0) {
        pfxData = QByteArray(data, len);
    } else {
        appendError("Failed to get PFX data from BIO");
    }

cleanup:
    // 释放资源（按创建顺序的逆序）
    if (p12) PKCS12_free(p12);
    if (bio) BIO_free(bio);
    if (chainBio) BIO_free(chainBio);
    if (pkey) EVP_PKEY_free(pkey);
    if (certs) sk_X509_pop_free(certs, X509_free);

    return pfxData;
}

QByteArray OpenSSLHelper::toDer(const QByteArray &pemData)
{
    if (pemData.isEmpty())
        return QByteArray();

    BIO *bio = BIO_new_mem_buf(pemData.constData(), pemData.size());
    if (!bio) {
        SSL_APPEND_ERROR("Failed to create BIO");
        return QByteArray();
    }

    QByteArray derData;
    if (pemData.contains("BEGIN EC PRIVATE KEY") || pemData.contains("BEGIN RSA PRIVATE KEY") || 
        pemData.contains("BEGIN PRIVATE KEY")) {
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        if (pkey) {
            unsigned char *buf = nullptr;
            int len = i2d_PrivateKey(pkey, &buf);
            if (len > 0) derData = QByteArray(reinterpret_cast<char *>(buf), len);
            OPENSSL_free(buf);
            EVP_PKEY_free(pkey);
        }
    } else if (pemData.contains("BEGIN PUBLIC KEY")) {
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        if (pkey) {
            unsigned char *buf = nullptr;
            int len = i2d_PUBKEY(pkey, &buf);
            if (len > 0) derData = QByteArray(reinterpret_cast<char *>(buf), len);
            OPENSSL_free(buf);
            EVP_PKEY_free(pkey);
        }
    } else if (pemData.contains("BEGIN CERTIFICATE REQUEST")) {
        X509_REQ *req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
        if (req) {
            unsigned char *buf = nullptr;
            int len = i2d_X509_REQ(req, &buf);
            if (len > 0) derData = QByteArray(reinterpret_cast<char*>(buf), len);
            OPENSSL_free(buf);
            X509_REQ_free(req);
        }
    } else if (pemData.contains("BEGIN CERTIFICATE")) {
        X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (cert) {
            unsigned char *buf = nullptr;
            int len = i2d_X509(cert, &buf);
            if (len > 0) derData = QByteArray(reinterpret_cast<char*>(buf), len);
            OPENSSL_free(buf);
            X509_free(cert);
        }
    }

    BIO_free(bio);
    if (derData.isEmpty()) {
        appendError("PEM to DER conversion failed");
    }

    return derData;
}

QByteArray OpenSSLHelper::digest(const QByteArray &data, const QString &hashAlgo)
{
    if (data.isEmpty())
        return QByteArray();

    EVP_MD *md = EVP_MD_fetch(nullptr, hashAlgo.toUtf8().constData(), nullptr);
    if (!md) {
        qWarning() << "Unsupported hash algorithm:" << hashAlgo;
        return QByteArray();
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_MD_free(md);
        qWarning() << "EVP_MD_CTX_new failed";
        return QByteArray();
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, nullptr)) {
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);
        qWarning() << "EVP_DigestInit_ex failed:" << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    if (1 != EVP_DigestUpdate(mdctx, data.constData(), data.size())) {
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);
        qWarning() << "EVP_DigestUpdate failed:" << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLen)) {
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);
        qWarning() << "EVP_DigestFinal_ex failed:" << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);

    return QByteArray(reinterpret_cast<char*>(hash), hashLen);
}

QByteArray OpenSSLHelper::signDigest(const QByteArray &digest,
                                    const QSslKey &privateKey,
                                    const QString &hashAlgo,
                                    const QString &passphrase,
                                    const QByteArray &userId)
{
    const unsigned char SM2_DEFAULT_USERID[] = "1234567812345678"; // 16 bytes

    EVP_PKEY *pkey = nullptr;
    EVP_MD *md = nullptr;
    EVP_PKEY_CTX *pkey_ctx = nullptr;
    EVP_MD_CTX *md_ctx = nullptr;
    BIO *bio = nullptr;
    QByteArray signature;
    size_t siglen = 0;
    int key_type = EVP_PKEY_NONE;
    QByteArray pemData = privateKey.toPem(passphrase.toUtf8());

    clearErrors();

    // 1. Parameter validation
    if (digest.isEmpty()) {
        appendError("Digest data is empty");
        goto cleanup;
    }
    if (privateKey.isNull()) {
        appendError("Private key is invalid");
        goto cleanup;
    }

    // 2. Load private key
    bio = BIO_new_mem_buf(pemData.constData(), pemData.size());
    if (!bio) {
        appendError("Failed to create BIO for private key");
        goto cleanup;
    }
    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        appendError("Failed to parse private key: " + getOpenSSLError());
        goto cleanup;
    }

    key_type = keyAlgorithmFromName(EVP_PKEY_get0_type_name(pkey));
    if (key_type == -1) {
        appendError("Unsupported key type");
        goto cleanup;
    }

    // 3. Get digest algorithm
    md = EVP_MD_fetch(nullptr, hashAlgo.toUtf8().constData(), nullptr);
    if (!md) {
        appendError("Unsupported hash algorithm: " + hashAlgo);
        goto cleanup;
    }

    // 4. 创建签名上下文
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        appendError("EVP_MD_CTX_new failed: " + getOpenSSLError());
        goto cleanup;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!pkey_ctx) {
        appendError("EVP_PKEY_CTX_new failed: " + getOpenSSLError());
        goto cleanup;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);
    if (1 != EVP_PKEY_sign_init(pkey_ctx)) {
        appendError("EVP_PKEY_sign_init failed: " + getOpenSSLError());
        goto cleanup;
    }

    qDebug() << "key_type" << key_type << "hashAlgo" << hashAlgo;
    // 5. Initialize signing operation
    if (key_type == EVP_PKEY_SM2) {
        if (1 != EVP_PKEY_CTX_set1_id(pkey_ctx,
                                    userId.isEmpty() ? SM2_DEFAULT_USERID : 
                                    reinterpret_cast<const unsigned char*>(userId.constData()),
                                    userId.isEmpty() ? 16 : userId.size())) {
            appendError("SM2 init failed: " + getOpenSSLError());
            goto cleanup;
        }
    } else if (key_type == EVP_PKEY_RSA) {
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING)) {
            appendError("RSA init failed: " + getOpenSSLError());
            goto cleanup;
        }
    }

    if (1 != EVP_PKEY_CTX_set_signature_md(pkey_ctx, md)) {
        appendError("EVP_PKEY_CTX_set_signature_md failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 6. Get signature length
    if (1 != EVP_PKEY_sign(pkey_ctx, nullptr, &siglen, 
            (unsigned char *)digest.constData(), 
            digest.size())) {
        appendError("Failed to get signature length: " + getOpenSSLError());
        goto cleanup;
    }

    // 7. Allocate space and sign
    signature.resize(static_cast<int>(siglen));
    if (1 != EVP_PKEY_sign(pkey_ctx, 
                         reinterpret_cast<unsigned char *>(signature.data()), 
                         &siglen,
                         (unsigned char *)digest.constData(),
                         digest.size())) {
        appendError("Signing failed: " + getOpenSSLError());
        signature.clear();
    } else {
        signature.resize(static_cast<int>(siglen));
    }

cleanup:
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio) BIO_free(bio);
    if (md) EVP_MD_free(md);

    return signature;
}

QByteArray OpenSSLHelper::signData(const QByteArray &data, 
                                 const QSslKey &privateKey,
                                 const QString &hashAlgo,
                                 const QString &passphrase,
                                 const QByteArray &userId)
{
    const unsigned char SM2_DEFAULT_USERID[] = "1234567812345678"; // 16 bytes

    EVP_MD_CTX *md_ctx = nullptr;
    EVP_PKEY_CTX *pkey_ctx = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_MD *md = nullptr;
    BIO *bio = nullptr;
    QByteArray signature;
    size_t siglen = 0;
    int key_type = EVP_PKEY_NONE;
    QByteArray pemData = privateKey.toPem(passphrase.toUtf8());

    clearErrors();

    // 1. 参数检查
    if (data.isEmpty()) {
        appendError("Input data is empty");
        goto cleanup;
    }
    if (privateKey.isNull()) {
        appendError("Private key is invalid");
        goto cleanup;
    }

    // 2. 加载私钥
    bio = BIO_new_mem_buf(pemData.constData(), pemData.size());
    if (!bio) {
        appendError("Failed to create BIO for private key");
        goto cleanup;
    }
    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        appendError("Failed to parse private key: " + getOpenSSLError());
        goto cleanup;
    }

    key_type = keyAlgorithmFromName(EVP_PKEY_get0_type_name(pkey));
    if (key_type == -1) {
        appendError("Unsupported key type");
        goto cleanup;
    }

    // 3. 获取摘要算法
    md = EVP_MD_fetch(nullptr, hashAlgo.toUtf8().constData(), nullptr);
    if (!md) {
        appendError("Unsupported hash algorithm: " + hashAlgo);
        goto cleanup;
    }

    // 4. 创建签名上下文
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        appendError("EVP_MD_CTX_new failed: " + getOpenSSLError());
        goto cleanup;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!pkey_ctx) {
        appendError("EVP_PKEY_CTX_new failed: " + getOpenSSLError());
        goto cleanup;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);
    if (1 != EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, pkey)) {
        appendError("EVP_DigestSignInit failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 5. 初始化签名操作
    if (key_type == EVP_PKEY_SM2) {
        if (1 != EVP_PKEY_CTX_set1_id(pkey_ctx,
                                    userId.isEmpty() ? SM2_DEFAULT_USERID : 
                                    reinterpret_cast<const unsigned char*>(userId.constData()),
                                    userId.isEmpty() ? 16 : userId.size())) {
            appendError("SM2 init failed: " + getOpenSSLError());
            goto cleanup;
        }
    } else if (key_type == EVP_PKEY_RSA) {
        // RSA处理
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING)) {
            appendError("RSA init failed: " + getOpenSSLError());
            goto cleanup;
        }
    }

    // 6. 计算数据摘要并签名
    if (1 != EVP_DigestSign(md_ctx, nullptr, &siglen, 
                          reinterpret_cast<const unsigned char*>(data.constData()), 
                          data.size())) {
        appendError("Failed to get signature length: " + getOpenSSLError());
        goto cleanup;
    }

    signature.resize(static_cast<int>(siglen));
    if (1 != EVP_DigestSign(md_ctx, 
                          reinterpret_cast<unsigned char*>(signature.data()), 
                          &siglen,
                          reinterpret_cast<const unsigned char*>(data.constData()),
                          data.size())) {
        appendError("Signing failed: " + getOpenSSLError());
        signature.clear();
    } else {
        signature.resize(static_cast<int>(siglen));
    }

cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio) BIO_free(bio);
    if (md) EVP_MD_free(md);

    return signature;
}

bool OpenSSLHelper::signVerify(const QByteArray &data,
                             const QByteArray &signature,
                             const QSslKey &publicKey,
                             const QString &hashAlgo,
                             const QByteArray &userId)
{
    const unsigned char SM2_DEFAULT_USERID[] = "1234567812345678"; // 16 bytes

    EVP_PKEY *pkey = nullptr;
    const EVP_MD *md = nullptr;
    EVP_MD_CTX *md_ctx = nullptr;
    EVP_PKEY_CTX *pkey_ctx = nullptr;
    BIO *bio = nullptr;
    int key_type = EVP_PKEY_NONE;
    bool result = false;
    QByteArray pemData = publicKey.toPem();

    qDebug() << "pemData" << pemData;

    clearErrors();

    // 1. 参数检查
    if (data.isEmpty()) {
        appendError("Input data is empty");
        goto cleanup;
    }
    if (signature.isEmpty()) {
        appendError("Signature is empty");
        goto cleanup;
    }
    if (publicKey.isNull()) {
        appendError("Public key is invalid");
        goto cleanup;
    }

    // 2. 加载公钥
    bio = BIO_new_mem_buf(pemData.constData(), pemData.size());
    if (!bio) {
        appendError("Failed to create BIO for public key");
        goto cleanup;
    }
    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        appendError("Failed to parse public key: " + getOpenSSLError());
        goto cleanup;
    }

    qDebug() << "EVP_PKEY_get0_type_name(pkey)" << EVP_PKEY_get0_type_name(pkey) << "hashAlgo" << hashAlgo;
    key_type = keyAlgorithmFromName(EVP_PKEY_get0_type_name(pkey));
    if (key_type == -1) {
        appendError("Unsupported key type");
        goto cleanup;
    }

    // 3. 获取摘要算法
    md = EVP_MD_fetch(nullptr, hashAlgo.toUtf8().constData(), nullptr);
    if (!md) {
        appendError("Unsupported hash algorithm: " + hashAlgo);
        goto cleanup;
    }

    // 4. 创建验证上下文
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        appendError("EVP_MD_CTX_new failed: " + getOpenSSLError());
        goto cleanup;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!pkey_ctx) {
        appendError("EVP_PKEY_CTX_new failed: " + getOpenSSLError());
        goto cleanup;
    }

    // 5. 初始化验证操作
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);
    if (1 != EVP_DigestVerifyInit(md_ctx, nullptr, md, nullptr, pkey)) {
        appendError("EVP_DigestVerifyInit failed: " + getOpenSSLError());
        goto cleanup;
    }

    if (key_type == EVP_PKEY_SM2) {
        if (1 != EVP_PKEY_CTX_set1_id(pkey_ctx,
                                    userId.isEmpty() ? SM2_DEFAULT_USERID : 
                                    reinterpret_cast<const unsigned char*>(userId.constData()),
                                    userId.isEmpty() ? 16 : userId.size())) {
            appendError("SM2 verify init failed: " + getOpenSSLError());
            goto cleanup;
        }
    }
    else if (key_type == EVP_PKEY_RSA) {
        if (1 != EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING)) {
            appendError("RSA verify init failed: " + getOpenSSLError());
            goto cleanup;
        }
    }

    // 6. 执行验证
    result = (1 == EVP_DigestVerify(md_ctx,
                                  reinterpret_cast<const unsigned char *>(signature.constData()),
                                  signature.size(),
                                  reinterpret_cast<const unsigned char *>(data.constData()),
                                  data.size()));
    if (!result) {
        appendError("Signature verification failed: " + getOpenSSLError());
    }

cleanup:
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio) BIO_free(bio);
    if (md && key_type != EVP_PKEY_SM2) EVP_MD_free((EVP_MD*)md);
    return result;
}

QByteArray OpenSSLHelper::asymmetricEncrypt(const QByteArray &data, const QSslKey &publicKey) 
{
    EVP_PKEY *pkey = nullptr;
    BIO *bio = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    QByteArray encrypted;
    size_t outlen = 0;
    QByteArray pemData = publicKey.toPem();

    if (data.isEmpty())
        return QByteArray();

    if (publicKey.isNull()) {
        qCritical() << "Public key is invalid";
        return QByteArray();
    }

    // 从QSslKey加载公钥
    bio = BIO_new_mem_buf(pemData.constData(), pemData.size());
    if (!bio) {
        qCritical() << "Failed to create BIO";
        return encrypted;
    }

    // 区分RSA和EC密钥
    switch (publicKey.algorithm()) {
    case QSsl::Rsa:
    case QSsl::Ec:
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        break;
    default:
        qCritical() << "Unsupported key algorithm";
        BIO_free(bio);
        return encrypted;
    }

    if (!pkey) {
        qCritical() << "Failed to load public key:" << ERR_error_string(ERR_get_error(), nullptr);
        BIO_free(bio);
        return encrypted;
    }

    // 创建加密上下文
    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        qCritical() << "Failed to initialize encryption:" << ERR_error_string(ERR_get_error(), nullptr);
        goto cleanup;
    }

    // 设置密钥特定的参数
    switch (keyAlgorithmFromName(EVP_PKEY_get0_type_name(pkey))) {
    case EVP_PKEY_RSA:
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
                EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
            qCritical() << "Failed to set RSA OAEP params:" << ERR_error_string(ERR_get_error(), nullptr);
            goto cleanup;
        }
        break;
    case EVP_PKEY_EC:
    case EVP_PKEY_SM2:
        // ECIES加密通常自动处理参数
        break;
    default:
        qCritical() << "Unsupported key type";
        goto cleanup;
    }

    // 执行加密
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, 
           reinterpret_cast<const unsigned char*>(data.constData()),
           static_cast<size_t>(data.size())) <= 0) {
        qCritical() << "Failed to get output size:" << ERR_error_string(ERR_get_error(), nullptr);
        goto cleanup;
    }

    encrypted.resize(static_cast<int>(outlen));
    if (EVP_PKEY_encrypt(ctx, 
           reinterpret_cast<unsigned char *>(encrypted.data()), 
           &outlen,
           reinterpret_cast<const unsigned char *>(data.constData()),
           static_cast<size_t>(data.size())) <= 0) {
        qCritical() << "Encryption failed:" << ERR_error_string(ERR_get_error(), nullptr);
        encrypted.clear();
    } else {
        encrypted.resize(static_cast<int>(outlen));
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return encrypted;
}

QByteArray OpenSSLHelper::asymmetricDecrypt(const QByteArray &data, const QSslKey &privateKey) 
{
    EVP_PKEY *pkey = nullptr;
    BIO *bio = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    QByteArray decrypted;
    size_t outlen = 0;
    QByteArray pemData = privateKey.toPem();

    if (data.isEmpty())
         return QByteArray();

    if (privateKey.isNull()) {
        qCritical() << "Private key is invalid";
        return QByteArray();
    }

    // 加载私钥
    bio = BIO_new_mem_buf(pemData.constData(), pemData.size());
    if (!bio) {
        qCritical() << "Failed to create BIO";
        return decrypted;
    }

    // 区分RSA和EC密钥
    switch (privateKey.algorithm()) {
    case QSsl::Rsa:
    case QSsl::Ec:
        pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        break;
    default:
        qCritical() << "Unsupported key algorithm";
        BIO_free(bio);
        return decrypted;
    }

    if (!pkey) {
        qCritical() << "Failed to load private key:" << privateKey.algorithm()
                    << ERR_error_string(ERR_get_error(), nullptr);
        BIO_free(bio);
        return decrypted;
    }

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        qCritical() << "Failed to initialize decryption:" << ERR_error_string(ERR_get_error(), nullptr);
        goto cleanup;
    }

    // 设置密钥特定的参数
    switch (keyAlgorithmFromName(EVP_PKEY_get0_type_name(pkey))) {
    case EVP_PKEY_RSA:
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
            qCritical() << "Failed to set RSA OAEP params:" << ERR_error_string(ERR_get_error(), nullptr);
            goto cleanup;
        }
        break;
    case EVP_PKEY_EC:
    case EVP_PKEY_SM2:
        // ECIES解密通常自动处理参数
        break;
    default:
        qCritical() << "Unsupported key type";
        goto cleanup;
    }

    // 执行解密
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen,
                        reinterpret_cast<const unsigned char*>(data.constData()),
                        static_cast<size_t>(data.size())) <= 0) {
        qCritical() << "Failed to get output size:" << ERR_error_string(ERR_get_error(), nullptr);
        goto cleanup;
    }

    decrypted.resize(static_cast<int>(outlen));
    if (EVP_PKEY_decrypt(ctx,
                        reinterpret_cast<unsigned char*>(decrypted.data()),
                        &outlen,
                        reinterpret_cast<const unsigned char*>(data.constData()),
                        static_cast<size_t>(data.size())) <= 0) {
        qCritical() << "Decryption failed:" << ERR_error_string(ERR_get_error(), nullptr);
        decrypted.clear();
    } else {
        decrypted.resize(static_cast<int>(outlen));
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return decrypted;
}

// 加密实现
QByteArray OpenSSLHelper::aesEncrypt(const QByteArray &plaintext, 
                const QByteArray &key, SymMode mode, const QByteArray &iv)
{
    if (plaintext.isEmpty())
         return QByteArray();

    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        qCritical() << "Invalid key size (must be 16/24/32 bytes)";
        return QByteArray();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return QByteArray();
    }

    const EVP_CIPHER *cipher = aesCipher(mode, key);
    if (!cipher) {
        qCritical() << "Unsupported key size for selected mode";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // 处理IV（GCM推荐12字节，其他16字节）
    QByteArray actualIV = iv.isEmpty() ? aesGenerateIV(mode) : iv;
    qCritical() << "actualIV: " << actualIV.toHex();
    if (actualIV.isEmpty()) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // 初始化加密上下文
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr,
                          reinterpret_cast<const unsigned char*>(key.constData()),
                          reinterpret_cast<const unsigned char*>(actualIV.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // GCM模式需要额外处理Tag
    QByteArray tag;
    if (SYM_GCM == mode)
        tag.resize(16); // GCM标签通常16字节

    // 加密数据
    QByteArray ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int len = 0;
    if (EVP_EncryptUpdate(ctx,
                         reinterpret_cast<uint8_t *>(ciphertext.data()),
                         &len,
                         reinterpret_cast<const uint8_t *>(plaintext.constData()),
                         plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    int ciphertextLen = len;
    if (EVP_EncryptFinal_ex(ctx,
                           reinterpret_cast<uint8_t *>(ciphertext.data()) + len,
                           &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    ciphertextLen += len;

    // 获取GCM标签
    if (SYM_GCM == mode) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertextLen);

    // 返回数据格式：GCM=IV+密文+Tag，其他=IV+密文
    return (SYM_GCM == mode) ? (actualIV + ciphertext + tag) : (actualIV + ciphertext);
}

// 解密实现
QByteArray OpenSSLHelper::aesDecrypt(const QByteArray &ciphertext, 
                    const QByteArray &key, SymMode mode)
{
    if (ciphertext.isEmpty())
         return QByteArray();

    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        qCritical() << "Invalid key size (must be 16/24/32 bytes)";
        return QByteArray();
    }

    // 解析输入数据（GCM=IV+密文+Tag，其他=IV+密文）
    QByteArray iv, encryptedData, tag;
    switch (mode) {
        case SYM_GCM:
            if (ciphertext.size() < 12 + 16) { // IV(12) + Tag(16)
                qCritical() << "Invalid ciphertext format for GCM";
                return QByteArray();
            }
            iv = ciphertext.left(12);
            tag = ciphertext.right(16);
            encryptedData = ciphertext.mid(12, ciphertext.size() - 12 - 16);
            break;
        default:
            if (ciphertext.size() < 16) { // IV(16)
                qCritical() << "Invalid ciphertext format";
                return QByteArray();
            }
            iv = ciphertext.left(16);
            encryptedData = ciphertext.mid(16);
            break;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return QByteArray();
    }

    const EVP_CIPHER *cipher = aesCipher(mode, key);
    if (!cipher) {
        qCritical() << "Unsupported key size for selected mode";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // 初始化解密上下文
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr,
                          reinterpret_cast<const unsigned char*>(key.constData()),
                          reinterpret_cast<const unsigned char*>(iv.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // 设置GCM标签
    if (SYM_GCM == mode) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return QByteArray();
        }
    }

    // 解密数据
    QByteArray plaintext(encryptedData.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int len = 0;
    if (EVP_DecryptUpdate(ctx,
                         reinterpret_cast<unsigned char*>(plaintext.data()),
                         &len,
                         reinterpret_cast<const unsigned char*>(encryptedData.constData()),
                         encryptedData.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    int plaintextLen = len;
    int ret = EVP_DecryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(plaintext.data()) + len,
                                 &len);
    if (ret <= 0) { // GCM验证失败会返回0
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintextLen);
    return plaintext;
}

QByteArray OpenSSLHelper::sm4Encrypt(const QByteArray &plaintext,
                                            const QByteArray &key,
                                            SymMode mode,
                                            const QByteArray &iv)
{
    // 检查密钥长度（SM4 密钥必须为 16 字节）
    if (key.size() != 16) {
        qWarning() << "SM4 key must be 16 bytes!";
        return QByteArray();
    }

    // 初始化 OpenSSL 上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qWarning() << "Failed to create EVP context";
        return QByteArray();
    }

    // 选择 SM4 模式（CBC 或 ECB）
    const EVP_CIPHER *cipher = nullptr;
    switch (mode) {
    case SYM_CBC:
        cipher = EVP_sm4_cbc();  // SM4-CBC
        break;
    case SYM_ECB:
        cipher = EVP_sm4_ecb();  // SM4-ECB
        break;
    default:
        qWarning() << "Unsupported SM4 mode";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // 检查 IV（CBC 模式需要 16 字节 IV）
    if (mode == SYM_CBC && iv.size() != 16) {
        qWarning() << "SM4-CBC requires a 16-byte IV!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // 初始化加密操作
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr,
                          reinterpret_cast<const unsigned char*>(key.constData()),
                          iv.isEmpty() ? nullptr : reinterpret_cast<const unsigned char*>(iv.constData())) != 1) {
        qWarning() << "Failed to initialize SM4 encryption";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    // 输出缓冲区（可能需要填充）
    QByteArray ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx), '\0');
    int len = 0;

    // 执行加密
    if (EVP_EncryptUpdate(ctx,
                         reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
                         reinterpret_cast<const unsigned char*>(plaintext.constData()),
                         plaintext.size()) != 1) {
        qWarning() << "SM4 encryption failed";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx,
                           reinterpret_cast<unsigned char*>(ciphertext.data() + len), &finalLen) != 1) {
        qWarning() << "SM4 final block encryption failed";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    ciphertext.resize(len + finalLen);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

QByteArray OpenSSLHelper::sm4Decrypt(const QByteArray &ciphertext,
                                    const QByteArray &key,
                                    SymMode mode,
                                    const QByteArray &iv)
{
    // 检查密钥长度
    if (key.size() != 16) {
        qWarning() << "SM4 key must be 16 bytes!";
        return QByteArray();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qWarning() << "Failed to create EVP context";
        return QByteArray();
    }

    const EVP_CIPHER *cipher = nullptr;
    switch (mode) {
    case SYM_CBC:
        cipher = EVP_sm4_cbc();
        break;
    case SYM_ECB:
        cipher = EVP_sm4_ecb();
        break;
    default:
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if (mode == SYM_CBC && iv.size() != 16) {
        qWarning() << "SM4-CBC requires a 16-byte IV!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr,
                          reinterpret_cast<const unsigned char*>(key.constData()),
                          iv.isEmpty() ? nullptr : reinterpret_cast<const unsigned char*>(iv.constData())) != 1) {
        qWarning() << "Failed to initialize SM4 decryption";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    QByteArray plaintext(ciphertext.size(), '\0');
    int len = 0;

    if (EVP_DecryptUpdate(ctx,
                         reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                         reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                         ciphertext.size()) != 1) {
        qWarning() << "SM4 decryption failed";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx,
                           reinterpret_cast<unsigned char*>(plaintext.data() + len), &finalLen) != 1) {
        qWarning() << "SM4 final block decryption failed";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    plaintext.resize(len + finalLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

QByteArray OpenSSLHelper::aes128GenerateCMAC(const QByteArray &data, const QByteArray &key) {
    if (data.isEmpty()) {
        qCritical() << "Input data is empty";
        return QByteArray();
    }

    // 强制密钥为 16 字节（AES-128）
    if (key.size() != 16) {
        qCritical() << "Invalid key size (must be 16 bytes for AES-128-CMAC)";
        return QByteArray();
    }

    // 获取 CMAC 算法
    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    if (!mac) {
        qCritical() << "Failed to fetch CMAC:" << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    // 创建 CMAC 上下文
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        qCritical() << "Failed to create CMAC context";
        return QByteArray();
    }

    // 设置 CMAC 参数（AES-128-CBC）
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", const_cast<char *>("AES-128-CBC"), 0),
        OSSL_PARAM_construct_end()
    };

    // 初始化 CMAC
    if (!EVP_MAC_init(ctx, 
                     reinterpret_cast<const unsigned char*>(key.constData()), 
                     key.size(), 
                     params)) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        qCritical() << "CMAC init failed:" << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    // 更新数据
    if (!EVP_MAC_update(ctx, 
                       reinterpret_cast<const unsigned char*>(data.constData()), 
                       data.size())) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        qCritical() << "CMAC update failed";
        return QByteArray();
    }

    // 获取 CMAC 结果（固定 16 字节）
    QByteArray cmac(16, 0);
    size_t cmacLen;
    if (!EVP_MAC_final(ctx, 
                      reinterpret_cast<unsigned char*>(cmac.data()), 
                      &cmacLen, 
                      cmac.size())) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        qCritical() << "CMAC final failed:" << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    // 清理资源
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return cmac;
}

// 生成随机密钥
QByteArray OpenSSLHelper::aesGenerateKey(int keySize)
{
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        qCritical() << "Invalid key size (must be 16/24/32 bytes)";
        return QByteArray();
    }

    QByteArray key(keySize, 0);
    if (RAND_bytes(reinterpret_cast<uint8_t *>(key.data()), keySize) != 1) {
        return QByteArray();
    }
    return key;
}

// 生成随机IV
QByteArray OpenSSLHelper::aesGenerateIV(SymMode mode)
{
    int ivSize = (mode == SYM_GCM) ? 12 : 16; // GCM推荐12字节，其他16字节
    QByteArray iv(ivSize, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), ivSize) != 1) {
        return QByteArray();
    }
    return iv;
}

/**
 * 使用 openssl 工具操作的代码集
 */
bool OpenSSLHelper::opensslGenKeyPair(const QString &algorithm, // "RSA"/"EC"
                                    const QString &keySize, // RSA:2048/3072/4096, EC:256/384/521
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
        int bits = rsaBitsFromName(keySize);
        if (bits != 2048 && bits != 3072 && bits != 4096) {
            qCritical() << "Invalid RSA key size, defaulting to 2048";
            bits = 2048;
        }
        pkeyoptValue = tr("rsa_keygen_bits:%1").arg(bits);
    } else if (algorithm.toUpper() == "ECC") {
        pkeyoptValue = tr("ec_paramgen_curve:%1").arg(keySize);
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

bool OpenSSLHelper::opensslGenSelfCert(int validDays,
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
            tr("-%1").arg(hashAlgo.toLower()),
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
            tr("-%1").arg(hashAlgo.toLower()),
            "-days", QString::number(validDays),
            "-out", tr("\"%1\"").arg(outPath),
            "-extfile", tr("\"%1\"").arg(configFile.fileName()),
        };
    if (!passphrase.isEmpty())
        arguments << "-passin" << "pass:" + passphrase;

    return opensslTool("openssl", arguments);
}

// [证书链=一级根证书+二级根证书]
bool OpenSSLHelper::opensslGenChain(const QString &subCAPath, 
                        const QString &rootCAPath, 
                        const QString &outPath)
{
    // Get-Content -Path interCAPath, rootCAPath | Out-File -FilePath outPath -Encoding ASCII
    // 等价于 Linux: cat interCA.crt.pem rootCA.crt.pem > chain.pem
    QString command = tr("-Path \"%1\", \"%2\" | Out-File -FilePath \"%3\" -Encoding ASCII")
                        .arg(subCAPath, rootCAPath, outPath);
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

    if (data.contains("BEGIN CERTIFICATE REQUEST")) {
        arguments << "req";
    } else if (data.contains("BEGIN CERTIFICATE")) {
        arguments << "x509";
    } else if (data.contains("BEGIN RSA PRIVATE KEY")) { // 传统RSA方式
        arguments << "rsa";
    } else if (data.contains("BEGIN EC PRIVATE KEY")) {  // 传统EC方式
        arguments << "ec";
    } else if (data.contains("BEGIN PRIVATE KEY")) {     // PKCS#8私钥 RSA/EC都是这种
        arguments << "pkey";
    } else if (data.contains("BEGIN PUBLIC KEY")) {
        arguments << "pkey" << "-pubin";
    } else {
        qCritical() << "Unsupported PEM format:" << pemPath;
        return false;
    }

    arguments << "-in" << tr("\"%1\"").arg(pemPath) 
              << "-outform" << "der" << "-out" << tr("\"%1\"").arg(outPath);
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
          -aes256 -pass pass:subcapass -out certs/subCA.key.pem
     */
    opensslTool("openssl", {
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:3072",
            "-aes256",
            "-pass", "pass:intercapass",
            "-out", "certs/subCA.key.pem",
        });

    /**
     * openssl req -new -key certs/subCA.key.pem -passin pass:subcapass \
            -out certs/subCA.csr.pem \
            -subj "/C=CN/ST=Fujian/O=cetxiyuan.com/CN=Subordinate CA By CetXiyuan" \
            -config NUL \
            -addext "subjectKeyIdentifier=hash" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" 
     */
    opensslTool("openssl", {
            "req",
            "-new",
            "-key", "certs/subCA.key.pem",
            "-passin", "pass:subcapass",
            "-out", "certs/subCA.csr.pem",
            "-subj", "\"/C=CN/ST=Fujian/O=cetxiyuan.com/CN=Subordinate CA By CetXiyuan\"",
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
     * openssl x509 -req -in certs/subCA.csr.pem -CA certs/rootCA.crt.pem \
            -CAkey certs/rootCA.key.pem -passin pass:rootcapass -CAcreateserial \
            -out certs/subCA.crt.pem -days 1825 -sha256 \
            -extfile F:/sharefolder/cetqtlearn/CetCryptoToolkit/CetCryptoToolkit/temp_config.QfOfqi
     */
    opensslTool("openssl", {
            "x509",
            "-req",
            "-in", "certs/subCA.csr.pem",
            "-CA", "certs/rootCA.crt.pem",
            "-CAkey", "certs/rootCA.key.pem",
            "-passin", "pass:rootcapass",
            "-CAcreateserial",
            "-out", "certs/subCA.crt.pem",
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
     * openssl x509 -req -in certs/terminal.csr.pem -CA certs/subCA.crt.pem \
            -CAkey certs/subCA.key.pem -passin pass:subcapass -CAcreateserial \
            -out certs/terminal.crt.pem -days 365 -sha256 \
            -extfile F:/sharefolder/cetqtlearn/CetCryptoToolkit/CetCryptoToolkit/temp_config.hJFDKV
     */
    opensslTool("openssl", {
            "x509",
            "-req",
            "-in", "certs/terminal.csr.pem",
            "-CA", "certs/subCA.crt.pem",
            "-CAkey", "certs/subCA.key.pem",
            "-passin", "pass:subcapass",
            "-CAcreateserial",
            "-out", "certs/terminal.crt.pem",
            "-days", "365",
            "-sha256",
            "-extfile", configFile1.fileName(),
        });

    return true;
}

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

    // 5. 转换 CA 证书链（Subordinate Certificates）
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
        qCritical() << "Failed to open private key file:" << filePath;
        return QSslKey();
    }

    QByteArray pemData = file.readAll();
    file.close();

    QSslKey privateKey(pemData, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    if (privateKey.isNull())
        privateKey = QSslKey(pemData, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);

    if (privateKey.isNull()) {
        qCritical() << "Failed to parse private key from file:" << filePath;
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

X509 *OpenSSLHelper::qcertToX509(const QSslCertificate &cert)
{
    QByteArray pem = cert.toPem();
    BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
    X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return x509;
}

EVP_PKEY *OpenSSLHelper::qsslkeyToEVP(const QSslKey &key)
{
    QByteArray pem = key.toPem();
    BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

X509_NAME *OpenSSLHelper::parseSubjectDN(const QString &subjectDN)
{
    X509_NAME *name = X509_NAME_new();
    if (!name) 
        return nullptr;

    QStringList dnParts = subjectDN.split('/', Qt::SkipEmptyParts);
    for (const QString &dnPart : dnParts) {
        QStringList keyValue = dnPart.split('=', Qt::SkipEmptyParts);
        if (keyValue.size() != 2) continue;
        const QString &key = keyValue[0].trimmed();
        const QString &value = keyValue[1].trimmed();
        if (X509_NAME_add_entry_by_txt(name, 
                key.toLatin1().constData(),
                MBSTRING_ASC,
                (const unsigned char*)value.toUtf8().constData(),
                -1, -1, 0) != 1) {
            X509_NAME_free(name);
            return nullptr;
        }
    }

    return name;
}

bool OpenSSLHelper::addExtensions(X509 *issuer, 
                                X509 *subject, 
                                X509_REQ *req, 
                                const QStringList &extensions) 
{
    if (extensions.isEmpty())
        return false;

    // 1. 初始化上下文
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, 
        issuer,     // CA证书（颁发者）
        subject,    // 当前证书
        req,        // 证书请求（可为NULL）
        nullptr,    // 不使用配置数据库
        0           // 标志位
    );

    // 2. 处理扩展
    bool success = true;
    STACK_OF(X509_EXTENSION) *ext_stack = nullptr;

    // 仅在处理CSR时创建扩展栈
    if (req) {
        ext_stack = sk_X509_EXTENSION_new_null();
        if (!ext_stack) {
            appendError("Failed to create extensions stack for CSR");
            return false;
        }
    }

    for (const QString &extStr : extensions) {
        // 跳过空行和注释行
        if (extStr.trimmed().isEmpty() || extStr.startsWith("#"))
            continue;

        // 解析键值对
        QStringList parts = extStr.split('=', Qt::SkipEmptyParts);
        if (parts.size() != 2) {
            appendError(tr("Invalid extension format: %1").arg(extStr));
            success = false;
            continue;
        }

        const QString &name = parts[0].trimmed();
        const QString &value = parts[1].trimmed();

        //qDebug() << "Processing extension - name:" << name << "value:" << value;

        // 2.2 创建扩展
        int nid = OBJ_txt2nid(name.toLatin1());
        //qDebug() << "NID:" << nid << "for extension:" << name;
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.toUtf8().constData());
        if (!ext) {
            appendError(tr("Failed to create extension %1: %2")
                       .arg(name)
                       .arg(getOpenSSLError()));
            success = false;
            continue;
        }

        // 2.3 添加到证书或CSR
        if (subject) {
            if (X509_add_ext(subject, ext, -1) != 1) {
                appendError(tr("Failed to add extension to certificate :%1")
                               .arg(getOpenSSLError()));
                success = false;
            }
            X509_EXTENSION_free(ext);
        } else if (req && ext_stack) {
            if (!sk_X509_EXTENSION_push(ext_stack, ext)) {
                X509_EXTENSION_free(ext);
                success = false;
                break;
            }
        }
    }

    // 批量添加到CSR
    if (req && ext_stack) {
        if (X509_REQ_add_extensions(req, ext_stack) != 1) {
            appendError(tr("Failed to add extensions to CSR :%1")
                           .arg(getOpenSSLError()));
            success = false;
        }
        sk_X509_EXTENSION_pop_free(ext_stack, X509_EXTENSION_free);
    }

    return success;
}

// 获取对应模式的EVP_CIPHER指针
const EVP_CIPHER *OpenSSLHelper::aesCipher(SymMode mode, const QByteArray &key)
{
    switch (mode) {
        case SYM_ECB:
            switch (key.size()) {
                case 16: return EVP_aes_128_ecb();
                case 24: return EVP_aes_192_ecb();
                case 32: return EVP_aes_256_ecb();
            }
            break;
        case SYM_CBC:
            switch (key.size()) {
                case 16: return EVP_aes_128_cbc();
                case 24: return EVP_aes_192_cbc();
                case 32: return EVP_aes_256_cbc();
            }
            break;
        case SYM_GCM:
            switch (key.size()) {
                case 16: return EVP_aes_128_gcm();
                case 24: return EVP_aes_192_gcm();
                case 32: return EVP_aes_256_gcm();
            }
            break;
        case SYM_CTR:
            switch (key.size()) {
                case 16: return EVP_aes_128_ctr();
                case 24: return EVP_aes_192_ctr();
                case 32: return EVP_aes_256_ctr();
            }
            break;
    }
    return nullptr;
}

QString OpenSSLHelper::getOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    QString error = QString::fromLatin1(buf, len);
    BIO_free(bio);
    return error.trimmed();
}

QString OpenSSLHelper::lastErrors() const
{
    return m_errors.isEmpty()? "" :  m_errors.last();
}

void OpenSSLHelper::clearErrors()
{
    ERR_clear_error();
    m_errors.clear();
}

void OpenSSLHelper::appendError(const QString &error)
{
    m_errors.append(error);
    qCritical() << "error" << error;
}

int OpenSSLHelper::keyAlgorithmFromName(const QString &name)
{
    for (const QPair<QString, int> &pair : supportedKeyAlgorithms)
        if (name == pair.first)
            return pair.second;

    return -1;
}

const EVP_MD *OpenSSLHelper::digestFromName(const QString &name)
{
    for (const QPair<QString, const EVP_MD *> &pair : supportedDigests)
        if (name == pair.first)
            return pair.second;

    return nullptr;
}

int OpenSSLHelper::ecCurveFromName(const QString &name)
{
    for (const QPair<QString, int> &pair : supportedEcCurves)
        if (name == pair.first)
            return pair.second;

    return -1;
}

int OpenSSLHelper::rsaBitsFromName(const QString &name)
{
    for (const QPair<QString, int> &pair : supportedRsaBits)
        if (name == pair.first)
            return pair.second;

    return -1;
}

OpenSSLHelper::SymMode OpenSSLHelper::symModeFromName(const QString &name)
{
    for (const QPair<QString, OpenSSLHelper::SymMode> &pair : supportedSymModes)
        if (name == pair.first)
            return pair.second;

    return (OpenSSLHelper::SymMode)-1;
}

QStringList OpenSSLHelper::supportKeyAlgorithmNames()
{
    QStringList names;
    for (const QPair<QString, int> &pair : supportedKeyAlgorithms)
        names.append(pair.first);
    return names;
}

QStringList OpenSSLHelper::supportDigestNames()
{
    QStringList names;
    for (const QPair<QString, const EVP_MD *> &pair : supportedDigests)
        names.append(pair.first);
    return names;
}

QStringList OpenSSLHelper::supportECCurveNames()
{
    QStringList names;
    for (const QPair<QString, int> &pair : supportedEcCurves)
        names.append(pair.first);
    return names;
}

QStringList OpenSSLHelper::supportRSABitsNames()
{
    QStringList names;
    for (const QPair<QString, int> &pair : supportedRsaBits)
        names.append(pair.first);
    return names;
}

QStringList OpenSSLHelper::supportSymModesNames()
{
    QStringList names;
    for (const QPair<QString, OpenSSLHelper::SymMode> &pair : supportedSymModes)
        names.append(pair.first);
    return names;
}

QByteArray OpenSSLHelper::sm2PubKeyToDer(const QByteArray &rawPubKey)
{
    // 1. 检查输入是否为有效的 SM2 公钥
    if (rawPubKey.size() != 64) {
        qCritical() << "Invalid SM2 public key format (must be 64 bytes)";
        return QByteArray();
    }

    QByteArray derPubKey;
    QByteArray pubKey;

    EVP_PKEY *pkey = nullptr;
    OSSL_PARAM_BLD *paramBld = nullptr;
    OSSL_PARAM *params = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    unsigned char *derPtr = nullptr;
    int derLen = 0;

    // 2. 使用 EVP_PKEY 和 OSSL_PARAM 构建 SM2 公钥
    paramBld = OSSL_PARAM_BLD_new();
    if (!paramBld) {
        qCritical() << "Failed to create OSSL_PARAM_BLD";
        goto cleanup;
    }

    // 传递 04||X||Y
    pubKey.append((uint8_t)0x04);
    pubKey.append(rawPubKey);
    if (!OSSL_PARAM_BLD_push_octet_string(paramBld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubKey.constData(),
                                         pubKey.size())) {
        qCritical() << "Failed to set public key data";
        goto cleanup;
    }

    // 设置 SM2 曲线参数
    if (!OSSL_PARAM_BLD_push_utf8_string(paramBld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "SM2", 0)) {
        qCritical() << "Failed to set SM2 curve";
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(paramBld);
    if (!params) {
        qCritical() << "Failed to build OSSL_PARAM";
        goto cleanup;
    }

    // 3. 从参数创建 EVP_PKEY
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (!ctx) {
        qCritical() << "Failed to create EVP_PKEY_CTX";
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        qCritical() << "Failed to initialize EVP_PKEY_fromdata";
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        qCritical() << "Failed to create EVP_PKEY from data";
        goto cleanup;
    }

    // 4. 编码为 DER 格式（使用 i2d_PUBKEY）
    derLen = i2d_PUBKEY(pkey, &derPtr);  // DER 编码
    if (derLen <= 0) {
        qCritical() << "Failed to encode SM2 public key to DER";
        goto cleanup;
    }
    /**
     * 5F70688E30DE3F86C5113E9C7DD0FDB780FD6701D5871153F698C16094188EE7F79FCC77A3FC06D85B5755F25B5AF5E8274B8DF81BA492D64065B65379914ADC
     * 3059301306072A8648CE3D020106082A811CCF5501822D034200045F70688E30DE3F86C5113E9C7DD0FDB780FD6701D5871153F698C16094188EE7F79FCC77A3FC06D85B5755F25B5AF5E8274B8DF81BA492D64065B65379914ADC
     * ASN.1 DER格式：3059(SEQUENCE 总长度 0x59(89 字节)) + 3013(SEQUENCE 椭圆曲线参数(19 字节))
            + 0607(OID 标识算法：1.2.840.10045.2.1(ECDSA))2A8648CE3D0201
            + 0608(OID 标识 SM2 曲线：1.2.156.10197.1.301)2A811CCF5501822D
            + 03420004(公钥数据 00 填充 + 04(未压缩格式))
            + 5F70688E30DE3F86C5113E9C7DD0FDB780FD6701D5871153F698C16094188EE7F79FCC77A3FC06D85B5755F25B5AF5E8274B8DF81BA492D64065B65379914ADC
     */
    derPubKey = QByteArray(reinterpret_cast<const char *>(derPtr), derLen);

cleanup:
    // 5. 清理资源
    if (derPtr) OPENSSL_free(derPtr);
    if (params) OSSL_PARAM_free(params);
    if (paramBld) OSSL_PARAM_BLD_free(paramBld);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);

    return derPubKey;
}

QByteArray OpenSSLHelper::sm2SignToDer(const QByteArray &rawSignKey)
{
    // 1. 检查输入是否为有效的 SM2 公钥
    if (rawSignKey.size() != 64) {
        qCritical() << "Invalid SM2 signature format - must be 64 bytes (32-byte r + 32-byte s)";
        return QByteArray();
    }

    ECDSA_SIG *sign = nullptr;
    BIGNUM *r = nullptr, *s = nullptr;
    unsigned char *derPtr = nullptr;
    int derLen = 0;
    QByteArray signData;

    r = BN_bin2bn(reinterpret_cast<const uint8_t *>(rawSignKey.constData()), 32, nullptr);
    s = BN_bin2bn(reinterpret_cast<const uint8_t *>(rawSignKey.constData() + 32), 32, nullptr);
    if (!r || !s) {
        qCritical() << "Failed to convert signature components to BIGNUM";
        goto cleanup;
    }

    /* 2. 64-byte r||s -> DER */
    sign = ECDSA_SIG_new();
    if (!sign || ECDSA_SIG_set0(sign, r, s) != 1) {
        qCritical() << "Failed to create ECDSA_SIG structure";
        goto cleanup;
    }

    derLen = i2d_ECDSA_SIG(sign, &derPtr);
    if (derLen <= 0) {
        qCritical() << "Failed to convert signature to DER format";
        goto cleanup;
    }

    /**
     * EE31D14FBAD44C35964429FAE0DE6410233419DC70D55A880124EE2B4663390F1C4FF5E5E640CA4B707D9FDF7034F385B9FD5818E74C85447BF5388AC2DEF2F6
     * 3045022100EE31D14FBAD44C35964429FAE0DE6410233419DC70D55A880124EE2B4663390F02201C4FF5E5E640CA4B707D9FDF7034F385B9FD5818E74C85447BF5388AC2DEF2F6
     * ASN.1 DER 格式：30(SEQUENCE) + 45(总长度) + 02(INTEGER: R的标记) + 21(R 的长度(32+1补字节)) + 00EE...0F
              + 02(INTEGER: S的标记) + 20(r 的长度(32)) + 1C4F...F6
     */
    signData = QByteArray(reinterpret_cast<const char *>(derPtr), derLen);

cleanup:
    if (derPtr) OPENSSL_free(derPtr);
    if (sign) ECDSA_SIG_free(sign);
    if (r) BN_free(r);
    if (s) BN_free(s);

    return signData;
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
    if (!helper.generateCertificateChain("/path/to/certs", "rootPass123", "subPass123")) {
        qCritical() << "Failed to generate certificate chain";
        return 1;
    }
    // 转换格式示例
    QStringList pemFiles = {
        "/path/to/certs/rootCA.crt.pem",
        "/path/to/certs/subCA.crt.pem",
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

