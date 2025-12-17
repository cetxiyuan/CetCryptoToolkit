#ifndef OPENSSLHELPER_H
#define OPENSSLHELPER_H

#include <QObject>
#include <QList>
#include <QPair>

#include <QSslCertificate>
#include <QSslKey>
#include <QSslError>
#include <QSslCipher>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>


class OpenSSLHelper : public QObject
{
    Q_OBJECT
public:
    enum SymMode {
        SYM_ECB,    // 电子密码本（不推荐）
        SYM_CBC,    // 密码分组链接
        SYM_GCM,    // 伽罗瓦计数器模式（认证加密）
        SYM_CTR     // 计数器模式
    };

    explicit OpenSSLHelper(QObject *parent = nullptr);
    ~OpenSSLHelper();

    // 初始化与清理
    static void initOpenSSL();
    static void cleanupOpenSSL();

    // 密钥生成 QPair<公钥, 私钥>
    QPair<QSslKey, QSslKey> genKeyPair(const QString &algorithm, 
                                     const QString &keySize = "2048-bit", 
                                     const QString &passphrase = "");

    // 生成自签证书
    QSslCertificate genSelfCert(int validDays,
                       const QString &subjectDN,
                       const QSslKey &privateKey,
                       const QString &hashAlgo = "sha256",
                       const QString &passphrase = "");
    // 生成证书请求
    QString genCSR(const QString &subjectDN, 
                        const QSslKey &privateKey,
                        const QStringList &extensions = {},
                        const QString &passphrase = "");
    // 签名证书请求
    QSslCertificate signCSR(int validDays,
                        const QString &csrPem,
                        const QSslCertificate &caCert,
                        const QSslKey &caPrivateKey,
                        const QStringList &extensions = {},
                        const QString &hashAlgo = "sha256",
                        const QString &passphrase = "");

    // [证书链=一级根证书+二级根证书]
    QByteArray genChain(const QSslCertificate &subCACert, 
                        const QSslCertificate &rootCACert);
    QByteArray toP7b(const QByteArray &chainPem);

    // [PFX文件=证书链+终端私钥+终端证书] [密码=pfxpassword]
    QByteArray toPfx(const QSslCertificate &cert, 
                const QSslKey &privateKey,
                const QByteArray &chainPem,
                const QString &passphrase = "");

    QByteArray toDer(const QByteArray &pemData);

    // 签名与验证
    QByteArray digest(const QByteArray &data, const QString &hashAlgo);
    QByteArray signDigest(const QByteArray &digest,
                        const QSslKey &privateKey,
                        const QString &hashAlgo = "sha256",
                        const QString &passphrase = "",
                        const QByteArray &userId = ""); // 仅SM2有
    QByteArray signData(const QByteArray &data, 
                        const QSslKey &privateKey,
                        const QString &hashAlgo = "sha256",
                        const QString &passphrase = "",
                        const QByteArray &userId = ""); // 仅SM2有
    bool signVerify(const QByteArray &data, 
                        const QByteArray &signature,
                        const QSslKey &publicKey, 
                        const QString &hashAlgo = "sha256",
                        const QByteArray &userId = ""); // 仅SM2有

    // RSA/EC 公钥加密
    static QByteArray asymmetricEncrypt(const QByteArray &data, const QSslKey &publicKey);
    // RSA/EC 私钥解密
    static QByteArray asymmetricDecrypt(const QByteArray &data, const QSslKey &privateKey);

    // 加密（返回格式：GCM模式=IV+密文+Tag，其他模式=IV+密文）
    static QByteArray aesEncrypt(const QByteArray &plaintext, 
            const QByteArray &key, SymMode mode = SYM_ECB, 
            const QByteArray &iv = QByteArray());
    // 解密（输入格式需与加密输出一致）
    static QByteArray aesDecrypt(const QByteArray &ciphertext, 
            const QByteArray &key, SymMode mode = SYM_ECB);
    // 生成CMAC（用于消息认证）
    static QByteArray aes128GenerateCMAC(const QByteArray &data, const QByteArray &key);
    // 生成随机密钥（16/24/32字节）
    static QByteArray aesGenerateKey(int keySize = 32);
    // 生成随机IV（GCM推荐12字节，其他16字节）
    static QByteArray aesGenerateIV(SymMode mode);

    QByteArray sm4Encrypt(const QByteArray &plaintext,
                            const QByteArray &key,
                            SymMode mode,
                            const QByteArray &iv);
    QByteArray sm4Decrypt(const QByteArray &ciphertext,
                            const QByteArray &key,
                            SymMode mode,
                            const QByteArray &iv);

    QByteArray sm2PubKeyToDer(const QByteArray &rawPubKey);
    QByteArray sm2SignToDer(const QByteArray &rawSignKey);

    // 证书管理
    static QList<QSslCertificate> loadCertificates(const QString &filePath);
    static bool saveCertificate(const QSslCertificate &cert,
                              const QString &filePath);
    static QList<QSslCertificate> loadPKCS12(const QByteArray &pkcs12Data,
                                           const QString &passphrase,
                                           QSslKey *privateKey = nullptr);

    static QSslKey loadPublicKey(const QString &filePath);
    static bool savePublicKey(const QSslKey &publicKey, const QString &filePath);
    static QSslKey loadPrivateKey(const QString &filePath);
    static bool savePrivateKey(const QSslKey &privateKey, const QString &filePath);

    static QStringList supportKeyAlgorithmNames();
    static QStringList supportDigestNames();
    static QStringList supportECCurveNames();
    static QStringList supportRSABitsNames();
    static QStringList supportSymModesNames();
    static int keyAlgorithmFromName(const QString &name);
    static int ecCurveFromName(const QString &name);
    static int rsaBitsFromName(const QString &name);
    static SymMode symModeFromName(const QString &name);

    // 错误处理
    QString lastErrors() const;
    void clearErrors();
    void appendError(const QString &error);

private:
    static int callbackPassword(char *buf, int size, int rwflag, void *userdata);
    static X509 *qcertToX509(const QSslCertificate &cert);
    static EVP_PKEY *qsslkeyToEVP(const QSslKey &key);

public:
    bool opensslGenKeyPair(const QString &algorithm, // "RSA"/"EC"
                        const QString &keySize,     // RSA:2048/3072/4096, EC:256/384/521
                        const QString &privKeyPath,
                        const QString &pubKeyPath = "",
                        const QString &passphrase = "");
    bool opensslGenSelfCert(int validDays,
                       const QString &subjectDN,
                       const QString &keyPath,
                       const QString &outPath,
                       const QString &hashAlgo = "-sha256",
                       const QString &passphrase = "");
    bool opensslGenCSR(const QString &subjectDN, 
                        const QString &keyPath, 
                        const QString &outPath,
                        const QStringList &extensions,
                        const QString &passphrase = "");
    bool opensslSignCSR(int validDays,
                        const QString &csrPath,
                        const QString &caPath,
                        const QString &caKeyPath,
                        const QString &outPath,
                        const QStringList &extensions,
                        const QString &hashAlgo = "-sha256",
                        const QString &passphrase = "");

    // [证书链=一级根证书+二级根证书]
    bool opensslGenChain(const QString &subCAPath, 
                        const QString &rootCAPath, 
                        const QString &outPath);
    bool opensslToP7b(const QString &chainPath, const QString &outPath);

    // [PFX文件=证书链+终端私钥+终端证书] [密码=pfxpassword]
    bool opensslToPfx(const QString &pemPath, 
                        const QString &pemKeyPath,
                        const QString &chainPath, 
                        const QString &outPath, 
                        const QString &passphrase = "");
    bool opensslToDer(const QString &pemPath, const QString &outPath);
    bool opensslTool(const QString &program, const QStringList &arguments);
    bool opensslTest(void);

private:
    X509_NAME *parseSubjectDN(const QString &subjectDN);
    bool addExtensions(X509 *ca_cert, X509 *cert, X509_REQ *req, 
        const QStringList &extensions);
    QString getOpenSSLError();

private:
    static const EVP_CIPHER *aesCipher(SymMode mode, const QByteArray &key);
    static const EVP_MD *digestFromName(const QString &name);

    QList<QString> m_errors;
};

#endif // OPENSSLHELPER_H
