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
    explicit OpenSSLHelper(QObject *parent = nullptr);
    ~OpenSSLHelper();

    // 初始化与清理
    static void initOpenSSL();
    static void cleanupOpenSSL();

    // 密钥生成 QPair<公钥, 私钥>
    QPair<QSslKey, QSslKey> genKeyPair(const QString &algorithm, 
                                     int keySize = 2048, 
                                     const QString &passphrase = "");

    // 生成自签证书
    QSslCertificate genSelfCert(int validDays,
                       const QString &subjectDN,
                       const QSslKey &privateKey,
                       const QString &hashAlgo = "-sha256",
                       const QString &passphrase = "");
    // 生成证书请求
    QString genCSR(const QString &subjectDN, 
                        const QSslKey &privateKey,
                        const QVariantMap &extensions = {},
                        const QString &passphrase = "");
    // 签名证书请求
    QSslCertificate signCSR(int validDays,
                        const QString &csrPem,
                        const QSslCertificate &caCert,
                        const QSslKey &caPrivateKey,
                        const QVariantMap &extensions = {},
                        const QString &hashAlgo = "-sha256",
                        const QString &passphrase = "");

    // [证书链=一级根证书+二级根证书]
    QString genChain(const QSslCertificate &interCACert, 
                        const QSslCertificate &rootCACert);
    QByteArray toP7b(const QString &chainPem);

    // [PFX文件=证书链+终端私钥+终端证书] [密码=pfxpassword]
    QByteArray toPfx(const QSslCertificate &cert, 
                const QSslKey &privateKey,
                const QString &chainPem,
                const QString &passphrase = "");

    QByteArray toDer(const QString &pemData);

    // 签名与验证
    QByteArray signData(const QByteArray &data, 
                        const QSslKey &privateKey,
                        const QString &hashAlgo = "-sha256");

    bool verifySignature(const QByteArray &data, 
                        const QByteArray &signature,
                        const QSslKey &publicKey, 
                        const QString &hashAlgo = "-sha256");

    // 加密解密
    QByteArray encrypt(const QByteArray &data,
                      const QSslKey &publicKey,
                      const QSslCipher &cipher);

    QByteArray decrypt(const QByteArray &data,
                      const QSslKey &privateKey,
                      const QSslCipher &cipher);

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
                        int keySize, // RSA:2048/3072/4096, EC:256/384/521
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
                        const QStringList &addexts,
                        const QString &passphrase = "");
    bool opensslSignCSR(int validDays,
                        const QString &csrPath,
                        const QString &caPath,
                        const QString &caKeyPath,
                        const QString &outPath,
                        const QStringList &addexts,
                        const QString &hashAlgo = "-sha256",
                        const QString &passphrase = "");

    // [证书链=一级根证书+二级根证书]
    bool opensslGenChain(const QString &interCAPath, 
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
    const EVP_MD *getHashAlgorithm(const QString &algo);
    bool addExtensions(X509 *ca_cert, X509 *cert, X509_REQ *req, const QVariantMap &extensions);
    QString getOpenSSLError();

    QList<QString> m_errors;
};

#endif // OPENSSLHELPER_H
