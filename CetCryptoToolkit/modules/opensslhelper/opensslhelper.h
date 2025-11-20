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

    // 密钥生成
    QPair<QSslKey, QSslKey> generateRSAKeyPair(int bits = 2048);
    QPair<QSslKey, QSslKey> generateECCKeyPair(int nid = NID_X9_62_prime256v1);

    // 证书操作
    QSslCertificate createSelfSignedCA(const QSslKey &privateKey, 
                                                      const QString &subjectDN,
                                                      int validityDays);

    QByteArray makeCertificateRequest(const QSslKey &privateKey,
                           const QString &subjectDN);
    QSslCertificate signCertificateRequest(const QByteArray &csrData,
                                        const QSslCertificate &caCert,
                                        const QSslKey &caPrivateKey,
                                        int validDays);

    QByteArray toDerCSR(const QByteArray &pemCsr);


    // 签名与验证
    QByteArray signData(const QByteArray &data,
                       const QSslKey &privateKey,
                       const EVP_MD *md = EVP_sha256());

    bool verifySignature(const QByteArray &data,
                        const QByteArray &signature,
                        const QSslKey &publicKey,
                        const EVP_MD *md = EVP_sha256());

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

public:
    bool opensslGenKeyPair(const QString &algorithm, // "RSA"/"EC"
                        int keySize, // RSA:2048/3072/4096, EC:256/384/521
                        const QString &privKeyPath,
                        const QString &pubKeyPath = "",
                        const QString &passphrase = "");
    bool opensslGenCertCA(int validDays,
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

private:
    X509 *createCertificateTemplate(const QString &subject, int validDays);
    bool addExtensions(X509 *cert, const QVariantMap &extensions);
    QPair<QSslKey, QSslKey> getSslKeyPair(EVP_PKEY *pkey, QSsl::KeyAlgorithm algo);
    X509_NAME *parseSubjectName(const QString &subjectDN);

    bool opensslTest(void);

    QList<QString> m_errors;
};

#endif // OPENSSLHELPER_H
