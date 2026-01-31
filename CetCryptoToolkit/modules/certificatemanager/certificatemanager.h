#ifndef CERTIFICATEMANAGER_H
#define CERTIFICATEMANAGER_H

#include "opensslhelper.h"

#include <QDialog>

#define USE_OPENSSL_TOOL_HANDLER     (0)

#define CASUB_DEF_COMMONNAME        "CetXiyuan Subordinate CA Signing Authority"
#define CAROOT_CUS_COMMONNAME       "CetXiyuan Custom Root CA Signing Authority"
#define CAROOT_DEF_COMMONNAME       "CetXiyuan Root CA Signing Authority"  // 域名/服务器名
#define CAROOT_DEF_DIR              QCoreApplication::applicationDirPath() + "/dir-certs"
#define CASUB_DEF_DIR               CAROOT_DEF_DIR

/**
 * 一级根证书、二级根证书和终端证书的默认证书扩展字段
 */
#define CAROOT_DEF_CERTEXTS                                 \
    "basicConstraints=critical,CA:TRUE,pathlen:1\n"         \
    "keyUsage=critical,keyCertSign,cRLSign\n"               \
    "subjectKeyIdentifier=hash\n"                           \
    "authorityKeyIdentifier=keyid:always,issuer:always"

#define CASUB_DEF_CERTEXTS                                  \
    "basicConstraints=critical,CA:TRUE,pathlen:0\n"         \
    "keyUsage=critical,keyCertSign,cRLSign\n"               \
    "subjectKeyIdentifier=hash\n"                           \
    "authorityKeyIdentifier=keyid:always,issuer:always"

// subjectAltName=DNS:example.com,DNS:example1.com,IP:172.16.90.86,IP:127.0.0.1
#define ENDENTITY_DEF_CERTEXTS                              \
    "basicConstraints=critical,CA:FALSE\n"                  \
    "keyUsage=digitalSignature,keyEncipherment\n"           \
    "subjectKeyIdentifier=hash\n"                           \
    "authorityKeyIdentifier=keyid:always,issuer:always\n"   \
    "extendedKeyUsage=serverAuth,clientAuth\n"              \
    "subjectAltName=DNS:example.com,IP:172.16.90.86"


namespace Ui {
class CertificateManager;
}

class CertificateManager : public QDialog
{
    Q_OBJECT

public:
    enum CertType {
        CERT_EndEntity = 0,     /**< 终端证书 */
        CERT_SubordinateCA,     /**< 二级根证书 */
        CERT_RootCACustom,      /**< 一级根证书(Custom) */
        CERT_RootCACetXiyuan,   /**< 一级根证书(CetXiyuan) */
    };
    Q_ENUM(CertType)

    explicit CertificateManager(OpenSSLHelper *openSSLHelper, QWidget *parent = nullptr);
    ~CertificateManager();
    bool genCertificate(int type, const QString &outputDir);
    // 采用 openssl 工具生成证书的版本
    QSslCertificate genCertificateOpenssl(int type, const QString &outputDir, 
                            const QString &commonName, const QString &subjectDN,
                            QString &extMessage);
    // 采用 openssl 代码生成证书的版本
    QSslCertificate genCertificateCode(int type, const QString &outputDir, 
                            const QString &commonName, const QString &subjectDN,
                            QString &extMessage);
    bool saveToFile(const QByteArray &data, const QString &filePath);
    void saveCertificateFiles(QPair<QSslKey, QSslKey> keyPair, 
                    const QByteArray &csrData, const QSslCertificate &sslCert,
                    const QString &outputDir, const QString &commonName);
    void saveCertificateCAFiles(QPair<QSslKey, QSslKey> keyPair, 
                    const QSslCertificate &caCert, const QString &outputDir, 
                    const QString &caName);
    void setCommonName(const QString &commonName);
    void setValidDays(int validDays);
    void setCertExts(const QString &certExts);

private:
    void loadCA(QSslCertificate &sslCert, QPair<QSslKey, QSslKey> &keyPair, 
        const QString &dir, const QString &tier, const QString &caname);

private slots:
    void on_keyTypeComboBox_currentTextChanged(const QString &arg1);


private:
    Ui::CertificateManager *ui;
    OpenSSLHelper *const m_openSSLHelper;
    QPair<QSslKey, QSslKey> m_subCAKeyPair;     /* <二级证书公钥, 二级证书私钥> */
    QPair<QSslKey, QSslKey> m_rootCAKeyPair;    /* <一级证书公钥, 一级证书公钥> */
    QSslCertificate m_subCACert;                /* 二级证书 */
    QSslCertificate m_rootCACert;               /* 一级证书 */
};

#endif // CERTIFICATEMANAGER_H
