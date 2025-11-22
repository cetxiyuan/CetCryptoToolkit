#ifndef CERTIFICATEMANAGER_H
#define CERTIFICATEMANAGER_H

#include "opensslhelper.h"

#include <QDialog>

#define USE_OPENSSL_TOOL_HANDLER     (0)

#define CAINTER_DEF_COMMONNAME      "CetXiyuan Intermediate CA Signing Authority"
#define CAROOT_CUS_COMMONNAME       "CetXiyuan Custom Root CA Signing Authority"
#define CAROOT_DEF_COMMONNAME       "CetXiyuan Root CA Signing Authority"  // 域名/服务器名
#define CAROOT_DEF_DIR  QCoreApplication::applicationDirPath() + "/certs"


namespace Ui {
class CertificateManager;
}

class CertificateManager : public QDialog
{
    Q_OBJECT

public:
    enum CertType {
        CERT_EndEntity = 0,     /**< 终端证书 */
        CERT_IntermediateCA,    /**< 二级根证书 */
        CERT_RootCACustom,      /**< 一级根证书(Custom) */
        CERT_RootCACetXiyuan,   /**< 一级根证书(CetXiyuan) */
    };
    Q_ENUM(CertType)

    explicit CertificateManager(OpenSSLHelper *openSSLHelper, QWidget *parent = nullptr);
    ~CertificateManager();
    bool genCertificateOpenssl(int type, const QString &outputDir);
    bool genCertificate(int type, const QString &outputDir);
    bool saveToFile(const QByteArray &data, const QString &filePath);
    void saveCertificateFiles(QPair<QSslKey, QSslKey> keyPair, 
                    const QByteArray &csrData, const QSslCertificate &sslCert,
                    const QString &outputDir, const QString &commonName);
    void saveCertificateCAFiles(QPair<QSslKey, QSslKey> keyPair, 
                    const QSslCertificate &caCert, const QString &outputDir, 
                    const QString &caName);
    void setCommonName(const QString &commonName);
    void setValidDays(int validDays);

private:
    void loadCA(QSslCertificate &sslCert, QPair<QSslKey, QSslKey> &keyPair, 
        const QString &dir, const QString &tier, const QString &caname);

private slots:
    void on_keyTypeComboBox_currentTextChanged(const QString &arg1);


private:
    Ui::CertificateManager *ui;
    OpenSSLHelper *const m_openSSLHelper;
    QPair<QSslKey, QSslKey> m_interCAKeyPair;   /* <二级证书公钥, 二级证书私钥> */
    QPair<QSslKey, QSslKey> m_rootCAKeyPair;    /* <一级证书公钥, 一级证书公钥> */
    QSslCertificate m_interCACert;              /* 二级证书 */
    QSslCertificate m_rootCACert;               /* 一级证书 */
};

#endif // CERTIFICATEMANAGER_H
