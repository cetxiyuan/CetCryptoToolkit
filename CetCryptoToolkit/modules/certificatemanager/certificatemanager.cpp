#include "certificatemanager.h"
#include "ui_certificatemanager.h"

#include <QDir>
#include <QFile>
#include <QMessageBox>
#include <QProcess>
#include <QVariantMap>
#include <QTimer>

#include <QDebug>

/**
 * 默认的一级根 CA 证书
 */
#define CAROOT_DEF_COUNTRY          "CN"                    // 国家：中国
#define CAROOT_DEF_STATE            "Fujian"                // 省/州：福建
#define CAROOT_DEF_LOCALITY         "Xiamen"                // 城市：厦门
#define CAROOT_DEF_ORGANIZATION     "RootCA"                // 组织/公司：CetXiyuan
#define CAROOT_DEF_ORGANIZATIONUNIT "cetxiyuan.com"         // 部门：IT Department
#define CAROOT_DEF_DAYS             (365 * 20)              // 有效天数：20 年
#define CAROOT_DEF_EMAILADDRESS     "cetxiyuan@yeah.net"    // 邮箱地址

#define CAROOT_DEF_CANAME           "CetXiyuan"             // 一级根证书名(CetXiyuan)
#define CAROOT_CUS_CANAME           "Custom"                // 一级根证书名(Custom)
#define CAINTER_CANAME              "SSL"                   // 二级根证书名

#define CAROOT                      "rootCA"                // 一级根证书标识
#define CAINTER                     "interCA"               // 二级根证书标识

#define CA_PEM_CERT(dir, tier, caname)          tr("%1/%2-%3.crt.pem").arg(dir, tier, caname)
#define CA_PEM_PUBLICKEY(dir, tier, caname)     tr("%1/%2-%3.pub.pem").arg(dir, tier, caname)
#define CA_PEM_PRIVATEKEY(dir, tier, caname)    tr("%1/%2-%3.key.pem").arg(dir, tier, caname)
#define CA_PEM_CSR(dir, tier, caname)           tr("%1/%2-%3.csr.pem").arg(dir, tier, caname)

#define CA_DER_CERT(dir, tier, caname)          tr("%1/%2-%3.crt.der").arg(dir, tier, caname)
#define CA_DER_PUBLICKEY(dir, tier, caname)     tr("%1/%2-%3.pub.der").arg(dir, tier, caname)
#define CA_DER_PRIVATEKEY(dir, tier, caname)    tr("%1/%2-%3.key.der").arg(dir, tier, caname)
#define CA_DER_CSR(dir, tier, caname)           tr("%1/%2-%3.csr.der").arg(dir, tier, caname)

/**
 * 一级根证书路径
 */
#define CAROOT_PEM_CERT(dir, caname)            CA_PEM_CERT(dir, CAROOT, caname)
#define CAROOT_PEM_PUBLICKEY(dir, caname)       CA_PEM_PUBLICKEY(dir, CAROOT, caname)
#define CAROOT_PEM_PRIVATEKEY(dir, caname)      CA_PEM_PRIVATEKEY(dir, CAROOT, caname)

#define CAROOT_DER_CERT(dir, caname)            CA_DER_CERT(dir, CAROOT, caname)
#define CAROOT_DER_PUBLICKEY(dir, caname)       CA_DER_PUBLICKEY(dir, CAROOT, caname)
#define CAROOT_DER_PRIVATEKEY(dir, caname)      CA_DER_PRIVATEKEY(dir, CAROOT, caname)

/**
 * 二级根证书路径
 */
#define CAINTER_PEM_CERT(dir)                   CA_PEM_CERT(dir, CAINTER, CAINTER_CANAME)
#define CAINTER_PEM_PUBLICKEY(dir)              CA_PEM_PUBLICKEY(dir, CAINTER, CAINTER_CANAME)
#define CAINTER_PEM_PRIVATEKEY(dir)             CA_PEM_PRIVATEKEY(dir, CAINTER, CAINTER_CANAME)
#define CAINTER_PEM_CSR(dir)                    CA_PEM_CSR(dir, CAINTER, CAINTER_CANAME)

#define CAINTER_DER_CERT(dir)                   CA_DER_CERT(dir, CAINTER, CAINTER_CANAME)
#define CAINTER_DER_PUBLICKEY(dir)              CA_DER_PUBLICKEY(dir, CAINTER, CAINTER_CANAME)
#define CAINTER_DER_PRIVATEKEY(dir)             CA_DER_PRIVATEKEY(dir, CAINTER, CAINTER_CANAME)
#define CAINTER_DER_CSR(dir)                    CA_DER_CSR(dir, CAINTER, CAINTER_CANAME)

/**
 * 证书链路径
 */
#define CHAIN_PEM_CERT(dir)                      tr("%1/ca-chain.pem").arg(dir)
#define CHAIN_P7B_CERT(dir)                      tr("%1/ca-chain.p7b").arg(dir)

/**
 * PFX文件路径
 */
#define FULL_BUNDLE_PFX(dir)                     tr("%1/full-bundle.pfx").arg(dir)


#define PLACEHOLDER_TEXT_COMMON \
    tr("%1,%2,域名/服务器名").arg(CAROOT_DEF_COMMONNAME, CAINTER_DEF_COMMONNAME)

#define TIP_COMMON  tr("一级根证书(eg: %1),二级根证书(eg: %2)," \
    "终端证书(域名/服务器名)").arg(CAROOT_DEF_COMMONNAME, CAINTER_DEF_COMMONNAME)


CertificateManager::CertificateManager(OpenSSLHelper *openSSLHelper, QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::CertificateManager)
    , m_openSSLHelper(openSSLHelper)
{
    ui->setupUi(this);
    setWindowTitle(tr("证书配置表"));

    ui->countryLineEdit->setPlaceholderText("CN(中国)");
    ui->stateProvinceLineEdit->setPlaceholderText("Beijing(北京)<可选>");
    ui->localityLineEdit->setPlaceholderText("Beijing(北京)<可选>");
    ui->organizationLineEdit->setPlaceholderText("Example Inc.(公司名称)");
    ui->organizationUnitLineEdit->setPlaceholderText("IT Department(部门：IT部门)<可选>");
    ui->emailAddressLineEdit->setPlaceholderText("admin@example.com<可选>");
    ui->commonLineEdit->setPlaceholderText(PLACEHOLDER_TEXT_COMMON);
    ui->commonLabel->setToolTip(TIP_COMMON);

    ui->countryLineEdit->setText("CN");
    ui->stateProvinceLineEdit->setText("FuJian");
    ui->localityLineEdit->setText("XiaMen");
    ui->organizationLineEdit->setText("CetXiyuan");
    ui->organizationUnitLineEdit->setText("IT Department");
    ui->commonLineEdit->setText("example.com");
    ui->emailAddressLineEdit->setText("admin@example.com");

    ui->keyTypeComboBox->addItem("RSA", "rsa");
    ui->keyTypeComboBox->addItem("ECC", "ec");

    ui->rsaKeyLengthComboBox->addItems(OpenSSLHelper::supportRsaBitsNames());
    ui->eccCurveComboBox->addItems(OpenSSLHelper::supportEcCurveNames());
    ui->hashAlgoComboBox->addItems(OpenSSLHelper::supportDigestNames());
    ui->hashAlgoComboBox->setCurrentIndex(3);

    qInfo() << "CA_DEFAULT_PEM_CERT:" << CAROOT_PEM_CERT(CAROOT_DEF_DIR, CAROOT_DEF_CANAME)
            << "CA_DEFAULT_PEM_PRIVATEKEY" << CAROOT_PEM_PRIVATEKEY(CAROOT_DEF_DIR, CAROOT_DEF_CANAME);
    if (!QFile::exists(CAROOT_DEF_DIR))
        QDir().mkdir(CAROOT_DEF_DIR);

    // 加载一级根证书
    if (!QFile::exists(CAROOT_PEM_CERT(CAROOT_DEF_DIR, CAROOT_DEF_CANAME))) {
        QTimer::singleShot(2000, this, [=]() {
                setCommonName(CAROOT_DEF_COMMONNAME);
                genCertificate(CERT_RootCACetXiyuan, CAROOT_DEF_DIR);
            });
    } else {
        loadCA(m_rootCACert, m_rootCAKeyPair, CAROOT_DEF_DIR, CAROOT, CAROOT_DEF_CANAME);
    }

    // 加载二级根证书
    if (QFile::exists(CAINTER_PEM_CERT(CAROOT_DEF_DIR))) {
        loadCA(m_interCACert, m_interCAKeyPair, CAROOT_DEF_DIR, CAINTER, CAINTER_CANAME);
    }
}

CertificateManager::~CertificateManager()
{
    delete ui;
}

void CertificateManager::setCommonName(const QString &commonName)
{
    if (commonName.contains(CAINTER_DEF_COMMONNAME)) {
        if ("RSA" == ui->keyTypeComboBox->currentText())
            ui->rsaKeyLengthComboBox->setCurrentIndex(3);
        else
            ui->eccCurveComboBox->setCurrentIndex(2);
    } else if (commonName.contains(CAROOT_CUS_COMMONNAME)) {
        if ("RSA" == ui->keyTypeComboBox->currentText())
            ui->rsaKeyLengthComboBox->setCurrentIndex(4);
        else
            ui->eccCurveComboBox->setCurrentIndex(3);
    }  else if (commonName.contains(CAROOT_DEF_COMMONNAME)) {
        if ("RSA" == ui->keyTypeComboBox->currentText())
            ui->rsaKeyLengthComboBox->setCurrentIndex(4);
        else
            ui->eccCurveComboBox->setCurrentIndex(3);
    } else {
        ui->rsaKeyLengthComboBox->setCurrentIndex(2);
        ui->eccCurveComboBox->setCurrentIndex(1);
    }

    return ui->commonLineEdit->setText(commonName);
}

void CertificateManager::setValidDays(int validDays)
{
    return ui->validDaysSpinBox->setValue(validDays);
}

QSslCertificate CertificateManager::genCertificateOpenssl(int type, const QString &outputDir, 
                                                const QString &commonName, const QString &subjectDN,
                                                QString &extMessage)
{
    QString keyAlgo = ui->keyTypeComboBox->currentText();
    QString hashAlgo = ui->hashAlgoComboBox->currentText();
    int validDays = ui->validDaysSpinBox->value();

    QString keySize;
    if (keyAlgo.contains("RSA"))
        keySize = ui->rsaKeyLengthComboBox->currentText();
    else if (keyAlgo.contains("ECC"))
        keySize = ui->eccCurveComboBox->currentText();

    bool chainRet = false;      // 证书链的生成结果
    bool pfxRet = false;        // PFX文件的生成结果
    QSslCertificate sslCert;
    QPair<QSslKey, QSslKey> keyPair;

    qDebug() << "type" << type 
             << "keyAlgo" << keyAlgo
             << "keySize" << keySize
             << "validDays" << validDays 
             << "subjectDN" << subjectDN;
    switch (type) {
    case CERT_EndEntity: { // 终端证书
        QString keyPath = tr("%1/%2.key.pem").arg(outputDir, commonName);
        QString pubPath = tr("%1/%2.pub.pem").arg(outputDir, commonName);
        QString csrPath = tr("%1/%2.csr.pem").arg(outputDir, commonName);
        QString crtPath = tr("%1/%2.crt.pem").arg(outputDir, commonName);

        if (!m_openSSLHelper->opensslGenKeyPair(keyAlgo, keySize, keyPath, pubPath))
            return sslCert;

        QStringList addexts;
        addexts << "subjectKeyIdentifier=hash"
                << "basicConstraints=CA:FALSE"
                << "keyUsage=digitalSignature,keyEncipherment"
                << "extendedKeyUsage=clientAuth,serverAuth"
                << "subjectAltName=DNS:cetterminal.example.com,DNS:www.cetterminal.example.com,IP:172.16.90.86,IP:127.0.0.1";
        if (!m_openSSLHelper->opensslGenCSR(subjectDN, keyPath, csrPath, addexts))
            return sslCert;

        addexts << "authorityKeyIdentifier=keyid,issuer";
        if (m_interCACert.isNull()) {
            qWarning() << "interCACert is null, use rootCACert Sign.";

            QString caname = QFile::exists(CAROOT_PEM_CERT(outputDir, CAROOT_CUS_CANAME))
                                ? CAROOT_CUS_CANAME : CAROOT_DEF_CANAME;
            if (!m_openSSLHelper->opensslSignCSR(validDays, csrPath,
                    CAROOT_PEM_CERT(outputDir, caname),
                    CAROOT_PEM_PRIVATEKEY(outputDir, caname),
                    crtPath, addexts, hashAlgo))
                return sslCert;
        } else {
            if (!m_openSSLHelper->opensslSignCSR(validDays, csrPath,
                    CAINTER_PEM_CERT(outputDir),
                    CAINTER_PEM_PRIVATEKEY(outputDir),
                    crtPath, addexts, hashAlgo))
                return sslCert;
        }

        // PEM to DER
        m_openSSLHelper->opensslToDer(crtPath,
            tr("%1/%2.crt.der").arg(outputDir, commonName));

        // 加载客户端证书
        sslCert = m_openSSLHelper->loadCertificates(crtPath).first();

        { // 生成证书链
            QString caname = QFile::exists(CAROOT_PEM_CERT(outputDir, CAROOT_CUS_CANAME))
                                ? CAROOT_CUS_CANAME : CAROOT_DEF_CANAME;
            chainRet = m_openSSLHelper->opensslGenChain(CAINTER_PEM_CERT(outputDir),
                                            CAROOT_PEM_CERT(outputDir, caname), 
                                            CHAIN_PEM_CERT(outputDir));
            if (chainRet) {
                // 证书链 转 P7B 格式
                chainRet = m_openSSLHelper->opensslToP7b(CHAIN_PEM_CERT(outputDir),
                                                    CHAIN_P7B_CERT(outputDir));
            }
        }

        { // 生成PFX文件
            pfxRet = m_openSSLHelper->opensslToPfx(crtPath, keyPath,
                                            CHAIN_PEM_CERT(outputDir),
                                            FULL_BUNDLE_PFX(outputDir));
        }

        // 扩展信息的添加
        extMessage = tr("\n证书链生成结果：%1\n证书链=一级根证书+二级根证书\n")
                        .arg(chainRet? "成功" : "失败");
        if (chainRet)
            extMessage.append(tr("证书链: %1\n%2\n").arg(CHAIN_PEM_CERT(outputDir), 
                CHAIN_P7B_CERT(outputDir)));
        extMessage.append(tr("\nPFX文件生成结果：%1\nPFX文件=终端证书+终端私钥+证书链\n")
                            .arg(pfxRet? "成功" : "失败"));
        if (pfxRet)
            extMessage.append(tr("PFX文件: %1\n").arg(FULL_BUNDLE_PFX(outputDir)));
        break;
    }
    case CERT_IntermediateCA: { // 二级根证书
        if (!m_openSSLHelper->opensslGenKeyPair(keyAlgo, keySize, 
                CAINTER_PEM_PRIVATEKEY(outputDir),
                CAINTER_PEM_PUBLICKEY(outputDir)))
            return sslCert;

        QStringList addexts;
        addexts << "subjectKeyIdentifier=hash"
                << "basicConstraints=critical,CA:TRUE,pathlen:0"
                << "keyUsage=critical,keyCertSign,cRLSign";
        if (!m_openSSLHelper->opensslGenCSR(subjectDN,
                CAINTER_PEM_PRIVATEKEY(outputDir),
                CAINTER_PEM_CSR(outputDir),
                addexts))
            return sslCert;

        addexts << "authorityKeyIdentifier=keyid:always,issuer";
        if (!m_openSSLHelper->opensslSignCSR(validDays, 
                CAINTER_PEM_CSR(outputDir),
                CAROOT_PEM_CERT(outputDir, CAROOT_DEF_CANAME),
                CAROOT_PEM_PRIVATEKEY(outputDir, CAROOT_DEF_CANAME),
                CAINTER_PEM_CERT(outputDir),
                addexts, hashAlgo))
            return sslCert;

        // PEM to DER
        m_openSSLHelper->opensslToDer(CAINTER_PEM_CERT(outputDir),
            CAINTER_DER_CERT(outputDir));

        // 加载二级根证书
        loadCA(sslCert, keyPair, outputDir, CAINTER, CAINTER_CANAME);
        if (!sslCert.isNull()) {
            m_interCACert = sslCert;
            m_interCAKeyPair = keyPair;
        }
        break;
    }
    case CERT_RootCACustom: // 一级根证书(Custom)
        if (!m_openSSLHelper->opensslGenKeyPair(keyAlgo, keySize, 
                CAROOT_PEM_PRIVATEKEY(outputDir, CAROOT_CUS_CANAME),
                CAROOT_PEM_PUBLICKEY(outputDir, CAROOT_CUS_CANAME)))
            return sslCert;
        if (!m_openSSLHelper->opensslGenSelfCert(validDays, subjectDN,
                CAROOT_PEM_PRIVATEKEY(outputDir, CAROOT_CUS_CANAME),
                CAROOT_PEM_CERT(outputDir, CAROOT_CUS_CANAME),
                hashAlgo))
            return sslCert;

        // PEM to DER
        m_openSSLHelper->opensslToDer(CAROOT_PEM_CERT(outputDir, CAROOT_CUS_CANAME),
            CAROOT_DER_CERT(outputDir, CAROOT_CUS_CANAME));

        // 加载一级根证书
        loadCA(sslCert, keyPair, outputDir, CAROOT, CAROOT_CUS_CANAME);
        if (!sslCert.isNull()) {
            m_rootCACert = sslCert;
            m_rootCAKeyPair = keyPair;
        }
        break;
    case CERT_RootCACetXiyuan: { // 一级根证书(CetXiyuan)
        QString subjectDN = tr("/C=%1/ST=%2/L=%3/O=%4/OU=%5/emailAddress=%6/CN=%7")
                            .arg(CAROOT_DEF_COUNTRY, CAROOT_DEF_STATE, CAROOT_DEF_LOCALITY)
                            .arg(CAROOT_DEF_ORGANIZATION, CAROOT_DEF_ORGANIZATIONUNIT)
                            .arg(CAROOT_DEF_EMAILADDRESS, CAROOT_DEF_COMMONNAME);

        if (!m_openSSLHelper->opensslGenKeyPair(keyAlgo, keySize, 
                CAROOT_PEM_PRIVATEKEY(outputDir, CAROOT_DEF_CANAME),
                CAROOT_PEM_PUBLICKEY(outputDir, CAROOT_DEF_CANAME)))
            return sslCert;

        if (!m_openSSLHelper->opensslGenSelfCert(validDays, subjectDN,
                CAROOT_PEM_PRIVATEKEY(outputDir, CAROOT_DEF_CANAME),
                CAROOT_PEM_CERT(outputDir, CAROOT_DEF_CANAME),
                hashAlgo))
            return sslCert;

        // PEM to DER
        m_openSSLHelper->opensslToDer(CAROOT_PEM_CERT(outputDir, CAROOT_DEF_CANAME),
            CAROOT_DER_CERT(outputDir, CAROOT_DEF_CANAME));

        // 加载一级根证书
        loadCA(sslCert, keyPair, outputDir, CAROOT, CAROOT_DEF_CANAME);
        if (!sslCert.isNull()) {
            m_rootCACert = sslCert;
            m_rootCAKeyPair = keyPair;
        }
        break;
    }
    default: break;
    }

    return sslCert;
}

QSslCertificate CertificateManager::genCertificateCode(int type, const QString &outputDir, 
                                        const QString &commonName, const QString &subjectDN,
                                        QString &extMessage)
{
    QString keyAlgo = ui->keyTypeComboBox->currentText();
    QString hashAlgo = ui->hashAlgoComboBox->currentText();
    int validDays = ui->validDaysSpinBox->value();

    QString keySize;
    if (keyAlgo.contains("RSA"))
        keySize = ui->rsaKeyLengthComboBox->currentText();
    else if (keyAlgo.contains("ECC"))
        keySize = ui->eccCurveComboBox->currentText();

    QString passphrase = ui->passphraseLineEdit->text();
    QString pfxPassphrase = ui->pfxPassphraseLineEdit->text();
    QByteArray pass = passphrase.toUtf8();

    bool chainRet = false;      // 证书链的生成结果
    bool pfxRet = false;        // PFX文件的生成结果
    QSslCertificate sslCert;

    QPair<QSslKey, QSslKey> keyPair
        = m_openSSLHelper->genKeyPair(keyAlgo, keySize, passphrase);
    if (keyPair.first.isNull() || keyPair.second.isNull()) {
        qCritical() << "keyPair.first || keyPair.second isNull():" << m_openSSLHelper->lastErrors();
        return sslCert;
    }
    QSslKey publicKey = keyPair.first;
    QSslKey privateKey = keyPair.second;

    //qDebug() << "publicKey" << publicKey.toPem().size() << publicKey.toPem().left(64);
    //qDebug() << "privateKey" << privateKey.toPem().size() << privateKey.toPem().left(64);
    qDebug() << "passphrase" << passphrase << "pfxPassphrase" << pfxPassphrase;
    qDebug() << "type" << type 
             << "keyAlgo" << keyAlgo
             << "keySize" << keySize
             << "validDays" << validDays 
             << "subjectDN" << subjectDN;
    switch (type) {
    case CERT_EndEntity: { // 终端证书
        QStringList extensions = {
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=digitalSignature,keyEncipherment",
            "subjectKeyIdentifier=hash",
            "extendedKeyUsage=serverAuth,clientAuth",
            "subjectAltName=DNS:example.com,DNS:example1.com,IP:172.16.90.86,IP:127.0.0.1",
        };

        QString csrPem = m_openSSLHelper->genCSR(subjectDN, privateKey, extensions, passphrase);
        if (csrPem.isEmpty()) {
            qCritical() << "csrPem.isEmpty():" << m_openSSLHelper->lastErrors();
            return sslCert;
        }

        extensions.append("authorityKeyIdentifier=keyid:always,issuer:always"); // 必须指向签发CA
        extensions.append("crlDistributionPoints=URI:http://example.com/ee.crl"); // 终端证书的CRL（推荐）
        //extensions.append("OCSP=URI:http://ocsp.example.com"); // OCSP响应地址（优于CRL）
        if (m_interCACert.isNull()) {
            qWarning() << "interCACert is null, use rootCACert Sign.";
            sslCert = m_openSSLHelper->signCSR(validDays, csrPem,
                                            m_rootCACert,
                                            m_rootCAKeyPair.second,
                                            extensions, hashAlgo, passphrase);
        } else {
            sslCert = m_openSSLHelper->signCSR(validDays, csrPem,
                                            m_interCACert,
                                            m_interCAKeyPair.second,
                                            extensions, hashAlgo, passphrase);
        }
        if (sslCert.isNull()) {
            qCritical() << "sslCert.isNull():" << m_openSSLHelper->lastErrors();
            return sslCert;
        }

        // 保存证书信息到文件
        saveToFile(publicKey.toPem(pass), tr("%1/%2.pub.pem").arg(outputDir, commonName));
        saveToFile(privateKey.toPem(pass), tr("%1/%2.key.pem").arg(outputDir, commonName));
        saveToFile(csrPem.toUtf8(), tr("%1/%2.csr.pem").arg(outputDir, commonName));
        saveToFile(sslCert.toPem(), tr("%1/%2.crt.pem").arg(outputDir, commonName));
        saveToFile(sslCert.toDer(), tr("%1/%2.crt.der").arg(outputDir, commonName));

        // 生成证书链
        QString chainPem = m_openSSLHelper->genChain(m_interCACert, m_rootCACert);
        if (!chainPem.isEmpty()) {
            // 证书链 转 P7B 格式
            QByteArray p7b = m_openSSLHelper->toP7b(chainPem);
            saveToFile(p7b, CHAIN_P7B_CERT(outputDir));
        }
        chainRet = !chainPem.isEmpty();

        if (!chainPem.isEmpty()) { // 生成PFX文件
            QByteArray pfx = m_openSSLHelper->toPfx(sslCert, 
                keyPair.second, chainPem, pfxPassphrase);
            saveToFile(pfx, FULL_BUNDLE_PFX(outputDir));

            pfxRet = !pfx.isEmpty();
        }

        // 扩展信息的添加
        extMessage = tr("\n证书链生成结果：%1\n证书链=一级根证书+二级根证书\n")
                        .arg(chainRet? "成功" : "失败");
        if (chainRet)
            extMessage.append(tr("证书链: %1\n%2\n").arg(CHAIN_PEM_CERT(outputDir), 
                CHAIN_P7B_CERT(outputDir)));
        extMessage.append(tr("\nPFX文件生成结果：%1\nPFX文件=终端证书+终端私钥+证书链\n")
                            .arg(pfxRet? "成功" : "失败"));
        if (pfxRet)
            extMessage.append(tr("PFX文件: %1\n").arg(FULL_BUNDLE_PFX(outputDir)));
        break;
    }
    case CERT_IntermediateCA: { // 二级根证书
        QStringList extensions = {
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "keyUsage=critical,keyCertSign,cRLSign",
            "subjectKeyIdentifier=hash",
        };
        QString csrPem = m_openSSLHelper->genCSR(subjectDN, privateKey, extensions, passphrase);
        if (csrPem.isEmpty()) {
            qCritical() << "csrPem.isEmpty():" << m_openSSLHelper->lastErrors();
            return sslCert;
        }

        extensions.append("authorityKeyIdentifier=keyid:always,issuer:always"); // 必须指向根CA的subjectKeyIdentifier
        extensions.append("crlDistributionPoints=URI:http://example.com/intermediate.crl"); // 中间CA的CRL分发点（推荐）
        //extensions.append("certificatePolicies", "1.2.3.4"); // 证书策略OID
        sslCert = m_openSSLHelper->signCSR(validDays, csrPem,
                                        m_rootCACert,
                                        m_rootCAKeyPair.second,
                                        extensions, hashAlgo,
                                        passphrase);
        if (sslCert.isNull()) {
            qCritical() << "sslCert.isNull():" << m_openSSLHelper->lastErrors();
            return sslCert;
        }

        // 保存证书信息到文件
        saveToFile(publicKey.toPem(pass), CAINTER_PEM_PUBLICKEY(outputDir));
        saveToFile(privateKey.toPem(pass), CAINTER_PEM_PRIVATEKEY(outputDir));
        saveToFile(csrPem.toUtf8(), CAINTER_PEM_CSR(outputDir));
        saveToFile(sslCert.toPem(), CAINTER_PEM_CERT(outputDir));
        saveToFile(sslCert.toDer(), CAINTER_DER_CERT(outputDir));

        // 更新二级根证书
        if (!sslCert.isNull()) {
            m_interCACert = sslCert;
            m_interCAKeyPair = keyPair;
        }
        break;
    }
    case CERT_RootCACustom:
    case CERT_RootCACetXiyuan: { // 一级根证书
        QString caname = (CERT_RootCACetXiyuan == type)
                          ? CAROOT_DEF_CANAME : CAROOT_CUS_CANAME;
        sslCert = m_openSSLHelper->genSelfCert(validDays, 
                            tr("/C=%1/ST=%2/L=%3/O=%4/OU=%5/emailAddress=%6/CN=%7")
                                .arg(CAROOT_DEF_COUNTRY, CAROOT_DEF_STATE, CAROOT_DEF_LOCALITY)
                                .arg(CAROOT_DEF_ORGANIZATION, CAROOT_DEF_ORGANIZATIONUNIT)
                                .arg(CAROOT_DEF_EMAILADDRESS, CAROOT_DEF_COMMONNAME), 
                            privateKey, hashAlgo,
                            passphrase);
        if (sslCert.isNull()) {
            qCritical() << "sslCert.isNull():" << m_openSSLHelper->lastErrors();
            return sslCert;
        }

        // 保存证书信息到文件
        saveToFile(publicKey.toPem(pass), CAROOT_PEM_PUBLICKEY(outputDir, caname));
        saveToFile(privateKey.toPem(pass), CAROOT_PEM_PRIVATEKEY(outputDir, caname));
        saveToFile(sslCert.toPem(), CAROOT_PEM_CERT(outputDir, caname));
        saveToFile(sslCert.toDer(), CAROOT_DER_CERT(outputDir, caname));

        // 更新一级根证书
        if (!sslCert.isNull()) {
            m_rootCACert = sslCert;
            m_rootCAKeyPair = keyPair;
        }
        break;
    }
    default: break;
    }

    return sslCert;
}

bool CertificateManager::genCertificate(int type, const QString &outputDir)
{
    QString country = ui->countryLineEdit->text();
    QString stateProvince = ui->stateProvinceLineEdit->text();
    QString locality = ui->localityLineEdit->text();
    QString organization = ui->organizationLineEdit->text();
    QString organizationUnit = ui->organizationUnitLineEdit->text();
    QString commonName = ui->commonLineEdit->text();
    QString emailAddress = ui->emailAddressLineEdit->text();
    QString subjectDN = tr("/C=%1/ST=%2/L=%3/O=%4/OU=%5/emailAddress=%6/CN=%7")
        .arg(country, stateProvince, locality, organization)
        .arg(organizationUnit, emailAddress, commonName);

    QString extMessage;
    QSslCertificate sslCert;
#if (USE_OPENSSL_TOOL_HANDLER > 0)
    sslCert = genCertificateOpenssl(type, outputDir, commonName, subjectDN, extMessage);
#else
    sslCert = genCertificateCode(type, outputDir, commonName, subjectDN, extMessage);
#endif

    if (!sslCert.isNull()) {
        QMessageBox::information(this, tr("提示"), 
            tr("证书生成成功\n证书：%1\t\n%2\n").arg(commonName, extMessage), 
                QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("证书生成失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }

    return !sslCert.isNull();
}

bool CertificateManager::saveToFile(const QByteArray &data, const QString &filePath)
{
    if (data.isEmpty())
        return false;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, tr("警告"), 
            tr("文件保存失败(%1:%2)！\t").arg(filePath, file.errorString()));
        return false;
    }

    file.write(data);
    file.close();

    return true;
}

void CertificateManager::saveCertificateFiles(QPair<QSslKey, QSslKey> keyPair, 
                    const QByteArray &csrData, const QSslCertificate &sslCert,
                    const QString &outputDir, const QString &commonName)
{
    QSslKey publicKey = keyPair.first;
    QSslKey privateKey = keyPair.second;

    // PEM 格式
    saveToFile(csrData, tr("%1/%2.crs.pem").arg(outputDir, commonName));
    m_openSSLHelper->saveCertificate(sslCert, tr("%1/%2.pem").arg(outputDir, commonName));
    m_openSSLHelper->savePublicKey(publicKey, tr("%1/%2-PublicKey.pem").arg(outputDir, commonName));
    m_openSSLHelper->savePrivateKey(privateKey, tr("%1/%2-PrivateKey.pem").arg(outputDir, commonName));

    // DER 格式(二进制)
    saveToFile(m_openSSLHelper->toDer(csrData), tr("%1/%2-CSR.der").arg(outputDir, commonName));
    saveToFile(sslCert.toDer(), tr("%1/%2.cer").arg(outputDir, commonName));
    saveToFile(publicKey.toDer(), tr("%1/%2-PublicKey.der").arg(outputDir, commonName));
    saveToFile(privateKey.toDer(), tr("%1/%2-PrivateKey.der").arg(outputDir, commonName));
}

void CertificateManager::saveCertificateCAFiles(QPair<QSslKey, QSslKey> keyPair, 
                                        const QSslCertificate &caCert, const QString &outputDir, 
                                        const QString &caName)
{
    QSslKey publicKey = keyPair.first;
    QSslKey privateKey = keyPair.second;

    // PEM 格式
    m_openSSLHelper->saveCertificate(caCert, CAROOT_PEM_CERT(outputDir, caName));
    m_openSSLHelper->savePublicKey(publicKey, CAROOT_PEM_PUBLICKEY(outputDir, caName));
    m_openSSLHelper->savePrivateKey(privateKey, CAROOT_PEM_PRIVATEKEY(outputDir, caName));

    // DER 格式(二进制)
    saveToFile(caCert.toDer(), CAROOT_DER_CERT(outputDir, caName));
    saveToFile(publicKey.toDer(), CAROOT_DER_PUBLICKEY(outputDir, caName));
    saveToFile(privateKey.toDer(), CAROOT_DER_PRIVATEKEY(outputDir, caName));
}

void CertificateManager::loadCA(QSslCertificate &sslCert, QPair<QSslKey, QSslKey> &keyPair, 
    const QString &dir, const QString &tier, const QString &caname)
{
    sslCert = m_openSSLHelper->loadCertificates(
        CA_PEM_CERT(dir, tier, caname)).first();
    keyPair.first = m_openSSLHelper->loadPublicKey(
        CA_PEM_PUBLICKEY(dir, tier, caname));
    keyPair.second = m_openSSLHelper->loadPrivateKey(
        CA_PEM_PRIVATEKEY(dir, tier, caname));
}


void CertificateManager::on_keyTypeComboBox_currentTextChanged(const QString &arg1)
{
    ui->rsaKeyLengthLabel->setVisible(false);
    ui->rsaKeyLengthComboBox->setVisible(false);
    ui->eccCurveLabel->setVisible(false);
    ui->eccCurveComboBox->setVisible(false);

    if (arg1.contains("RSA")) {
        ui->rsaKeyLengthLabel->setVisible(true);
        ui->rsaKeyLengthComboBox->setVisible(true);
    } else {
        ui->eccCurveLabel->setVisible(true);
        ui->eccCurveComboBox->setVisible(true);
    }
}

