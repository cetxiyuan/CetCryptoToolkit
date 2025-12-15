#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "version.h"

#include <QDir>
#include <QTimer>
#include <QPluginLoader>
#include <QSettings>
#include <QTextCodec>
#include <QMessageBox>
#include <QFileDialog>
#include <QProcess>

#include <QDebug>

#define INIT_INTERFACE(mInterface, name)    \
    mInterface(qobject_cast<typeof(mInterface)>(loadPlugin(name)))
#define LOAD_INTERFACE(mInterface, name, isRemind)    \
    mInterface = qobject_cast<typeof(mInterface)>(loadPlugin(name));    \
    if (!mInterface && isRemind)    \
        QMessageBox::warning(this, tr("警告"), tr("缺少 (%1) 库\t").arg(name))


#define CETRECORD_DIR "./Record"
#define CETCRYPTOTOOLKIT_VERSION  "CetCryptoToolkit V" APP_VERSION " " TIP_VERSION
#define CETCRYPTOTOOLKIT_INFO     "  欢迎使用：" APP_NAME \
        " - CetCryptoToolkit - 设计者：CetXiyuan(璟·汐源忆醉) - 随时欢迎交流，谢谢！"

#define TEXT_EndEntity          "终端证书"
#define TEXT_IntermediateCA     "二级根证书"
#define TEXT_RootCACustom       "一级根证书(Custom)"
#define TEXT_RootCACetXiyuan    "一级根证书(CetXiyuan)"

#define DIR_CERTS               CAROOT_DEF_DIR      // 证书目录
#define DIR_ASYMMETRICS         QCoreApplication::applicationDirPath() + "/dir-asymmetrics"   // 非对称加密算法目录
#define DIR_SYMMETRICS          QCoreApplication::applicationDirPath() + "/dir-symmetrics"    // 对称加密算法目录

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , INIT_INTERFACE(m_cetLogManagerInterface, "CetLogManagerPlugin.dll")
    , m_settings(new QSettings("Configs/AppMaster.ini", QSettings::IniFormat))
    , m_openSSLHelper(new OpenSSLHelper())
    , m_certManager(new CertificateManager(m_openSSLHelper, this))
{
    QTextCodec *codec = QTextCodec::codecForName("UTF-8");
    QTextCodec::setCodecForLocale(codec);
    m_settings->setIniCodec(QTextCodec::codecForName("UTF-8"));

    ui->setupUi(this);
    setWindowTitle(tr(CETCRYPTOTOOLKIT_VERSION));

    if (!QFile::exists(DIR_CERTS))
        QDir().mkdir(DIR_CERTS);
    if (!QFile::exists(DIR_ASYMMETRICS))
        QDir().mkdir(DIR_ASYMMETRICS);
    if (!QFile::exists(DIR_SYMMETRICS))
        QDir().mkdir(DIR_SYMMETRICS);

    // 证书管理相关
    ui->certTypeComboBox->addItem(tr(TEXT_EndEntity));
    ui->certTypeComboBox->addItem(tr(TEXT_IntermediateCA));
    ui->certTypeComboBox->addItem(tr(TEXT_RootCACustom));
    ui->certTypeComboBox->addItem(tr(TEXT_RootCACetXiyuan));
    ui->certOutputDirLineEdit->setText(CAROOT_DEF_DIR);

    // 非对称加密算法相关
    ui->aeaDigestComboBox->addItems(OpenSSLHelper::supportDigestNames());
    ui->aeaDigestComboBox->setCurrentIndex(3);

    // 对称加密算法相关
    ui->seaAlgoComboBox->addItem("AES");
    ui->seaAlgoComboBox->addItem("SM4");
    ui->seaEncryptModeComboBox->addItems(OpenSSLHelper::supportSymModesNames());
    ui->seaKeyLineEdit->setInputMask("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH");
    ui->seaIvLineEdit->setInputMask("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH");

    ui->seaKeyBitsComboBox->addItem("128位");
    ui->seaKeyBitsComboBox->addItem("192位");
    ui->seaKeyBitsComboBox->addItem("256位");
    ui->seaKeyBitsComboBox->addItem("不支持");

    ui->aeaPrivateToolButton->setVisible(false);
    ui->aeaPublicToolButton->setVisible(false);
    ui->aeaDataToolButton->setVisible(false);
    ui->seaDataToolButton->setVisible(false);
    ui->seaEncryptToolButton->setVisible(false);
    ui->seaDecryptToolButton->setVisible(false);

    initFeaturesPlugin();

    connect(ui->certConfigureToolButton, &QToolButton::clicked, 
        m_certManager, &CertificateManager::show);

    connect(ui->aeaPrivateFileCheckBox, &QCheckBox::clicked, 
        ui->aeaPrivateToolButton, &QToolButton::setVisible);
    connect(ui->aeaPublicFileCheckBox, &QCheckBox::clicked, 
        ui->aeaPublicToolButton, &QToolButton::setVisible);
    connect(ui->aeaDataFileCheckBox, &QCheckBox::clicked, 
        ui->aeaDataToolButton, &QToolButton::setVisible);
    connect(ui->seaDataFileCheckBox, &QCheckBox::clicked, 
        ui->seaDataToolButton, &QToolButton::setVisible);
    connect(ui->seaEncryptFileCheckBox, &QCheckBox::clicked, 
        ui->seaEncryptToolButton, &QToolButton::setVisible);
    connect(ui->seaDecryptFileCheckBox, &QCheckBox::clicked, 
        ui->seaDecryptToolButton, &QToolButton::setVisible);

}

MainWindow::~MainWindow()
{
    delete m_cetProgressInterface;
    delete m_cetUpdateInterface;
    delete m_cetLicenseInterface;

    delete m_settings;
    delete m_cetLogManagerInterface;

    delete ui;
}

QObject *MainWindow::loadPlugin(const QString &dllName)
{
    QObject *plugin = nullptr;
    QDir pluginsDir("D:/Program Files (x86)/CetXiyuan/CetToolDLLs/plugins");

    if (!pluginsDir.exists())
        pluginsDir.setPath("./plugins");

    foreach (const QString &fileName, pluginsDir.entryList(QDir::Files)) {
        if (0 == dllName.compare(fileName, Qt::CaseInsensitive)) {
            QPluginLoader pluginLoader(pluginsDir.absoluteFilePath(fileName));
            plugin = pluginLoader.instance();
            if (plugin) {
                plugin->setParent(this);
            }
            break;
        }
    }

    return plugin;
}

void MainWindow::initFeaturesPlugin()
{
    ui->logManagerMenu->addAction(tr("控制"), this, [=]() {
            m_cetLogManagerInterface->show();
        });

    LOAD_INTERFACE(m_cetLicenseInterface, "CetLicensePlugin.dll", true);
    if (m_cetLicenseInterface)
        m_cetLicenseInterface->initialize(PRODUCT_NAME);
    QAction *activeAction = ui->licenseMenu->addAction(tr("激活"), this, [=]() {
        int result = 0;
        bool activated = false;
        static bool auto_timing_active = true;
        if (m_cetLicenseInterface) {
            result = (auto_timing_active ? m_cetLicenseInterface->activate()
                                         : m_cetLicenseInterface->activateWindow());
            if (CetLicenseInterface::ACTIVATE_CANCEL == result)
                goto timing_active;
            activated = (CetLicenseInterface::ACTIVATE_OK == result);
        }
        if (activated) {
            this->setWindowTitle(tr(CETCRYPTOTOOLKIT_VERSION));
            this->statusBar()->clearMessage();
        } else {
            QString expireInfo = tr("%1 [ 已到期 (%2) (%3) ]").arg(
                tr(CETCRYPTOTOOLKIT_VERSION), PRODUCT_NAME, 
                m_cetLicenseInterface? m_cetLicenseInterface->solidKey() : "");
            this->setWindowTitle(expireInfo);
            this->statusBar()->showMessage(tr("%1 请激活后使用！").arg(expireInfo), 60 * 1000);
        }
        this->centralWidget()->setEnabled(activated);

        if (!auto_timing_active && CetLicenseInterface::ACTIVATE_CANCEL != result) {
            QMessageBox::information(this, tr("通知"), (m_cetLicenseInterface? 
                m_cetLicenseInterface->resultString() : "") + "\t", QMessageBox::Ok);
        }
    timing_active:
        auto_timing_active = false;
        QTimer::singleShot(5 * 24 * 3600 * 1000, this, [=]() {  /* 5 天检查一次 是否到期 */
            auto_timing_active = true;
            emit ui->licenseMenu->actions().first()->triggered(true);
        });
    });
    QTimer::singleShot(10 * 1000, this, [=]() {                 /* 上电 10 秒后开始检测激活 */
            emit activeAction->triggered(true);
        });

    LOAD_INTERFACE(m_cetUpdateInterface, "CetUpdatePlugin.dll", true);
    if (m_cetUpdateInterface)
        m_cetUpdateInterface->checkUpdate(APP_NAME, APP_VERSION, QCoreApplication::quit);

    LOAD_INTERFACE(m_cetProgressInterface, "CetProgressPlugin.dll", false);
}

// 返回原始数据
QByteArray MainWindow::getData(bool isFile, const QString &fileName, bool inBase64)
{
    QByteArray rawData;

    if (isFile) {
        QFile file(fileName);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::critical(this, tr("错误"), 
                tr("文件打开失败(%1)！\t").arg(fileName));
            return QByteArray();
        }
        rawData = file.readAll();
        file.close();
    } else {
        rawData = (inBase64)
                   ? fileName.toUtf8()
                   : QByteArray::fromHex(fileName.toUtf8());
    }

    //qDebug() << "getData: isFile" << isFile << "fileName" << fileName << rawData;

    return (inBase64)? QByteArray::fromBase64(rawData) : rawData;
}

void MainWindow::on_outputDirToolButton_clicked()
{
    QString directory = QFileDialog::getExistingDirectory(this, tr("证书输出目录"), 
        ui->outputDirToolButton->text());
    if (!directory.isEmpty()) {
        ui->certOutputDirLineEdit->setText(directory);
    }
}

void MainWindow::on_certTypeComboBox_currentTextChanged(const QString &arg1)
{
    if (arg1.contains(TEXT_EndEntity)) {
        m_certManager->setCommonName("example.com");
        m_certManager->setValidDays(365);
    } else if (arg1.contains(TEXT_IntermediateCA)) {
        m_certManager->setCommonName(CAINTER_DEF_COMMONNAME);
        m_certManager->setValidDays(365 * 5);
    } else if (arg1.contains(TEXT_RootCACustom)) {
        m_certManager->setCommonName(CAROOT_CUS_COMMONNAME);
        m_certManager->setValidDays(365 * 20);
    }  else if (arg1.contains(TEXT_RootCACetXiyuan)) {
        m_certManager->setCommonName(CAROOT_DEF_COMMONNAME);
        m_certManager->setValidDays(365 * 20);
    }
}

// 生成证书
void MainWindow::on_genCertPushButton_clicked()
{
    int index = ui->certTypeComboBox->currentIndex();
    QString outputDir = ui->certOutputDirLineEdit->text();

    m_certManager->genCertificate(index, outputDir);
}

// 非对称加密算法
void MainWindow::on_aeaPrivateToolButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("选择私钥文件"), 
                            ui->aeaPrivateLineEdit->text(), 
                            tr("PEM 文件 (*.pem);;DER 文件 (*.der);;所有文件 (*)"));
    if (!fileName.isEmpty()) {
        ui->aeaPrivateLineEdit->setText(fileName);
    }
}


void MainWindow::on_aeaPublicToolButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("选择公钥文件"), 
                            ui->aeaPublicLineEdit->text(), 
                            tr("PEM 文件 (*.pem);;DER 文件 (*.der);;所有文件 (*)"));
    if (!fileName.isEmpty()) {
        ui->aeaPublicLineEdit->setText(fileName);
    }
}


void MainWindow::on_aeaDataToolButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("选择数据文件"), 
                            ui->aeaDataLineEdit->text(), 
                            tr("数据文件 (*.dat *.txt);;所有文件 (*)"));
    if (!fileName.isEmpty()) {
        ui->aeaDataLineEdit->setText(fileName);
    }
}

void MainWindow::on_aeaEncryptPushButton_clicked()
{
    QByteArray data = getData(ui->aeaDataFileCheckBox->isChecked(), 
        ui->aeaDataLineEdit->text(), false);
    QSslKey publicKey = m_openSSLHelper->loadPublicKey(ui->aeaPublicLineEdit->text());
    if (publicKey.isNull())
        publicKey = QSslKey(QByteArray::fromHex(
            ui->aeaPublicLineEdit->text().toUtf8()), QSsl::Rsa, QSsl::Der, QSsl::PublicKey);
    if (publicKey.isNull())
        publicKey = QSslKey(QByteArray::fromHex(
            ui->aeaPublicLineEdit->text().toUtf8()), QSsl::Ec, QSsl::Der, QSsl::PublicKey);

    QByteArray encrypt = m_openSSLHelper->asymmetricEncrypt(data, publicKey);
    qDebug() << "encrypt" << encrypt.toHex() << "publicKey" << publicKey << "data" << data;
    if (!encrypt.isEmpty()) {
        ui->aeaEncryptLineEdit->setText(encrypt.toHex().toUpper());
        QMessageBox::information(this, tr("提示"), tr("加密成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("加密失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }
}


void MainWindow::on_aeaDecryptPushButton_clicked()
{
    QByteArray data = getData(ui->aeaDataFileCheckBox->isChecked(), 
        ui->aeaEncryptLineEdit->text(), ui->aeaBase64CheckBox->isChecked());
    QSslKey privateKey = m_openSSLHelper->loadPrivateKey(ui->aeaPrivateLineEdit->text());
    if (privateKey.isNull())
        privateKey = QSslKey(QByteArray::fromHex(
            ui->aeaPrivateLineEdit->text().toUtf8()), QSsl::Rsa, QSsl::Der);
    if (privateKey.isNull())
        privateKey = QSslKey(QByteArray::fromHex(
            ui->aeaPrivateLineEdit->text().toUtf8()), QSsl::Ec, QSsl::Der);

    QByteArray decrypt = m_openSSLHelper->asymmetricDecrypt(data, privateKey);
    qDebug() << "decrypt" << decrypt.toHex() << "privateKey" << privateKey << "data" << data;
    if (!decrypt.isEmpty()) {
        ui->aeaDecryptLineEdit->setText(decrypt.toHex().toUpper());
        QMessageBox::information(this, tr("提示"), tr("解密成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("解密失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }
}


void MainWindow::on_aeaDigestPushButton_clicked()
{
    bool inBase64 = ui->aeaBase64CheckBox->isChecked();
    QString hashAlgo = ui->aeaDigestComboBox->currentText();
    QByteArray data = getData(ui->aeaDataFileCheckBox->isChecked(), 
        ui->aeaDataLineEdit->text(), inBase64);
    QByteArray digest = m_openSSLHelper->digest(data, hashAlgo);

    qDebug() << "hashAlgo" << hashAlgo << "digest" << digest.toHex();
    if (!digest.isEmpty()) {
        if (inBase64) {
            ui->aeaDigestLineEdit->setText(digest.toBase64());
        } else {
            ui->aeaDigestLineEdit->setText(digest.toHex().toUpper());
        }
        QMessageBox::information(this, tr("提示"), tr("摘要生成成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("摘要生成失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }
}

void MainWindow::on_aeaDigestComboBox_currentTextChanged(const QString &arg1)
{
    bool visible = arg1.contains("SM3");
    ui->aeaUserIdLabel->setVisible(visible);
    ui->aeaUserIdLineEdit->setVisible(visible);
    ui->aeaUserIdIsHexCheckBox->setVisible(visible);
}


void MainWindow::on_aeaSignPushButton_clicked()
{
    bool inBase64 = ui->aeaBase64CheckBox->isChecked();
    QSslKey privateKey = m_openSSLHelper->loadPrivateKey(ui->aeaPrivateLineEdit->text());
    if (privateKey.isNull())
        privateKey = QSslKey(QByteArray::fromHex(
            ui->aeaPrivateLineEdit->text().toUtf8()), QSsl::Rsa, QSsl::Der);
    if (privateKey.isNull())
        privateKey = QSslKey(QByteArray::fromHex(
            ui->aeaPrivateLineEdit->text().toUtf8()), QSsl::Ec, QSsl::Der);


    QString hashAlgo = ui->aeaDigestComboBox->currentText();
    QByteArray userid = (ui->aeaUserIdIsHexCheckBox->isChecked())
                         ? QByteArray::fromHex(ui->aeaUserIdLineEdit->text().toUtf8())
                         : ui->aeaUserIdLineEdit->text().toUtf8();
    QByteArray data = getData(ui->aeaDataFileCheckBox->isChecked(), 
        ui->aeaDataLineEdit->text(), inBase64);
    QByteArray digest = (inBase64)
                         ? QByteArray::fromBase64(ui->aeaDigestLineEdit->text().toUtf8())
                         : QByteArray::fromHex(ui->aeaDigestLineEdit->text().toUtf8());
    QByteArray sign = (!digest.isEmpty())
                       ? m_openSSLHelper->signDigest(digest, privateKey, hashAlgo, userid)
                       : m_openSSLHelper->signData(data, privateKey, hashAlgo, userid);
    //QByteArray sign = m_openSSLHelper->signData(data, privateKey, hashAlgo, userid);

    qDebug() << "hashAlgo" << hashAlgo << "digest" << digest.toHex()
             << "sign" << sign.toHex();

    if (!sign.isEmpty()) {
        if (inBase64) {
            ui->aeaSignLineEdit->setText(sign.toBase64());
        } else {
            ui->aeaSignLineEdit->setText(sign.toHex().toUpper());
        }
        QMessageBox::information(this, tr("提示"), tr("签名成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("签名失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }
}

void MainWindow::on_aeaVerifySignPushButton_clicked()
{
    bool inBase64 = ui->aeaBase64CheckBox->isChecked();
    QByteArray origin = QByteArray::fromHex(
                ui->aeaPublicLineEdit->text().toUtf8());
    if (ui->aeaDigestComboBox->currentText().contains("SM3"))
        origin = m_openSSLHelper->sm2PubKeyToDer(origin);

    QSslKey publicKey = QSslKey(origin, QSsl::Ec, QSsl::Der, QSsl::PublicKey);
    QString hashAlgo = ui->aeaDigestComboBox->currentText();
    QByteArray userid = (ui->aeaUserIdIsHexCheckBox->isChecked())
                         ? QByteArray::fromHex(ui->aeaUserIdLineEdit->text().toUtf8())
                         : ui->aeaUserIdLineEdit->text().toUtf8();
    QByteArray data = getData(ui->aeaDataFileCheckBox->isChecked(), 
        ui->aeaDataLineEdit->text(), inBase64);
    QByteArray sign = (inBase64)
                       ? QByteArray::fromBase64(ui->aeaSignLineEdit->text().toUtf8())
                       : QByteArray::fromHex(ui->aeaSignLineEdit->text().toUtf8());

    if (ui->aeaDigestComboBox->currentText().contains("SM3"))
        sign = m_openSSLHelper->sm2SignToDer(sign);

    qDebug() << "data" << data << "publicKey" << publicKey.toDer().toHex().toUpper()
             << "sign" << sign.toHex().toUpper() << "userid" << userid;
    bool success = m_openSSLHelper->signVerify(data, sign, publicKey, hashAlgo, userid);
    if (success) {
        QMessageBox::information(this, tr("提示"), tr("验签成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("验签失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }
}


// 对称加密算法
void MainWindow::on_seaDataToolButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("选择数据文件"), 
                            ui->seaDataLineEdit->text(), 
                            tr("数据文件 (*.dat *.txt);;所有文件 (*)"));
    if (!fileName.isEmpty()) {
        ui->seaDataLineEdit->setText(fileName);
    }
}


void MainWindow::on_seaEncryptToolButton_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("选择加密后输出文件"), 
                            ui->seaEncryptLineEdit->text(), 
                            tr("加密数据 (*.enc *.bin);;所有文件 (*)"));
    if (!fileName.isEmpty()) {
        ui->seaEncryptLineEdit->setText(fileName);
    }
}


void MainWindow::on_seaDecryptToolButton_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("选择解密后输出文件"), 
                            ui->seaDecryptLineEdit->text(), 
                            tr("解密数据 (*.dat *.txt);;所有文件 (*)"));
    if (!fileName.isEmpty()) {
        ui->seaDecryptLineEdit->setText(fileName);
    }
}

void MainWindow::on_seaEncryptPushButton_clicked()
{
    bool isFile = ui->seaDataFileCheckBox->isChecked();
    bool inBase64 = ui->seaBase64CheckBox->isChecked();
    bool isAes = ui->seaAlgoComboBox->currentText().contains("AES");
    OpenSSLHelper::SymMode mode 
        = OpenSSLHelper::symModeFromName(ui->seaEncryptModeComboBox->currentText());
    QByteArray data = getData(isFile, ui->seaDataLineEdit->text(), false);
    QByteArray iv = QByteArray::fromHex(ui->seaIvLineEdit->text().toUtf8());
    QByteArray key = QByteArray::fromHex(ui->seaKeyLineEdit->text().toUtf8());
    qDebug() << "key" << key.toHex() << "iv" << iv.toHex() << "data" << data.toHex();

    QByteArray encrypt = isAes
        ? m_openSSLHelper->aesEncrypt(data, key, mode, iv)
        : m_openSSLHelper->sm4Encrypt(data, key, mode, iv);
    qDebug() << "encrypt" << encrypt.toHex();
    if (!encrypt.isEmpty()) {
        if (inBase64)
            encrypt = encrypt.toBase64();
        if (isFile) {
            QFile file(ui->seaEncryptLineEdit->text());
            if (file.open(QIODevice::WriteOnly))
                file.write(encrypt);
            file.close();
        }
        if (!isFile) {
            if (inBase64)
                ui->seaEncryptLineEdit->setText(encrypt);
            else
                ui->seaEncryptLineEdit->setText(encrypt.toHex().toUpper());
        }
        QMessageBox::information(this, tr("提示"), tr("加密成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("加密失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }
}


void MainWindow::on_seaDecryptPushButton_clicked()
{
    bool isFile = ui->seaDataFileCheckBox->isChecked();
    bool inBase64 = ui->seaBase64CheckBox->isChecked();
    bool isAes = ui->seaAlgoComboBox->currentText().contains("AES");
    OpenSSLHelper::SymMode mode 
        = OpenSSLHelper::symModeFromName(ui->seaEncryptModeComboBox->currentText());
    QByteArray iv = QByteArray::fromHex(ui->seaIvLineEdit->text().toUtf8());
    QByteArray key = QByteArray::fromHex(ui->seaKeyLineEdit->text().toUtf8());
    QByteArray data = getData(isFile, ui->seaEncryptLineEdit->text(), inBase64);
    qDebug() << "key" << key.toHex() << "data" << data.toHex();

    QByteArray decrypt = isAes
        ? m_openSSLHelper->aesDecrypt(data, key, mode)
        : m_openSSLHelper->sm4Decrypt(data, key, mode, iv);
    qDebug() << "decrypt" << decrypt.toHex();
    if (!decrypt.isEmpty()) {
        if (isFile) {
            QFile file(ui->seaDecryptLineEdit->text());
            if (file.open(QIODevice::WriteOnly))
                file.write(decrypt);
            file.close();
        }
        if (!isFile) {
            if (inBase64)
                ui->seaDecryptLineEdit->setText(decrypt.toBase64());
            else
                ui->seaDecryptLineEdit->setText(decrypt.toHex().toUpper());
        }
        QMessageBox::information(this, tr("提示"), tr("解密成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("解密失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }
}


void MainWindow::on_seaEncryptModeComboBox_currentTextChanged(const QString &arg1)
{
    bool visible = !arg1.contains("ECB");
    ui->seaIvLabel->setVisible(visible);
    ui->seaIvLineEdit->setVisible(visible);

    if (arg1.contains("GCM"))
        ui->seaIvLineEdit->setText("000000000000000000000000");
    else
        ui->seaIvLineEdit->setText("00000000000000000000000000000000");
}


void MainWindow::on_seaKeyLineEdit_textChanged(const QString &arg1)
{
    int i = 0;
    QByteArray key = QByteArray::fromHex(arg1.toUtf8());

    for (i = 0; i < ui->seaKeyBitsComboBox->count() - 1; ++i) {
        int bits = ui->seaKeyBitsComboBox->itemData(i).toInt();
        if (key.size() * 8 == bits) {
            ui->seaKeyBitsComboBox->setCurrentIndex(i);
            break;
        }
    }
    if (i >= (ui->seaKeyBitsComboBox->count() - 1)) {
        ui->seaKeyBitsComboBox->setCurrentIndex(i);
    }
}


void MainWindow::on_seaAlgoComboBox_currentTextChanged(const QString &arg1)
{
    if (arg1.contains("AES")) {
        ui->seaKeyBitsComboBox->setVisible(true);
    } else {
        ui->seaKeyBitsComboBox->setVisible(false);
    }
}


void MainWindow::on_aes128cmacPushButton_clicked()
{
    QByteArray key = QByteArray::fromHex(ui->seaKeyLineEdit->text().toUtf8());
    QByteArray data = QByteArray::fromHex(ui->seaDataLineEdit->text().toUtf8());
    qDebug() << "key" << key.toHex() << "data" << data.toHex();

    QByteArray encrypt = m_openSSLHelper->aes128GenerateCMAC(data, key);
    qDebug() << "encrypt" << encrypt.toHex();
    if (!encrypt.isEmpty()) {
        ui->seaEncryptLineEdit->setText(encrypt.toHex().toUpper());
        QMessageBox::information(this, tr("提示"), tr("计算成功！\t"), QMessageBox::Ok);
    } else {
        QMessageBox::critical(this, tr("错误"), 
            tr("计算失败(%1)！\t").arg(m_openSSLHelper->lastErrors()));
    }

}

