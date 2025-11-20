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

    ui->certTypeComboBox->addItem(tr(TEXT_EndEntity));
    ui->certTypeComboBox->addItem(tr(TEXT_IntermediateCA));
    ui->certTypeComboBox->addItem(tr(TEXT_RootCACustom));
    ui->certTypeComboBox->addItem(tr(TEXT_RootCACetXiyuan));
    ui->certOutputDirLineEdit->setText(CAROOT_DEF_DIR);

    initFeaturesPlugin();

    connect(ui->certConfigureToolButton, &QToolButton::clicked, 
        m_certManager, &CertificateManager::show);
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
        //this->centralWidget()->setEnabled(activated);

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

void MainWindow::on_genCertPushButton_clicked()
{
    int index = ui->certTypeComboBox->currentIndex();
    QString outputDir = ui->certOutputDirLineEdit->text();

    m_certManager->genCertificate(index, outputDir);
}

