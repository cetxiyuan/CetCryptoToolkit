#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "cetlogmanagerinterface.h"
#include "cetlicenseinterface.h"
#include "cetupdateinterface.h"
#include "cetprogressinterface.h"

#include "opensslhelper.h"
#include "certificatemanager.h"

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class QSettings;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void keyPressEvent(QKeyEvent *event);

private slots:
    void on_outputDirToolButton_clicked();

    void on_certTypeComboBox_currentTextChanged(const QString &arg1);

    void on_genCertPushButton_clicked();

    void on_aeaPrivateToolButton_clicked();

    void on_aeaPublicToolButton_clicked();

    void on_aeaDataToolButton_clicked();

    void on_aeaEncryptPushButton_clicked();

    void on_aeaDecryptPushButton_clicked();

    void on_aeaDigestPushButton_clicked();

    void on_aeaDigestComboBox_currentTextChanged(const QString &arg1);

    void on_aeaSignPushButton_clicked();

    void on_aeaVerifySignPushButton_clicked();

    void on_seaDataToolButton_clicked();

    void on_seaEncryptToolButton_clicked();

    void on_seaDecryptToolButton_clicked();

    void on_seaEncryptPushButton_clicked();

    void on_seaDecryptPushButton_clicked();

    void on_seaEncryptModeComboBox_currentTextChanged(const QString &arg1);

    void on_seaKeyLineEdit_textChanged(const QString &arg1);

    void on_seaAlgoComboBox_currentTextChanged(const QString &arg1);

    void on_aes128cmacPushButton_clicked();

private:
    QByteArray getData(bool isFile, const QString &fileName, bool inBase64 = false);

private:
    QObject *loadPlugin(const QString &dllName, QString *errInfo = nullptr);
    void initFeaturesPlugin();

private:
    Ui::MainWindow *ui;
    CetLogManagerInterface *m_cetLogManagerInterface;
    QSettings *const m_settings;
    OpenSSLHelper *const m_openSSLHelper;
    CertificateManager *const m_certManager;

    CetLicenseInterface *m_cetLicenseInterface;
    CetUpdateInterface *m_cetUpdateInterface;
    CetProgressInterface *m_cetProgressInterface;

    QSslKey m_privateKey;   // 非对称加密算法的私钥
    QSslKey m_publicKey;    // 非对称加密算法的公钥

};
#endif // MAINWINDOW_H
