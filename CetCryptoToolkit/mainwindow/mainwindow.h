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

private slots:
    void on_outputDirToolButton_clicked();

    void on_certTypeComboBox_currentTextChanged(const QString &arg1);

    void on_genCertPushButton_clicked();

private:
    QObject *loadPlugin(const QString &dllName);
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
};
#endif // MAINWINDOW_H
