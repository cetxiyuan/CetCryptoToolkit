#ifndef CETTOOLPLUGINCONTEXT_H
#define CETTOOLPLUGINCONTEXT_H

#include "cetlicenseinterface.h"
#include "cetlogmanagerinterface.h"
#include "cetprogressinterface.h"
#include "cetupdateinterface.h"

#include <QWidget>
#include <QMenu>
#include <functional>

class QMainWindow;

// 与 productwizard.h 保持一致的导出宏（避免重复定义）
#ifndef PRODUCTWIZARD_EXPORT
    #ifndef QT_STATIC
        #if defined(BUILD_PRODUCTWIZARD_LIB)
        #define PRODUCTWIZARD_EXPORT Q_DECL_EXPORT
        #else
        #define PRODUCTWIZARD_EXPORT Q_DECL_IMPORT
        #endif
    #else
        #define PRODUCTWIZARD_EXPORT
    #endif
#endif

class PRODUCTWIZARD_EXPORT CetToolPluginContext : public QWidget
{
    Q_OBJECT
public:
    // selfHash: HASH_CetProductWizard_DLL，由调用方编译进 exe，防止 DLL 被替换
    explicit CetToolPluginContext(const QString &selfHash, QWidget *parent = nullptr);
    ~CetToolPluginContext();

    // 加载所有功能插件（替代各项目的 initFeaturesPlugin）
    void initFeatures(QMenu *logManagerMenu,
                      QMenu *licenseMenu,
                      const QString &productName,
                      const QString &versionTitle,
                      const QString &appName,
                      const QString &appVersion,
                      std::function<void(bool activated)> onActivated = nullptr);

    // 接口访问器
    CetLogManagerInterface *logManager() const { return m_cetLogManagerInterface; }
    CetLicenseInterface  *license()   const { return m_cetLicenseInterface; }
    CetUpdateInterface   *updater()   const { return m_cetUpdateInterface; }
    CetProgressInterface *progress()  const { return m_cetProgressInterface; }

    // 带完整性校验的插件加载
    QObject *loadPlugin(const QString &dllName, QString *errInfo = nullptr);

private:
    static bool selfIntegrityCheck(const QString &expectedHash);

    bool m_integrityOk;
    CetLogManagerInterface *m_cetLogManagerInterface = nullptr;
    CetLicenseInterface    *m_cetLicenseInterface    = nullptr;
    CetUpdateInterface     *m_cetUpdateInterface     = nullptr;
    CetProgressInterface   *m_cetProgressInterface   = nullptr;
};

#endif // CETTOOLPLUGINCONTEXT_H
