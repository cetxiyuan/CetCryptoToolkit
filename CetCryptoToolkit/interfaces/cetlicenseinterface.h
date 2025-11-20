#ifndef CETLICENSEINTERFACE_H
#define CETLICENSEINTERFACE_H

#include <QObject>
#include <QString>

class CetLicenseInterface
{
public:
    virtual ~CetLicenseInterface() { }
    enum AcitavteResult { 
        ACTIVATE_CANCEL = 0,    /**< 激活取消 */
        ACTIVATE_OK,            /**< 激活成功 */
        ACTIVATE_ER             /**< 激活失败 */
    };

    virtual void initialize(const QString &productId) = 0;  /* 通过产品ID激活设备 */
    virtual int activate() = 0;                                /* 通过非窗口激活设备 */
    virtual int activateWindow() = 0;                          /* 通过激活窗口激活设备 */
    virtual QString resultString() = 0;                        /* 激活结果描述 */
    virtual QString solidKey() = 0;                            /* 产品固钥 */
};

Q_DECLARE_INTERFACE(CetLicenseInterface, "org.qter.plugin.CetLicenseInterface")

#endif // CETLICENSEINTERFACE_H
