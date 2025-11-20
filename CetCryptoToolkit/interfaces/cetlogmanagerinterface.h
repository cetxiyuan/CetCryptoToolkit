#ifndef CETLOGMANAGERINTERFACE_H
#define CETLOGMANAGERINTERFACE_H

#include <QObject>

class CetLogManagerInterface
{
public:
    virtual ~CetLogManagerInterface() { }
    virtual void show() = 0; /**< 显示控制窗口 */
};

Q_DECLARE_INTERFACE(CetLogManagerInterface, "org.qter.plugin.CetLogManagerInterface")

#endif // CETLOGMANAGERINTERFACE_H
