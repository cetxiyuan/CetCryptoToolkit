#ifndef CETCANINTERFACE_H
#define CETCANINTERFACE_H

#include <QObject>
#include <cstdint>

class CetCANInterface
{
public:
    virtual ~CetCANInterface() { }
    virtual const char *pluginVersion() = 0;
    virtual void setControl(bool acc, bool ig, bool can) = 0;
    virtual void recv(int chanel, uint32_t canid, const uint8_t candata[8]) = 0;
    virtual void getSendData(int *chanel, uint32_t *canid, uint8_t candata[8]) = 0;
    virtual int getSendNum(void) = 0;
};

Q_DECLARE_INTERFACE(CetCANInterface, "org.qter.plugin.CetCANInterface")

#endif // CETCANINTERFACE_H
