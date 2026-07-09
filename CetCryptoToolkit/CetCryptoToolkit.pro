QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# 开启LOG显示文件名 行数等信息
DEFINES += QT_MESSAGELOGCONTEXT

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += main.cpp
HEADERS += version.h
INCLUDEPATH += \
        $$PWD/mainwindow \
        $$PWD/modules \
        $$PWD/interfaces \
        $$PWD/include \
        $$PWD/../../CetToolDLLs/CetToolPlugins

include ($$PWD/mainwindow/mainwindow.pri)
include ($$PWD/modules/modules.pri)
include ($$PWD/interfaces/interfaces.pri)

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32: LIBS += -L$$PWD/libs/ -lCetProductWizard -lcrypto-3 -lssl-3

RC_FILE += app.rc
