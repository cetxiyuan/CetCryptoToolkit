#include "mainwindow.h"

#include <QApplication>
#include <QTextCodec>
#include <QStyleFactory>

int main(int argc, char *argv[])
{
    /* 支持程序支持高分辨率自动调整 */
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    /* 设置高 DPI 缩放因子的四舍五入策略 */
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

    QTextCodec::setCodecForLocale(QTextCodec::codecForLocale());
    QStringList list = QStyleFactory::keys();
    QApplication::setStyle(QStyleFactory::create(list.last()));

    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
