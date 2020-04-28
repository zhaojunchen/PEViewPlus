#include "mainwindow.h"
#include <QApplication>
#include <QDebug>
#include<iostream>
using namespace  std;

namespace x64 {
    static int i = 0;
}
namespace x32 {
    static int i = 1;
}
int main(int argc, char *argv[])
{
#if (QT_VERSION >= QT_VERSION_CHECK(5,9,0))
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

#ifdef X64
    using namespace x64;
#else
    using namespace x32;
#endif

    QString str = "winds";
    qDebug() << str;
    qint32 j = i;
    qDebug()<<j;




    return a.exec();
}
