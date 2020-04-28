#include "mainwindow.h"
#include <QApplication>
#include <QDebug>

int main(int argc, char *argv[])
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif // if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))


    QApplication a(argc, argv);
    MainWindow   w;
    QString ab = "123";
    qDebug() << ab;
    qint32 i = 0;

#ifdef WIN64
    i = 1;
#else // ifdef WIN64
    i = 2;
#endif // ifdef WIN64

    qDebug() << i;

    w.show();


    return a.exec();
}
