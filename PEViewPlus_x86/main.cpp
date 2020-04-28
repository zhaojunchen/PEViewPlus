#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
#if (QT_VERSION >= QT_VERSION_CHECK(5,9,0))
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif

//#ifdef X64
//    using namespace x64;
//#else
//    using namespace x86;
//#endif
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
