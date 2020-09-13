#include "mainwindow.h"

int main(int argc, char *argv[])
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif // if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))


    QApplication a(argc, argv);
    MainWindow   w;
    DWORD pid = GetCurrentProcessId();
    cout << "Process pid is " << pid;
    w.setWindowTitle("PEViewPlus");
    w.show();
    return a.exec();
}
