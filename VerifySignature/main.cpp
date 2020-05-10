#include <QtCore/QCoreApplication>
#include<qdebug.h>
#include<qfile.h>

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	qDebug() << "sfy";
	QFile peFile = QFile("d:test.exe");
	QByteArray peData = peFile.readAll();

	return a.exec();
}
