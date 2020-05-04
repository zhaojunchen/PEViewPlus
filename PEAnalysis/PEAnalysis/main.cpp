#include <QtCore/QCoreApplication>
#include "PEAnalysis.h"
#include "tools.h"
int main(int argc, char *argv[]) {
	QCoreApplication a(argc, argv);
	/*Write your code*/

	QVector<QByteArray> t = init("C:/test.exe");
	cout << endl << t.size();
	for (auto element : t) {
		cout << "\nsegement";
		show(element.data(), 20);
		
	}
	exit(0);

	return a.exec();
}