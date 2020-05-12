#include <QtCore/QCoreApplication>
#include "PEAnalysis.h"
#include "tools.h"
int main(int argc, char *argv[]) {
	QCoreApplication a(argc, argv);
	/*Write your code*/
	// 初始化desc

	QVector<QByteArray> t = init("C:/test.exe");
	// init_listView();
	details detail = init_dosHeader(0x400000, t[1]);
	for (int i = 0; i < detail.va.size(); ++i) {
		qDebug() << detail.va[i] << "\t " << detail.data[i] << "\t" << detail.desc[i];
	
		
		/*qDebug("%s %s %s", detail.va[i], detail.data[i], detail.desc[i]);*/
		
	}
	
	

	exit(0);

	return a.exec();
}

/**
 * //cout << endl << t.size();
	//for (auto element : t) {
	//	show(element.data(), 0x100);
	//}
	// QString QString::number ( long n, int base = 10 )
	QString k = QString::number(100, 16).toUpper();
	// show(t[0].data(), 100);
	// 如何显示rawdata 将Qbytearray转化为 t[0].toHex(' ').toUpper(); 间隔输出
	// cout << t[0].toHex(' ').toUpper();

	/*QString str1 = QString("%1").arg(12, 4, 16, QChar('0')).toUpper();
	cout << str1;
show(t[0].data(), 20);

QString s;
s.reserve(t[0].size());
char space = '.';
for (int i = 0; i < t[0].size(); ++i) {
	char ch = t[0].at(i);

	if (ch >= 0x20 && ch <= 0x7E) {
		s.append(ch);
	} else {
		s.append(space);
	}
}

cout << s;

 */