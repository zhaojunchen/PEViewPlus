#pragma once
#include <qstring.h>
#include <qstringlist.h>

class Info {
public:
	int type;// 0
	Info(int _type = 0) :type(_type) {
	}
	~Info() {}
};
class detail :Info {
public:
	QStringList Va;
	QStringList Data;
	QStringList Description;
	QStringList Value;
	detail() :Info(0) {}
	~detail() {}
};

class brief:Info {
public:
	QStringList Va;
	QStringList RawData;
	QStringList Value;
	brief() :Info(1) {}
	~brief() {}
};
