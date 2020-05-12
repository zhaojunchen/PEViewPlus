#pragma once
#include <qstring.h>
#include <qstringlist.h>

class details {
public:
	bool type;// false is rawdata
	QStringList va;
	QStringList data;
	QStringList value;
	QStringList desc;
	details(bool _type = false) :type(_type) {}
	~details() {}
};
