#include "TreeData.h"
#include <string>
#include "tool.cpp"
using std::string;

#ifndef _WIN64

// 32 bits!

// string s = qstr.toStdString(); && QString qstr2 = QString::fromStdString(s);


TreeData::TreeData(QString _file) {
    string file = _file.toStdString();
    uint8_t *c = "wuhandaxada";
    show()

}

#else // ifndef _WIN64
// do nothing

#endif // ifndef _WIN64
