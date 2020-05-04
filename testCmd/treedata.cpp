#include "TreeData.h"
#include <string>
#include "tool.cpp"
#include <windows.h>
#include <winnt.h>
#include <fstream>

using std::ifstream;
using std::ofstream;
using std::string;

using std::ios;



#ifndef _WIN64

// 32 bits!

// string s = qstr.toStdString(); && QString qstr2 = QString::fromStdString(s);


TreeData::TreeData(QString _file) {
    string file = _file.toStdString();

    // c++ open binary file
    ifstream f(file, ios::in | ios::binary);

    if (!f) {
        error("文件打开失败", __LINE__);
        exit(-1);
    }

    // 文件大小计算
    f.seekg(0, f.end);
    size_t fileSize = f.tellg();
    f.seekg(0, f.beg); // 定位到文件开始




}

TreeData::~TreeData() {}

#else // ifndef _WIN64
// do nothing

#endif // ifndef _WIN64
