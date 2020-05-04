#ifndef TREEDATA_H
#define TREEDATA_H
#include<QString>
#ifndef _WIN64
// 32 bits!
class TreeData{
public:
    TreeData(QString _file);
    ~TreeData();

};
#else // ifndef _WIN64

#endif // ifndef _WIN64


#endif // TREEDATA_H
