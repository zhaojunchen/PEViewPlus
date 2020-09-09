#ifndef DATA_H
#define DATA_H

class details {
public:

    bool type;    // type为fasle时 描述原始信息
    QString head; // 树节点的描述信息
    QStringList va;
    QStringList data;
    QStringList value;
    QStringList desc; // 描述l

    details(bool _type = false, QString _head = "") : type(_type), head(_head) {}

    ~details() {}
};

#endif // DATA_H
