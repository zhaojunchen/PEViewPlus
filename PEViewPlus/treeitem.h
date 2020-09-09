#ifndef TREEITEM_H
#define TREEITEM_H


// ! [0]
class TreeItem {
public:

    // data parent

    /**
     * @brief TreeItem      添加一个树形节点元素
     * @param data          添加数据元素类型为QVector类型
     * @param parentItem    新建节点的父节点
     */
    explicit TreeItem(const QVector<QVariant>& data,
                      TreeItem                *parentItem = nullptr);
    ~TreeItem();

    /**
     * @brief appendChild   节点添加父节点
     * @param child         将child节点作为this的子节点
     */
    void      appendChild(TreeItem *child);

    /**
     * @brief child     返回this的父节点
     * @param row       子节点的编号（按照行的顺序排列）
     * @return
     */
    TreeItem* child(int row);

    /**
     * @brief childCount    返回this的子节点数目
     * @return
     */
    int       childCount() const;

    /**
     * @brief columnCount   this的data部分（QVector的size值）
     * @return
     */
    int       columnCount() const;

    /**
     * @brief data      返回data的某一个index
     * @param column    column index
     * @return          返回QVar
     */
    QVariant  data(int column) const;

    /**
     * @brief row   当前节点相对于父节点的row（行号） index
     * @return      返回显示index
     */
    int       row() const;

    /**
     * @brief parentItem    返回当前节点的父节点
     * @return
     */
    TreeItem* parentItem();

private:

    QVector<TreeItem *>m_childItems;
    QVector<QVariant>m_itemData;
    TreeItem *m_parentItem;
};

// ! [0]

#endif // TREEITEM_H
