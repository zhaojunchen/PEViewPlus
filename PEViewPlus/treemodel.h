#ifndef TREEMODEL_H
#define TREEMODEL_H


class TreeItem;

// ! [0]
class TreeModel : public QAbstractItemModel {
    Q_OBJECT

public:

    /**
     * @brief TreeModel     输入字符串，构造所有的树的节点
     * @param data          输入的字符串
     * @param parent        父节点
     */
    explicit TreeModel(const QString& data,
                       QObject       *parent = nullptr);
    ~TreeModel();

    /**
     * @brief data      返回QModelIndex这个节点的数据
     * @param index
     * @param role      每一项的数据节点
     * @return
     */
    QVariant      data(const QModelIndex& index,
                       int                role) const override;
    Qt::ItemFlags flags(const QModelIndex& index) const override;
    QVariant      headerData(int             section,
                             Qt::Orientation orientation,
                             int             role = Qt::DisplayRole) const
    override;
    QModelIndex index(int                row,
                      int                column,
                      const QModelIndex& parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex& index) const override;

    /**
     * @brief rowCount  返回QModelIndex的行数  默认为QModelIndex()即是树的根节点
     * @param parent    父节点下的行数
     * @return
     */
    int         rowCount(const QModelIndex& parent = QModelIndex()) const
    override;

    /**
     * @brief columnCount   QModelIndex的列数 最简单的就是2列
     * @param parent
     * @return
     */
    int columnCount(const QModelIndex& parent = QModelIndex()) const
    override;

private:

    /**
     * @brief setupModelData    初始化数组
     * @param lines
     * @param parent
     */
    void setupModelData(const QStringList& lines,
                        TreeItem          *parent);

    TreeItem *rootItem;
};

// ! [0]

#endif // TREEMODEL_H
