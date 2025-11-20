#ifndef PRODUCTWIZARD_H
#define PRODUCTWIZARD_H

#include <QDialog>
#include <QGridLayout>
#include <QCheckBox>
#include <QSettings>

QT_BEGIN_NAMESPACE

#ifndef QT_STATIC
    #if defined(BUILD_PRODUCTWIZARD_LIB)
    #define PRODUCTWIZARD_EXPORT Q_DECL_EXPORT
    #else
    #define PRODUCTWIZARD_EXPORT Q_DECL_IMPORT
    #endif
#else
    #define PRODUCTWIZARD_EXPORT
#endif

namespace Ui {
class ProductWizard;
}

class Reward;

class PRODUCTWIZARD_EXPORT ProductWizard : public QDialog
{
    Q_OBJECT

public:
    explicit ProductWizard(const QString &name, QLayout *layout, QWidget *parent = nullptr);
    ~ProductWizard();
    int exec();
    static void addItem(bool displayable, const QString &text, 
        QAction *act1, QAction *act2 = nullptr, QAction *act3 = nullptr);
    static void addItem(bool displayable, const QString &text, 
        QWidget *wgt1, QWidget *wgt2 = nullptr, QWidget *wgt3 = nullptr);
    static void addItems(bool displayable, const QString &text, QList<QAction *> &actions);
    static void addItems(bool displayable, const QString &text, QList<QWidget *> &widgets);
    static QGridLayout *wizardLayout();

private:
    enum Type {
        TYPE_BASICS = 0,     /**< 基础版 */
        TYPE_CUSTOM,         /**< 定制版 */
        TYPE_FULLFUNC,       /**< 全功能版 */
    };
    struct ItemMember {
        ItemMember() : checkBox(nullptr), objects()    { }
        QCheckBox *checkBox;
        QList<QObject *> objects;
        int isActions       : 1;
        int isWidgets       : 1;
        int isDisplayable   : 1;
    };
    static void addItem_helper(bool displayable, const QString &text, struct ItemMember &item);

Q_SIGNALS:
    void itemsDisabled(QList<QObject *> items);

private slots:
    void on_okButton_clicked();

    void on_basicsRadioButton_clicked();

    void on_customRadioButton_clicked();

    void on_fullFuncRadioButton_clicked();

    void on_fullFuncPasswordLineEdit_textChanged(const QString &arg1);

    void on_selectAllCheckBox_stateChanged(int arg1);

private:
    Ui::ProductWizard *ui;
    QSettings *const m_settings;
    Reward *const m_reward;
    static QGridLayout *m_gridLayout;
    static QList<struct ItemMember> m_items;
};

QT_END_NAMESPACE

#endif // PRODUCTWIZARD_H
