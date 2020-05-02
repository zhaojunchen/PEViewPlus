# PEViewPlus

## 项目要求

**任务点**

1. 可以设计和实现一款PE文件浏览器。像PEview一样（图形界面）浏览所有PE结构(支持32位和64位)，包括但不限于 header, section table, section。
2. 浏览（修改）每一节的权限。 
3. 浏览（修改）编译器和OS支持的安全指示，如ASLR，DEP， stackguard, CFG等。
4. 浏览（修改）IAT、EAT、重定位表、资源节、异常表、证书表。
5. 对任意PE文件进行Shellcode注入，shellcode支持弹出计 算器、或显示“Injected”字符串。
6. 修改OEP或ImageBase等。 
7. 验证PE文件的签名。（可选） 
8. 支持对任意进程的任意函数进行hooking or in line hooking，Hooking后的shellcode支持弹出 CMD、或计算器、或一组文本字符串消息。（可选）
9. 支持代码节的反汇编（可选）。 
10. 关联重定位表项与代码中的重定位项位置（可选）

**小提示**

1.  PE文件浏览 n 判断文件类型32位/64位
2.  内存注入和文件注入 n 判断文件类型32位/64位
3. Inline Hooking n 识别函数头部代码长度 capstone-  www.capstone-engine.org  cuckoo-cuckoosandbox.org



## 界面设计

**界面分割操作**

```
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    
    setCentralWidget(ui->splitter_2);
}
// and in ui file splitter two widget
```



## 版本区分

```
#if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif // if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
```



```
// for vs and qt project
#ifdef _DEBUG
#ifndef _WIN64
#pragma comment(lib,"32bit_debug.lib")
#else
#pragma comment(lib,"64bit_debug.lib")
#endif
#else
#ifndef _WIN64
#pragma comment(lib,"32bit_release.lib")
#else
#pragma comment(lib,"64bit_release.lib")
#endif
#endif
```



## 参考资料

[1]: https://xz.aliyun.com/t/5753	"capstone"
[2]: https://blog.csdn.net/zhaobangyu/article/details/13023055?utm_source=distribute.pc_relevant.none-task-blog-baidujs-2	" 区分debug与release，32位与64位编译的宏定义"



