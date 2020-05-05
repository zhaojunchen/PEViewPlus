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

**解决方案**

1. PE浏览使用Qt代码实现
2. 浏览修改权限使用Qt代码实现
3. 浏览修改安全选项使用Qt代码实现

5. PE文件注入使用纯Vs编写
6. OEP和ImageBase使用纯VS编写

8. 通过调用vs dll的方式实现shellcode的进程注入！需要在vs引入反汇编
9. 代码节的反汇编 通过Qt或者Vs dll（返回string） 实现



**小提示**

1.  PE文件浏览 n 判断文件类型32位/64位
2.  内存注入和文件注入 n 判断文件类型32位/64位
3. Inline Hooking n 识别函数头部代码长度 capstone-  www.capstone-engine.org  cuckoo-cuckoosandbox.org

## 代码编写

- c++对象序列化

  [https://www.cnblogs.com/mmc1206x/p/11053826.html](https://www.cnblogs.com/mmc1206x/p/11053826.html)
  
- 类型转换

  1. `QByteArray`转化为`QString 16进制`

     ```
     QByteArray::toHex(' ').toUpper(); // 大写带空格间隔  用于原始数据的输出
     ```

  2. 整数转换转化为16进制

     ```
     QString str1 = QString("%1").arg(12, 4, 16, QChar('0')).toUpper();
     ```

  3. `QByteArray`转化为`QString` 可打印字符

     ```
     	QString s;
     	s.reserve(t[0].size());
     	char space = '.';
     	for (int i = 0; i < t[0].size(); ++i) {
     		char ch = t[0].at(i);
     		if (ch>= 0x20 && ch <= 0x7E) {
     			s.append(ch);
     		}else {
     			s.append(space);
     		}
     	}
     ```

     

  

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
// for vs and qt project 注意是单个_WIN64
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



