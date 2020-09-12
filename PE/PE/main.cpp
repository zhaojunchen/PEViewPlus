#include "pch.h"
#include "PE.h"

void myclock(clock_t startTime) {
	cout << "The run time is: " << (double)(clock() - startTime) / CLOCKS_PER_SEC << "s" << endl;
}

// 四列测试
void test(Node* node) {
	if (node->hasDesc) {
		Q_ASSERT(node->addr.size() == node->data.size() && node->desc.size() == node->value.size() && node->addr.size() == node->value.size());
		cout << node->addr.size() << " " << node->data.size() << " " << node->desc.size() << node->value.size();
		for (int i = 0; i < node->addr.size(); i++) {
			cout << node->addr[i] << "\t" << node->data[i] << "\t" << node->desc[i] << "\t" << node->value[i];
		}
	} else {
		Q_ASSERT(node->addr.size() == node->data.size() && node->data.size() == node->value.size());
		for (int i = 0; i < node->addr.size(); i++) {
			cout << node->addr[i] << "\t" << node->data[i] << "\t" << node->value[i];
		}
	}
}

int main(int argc, char *argv[]) {
	QCoreApplication a(argc, argv);
	clock_t startTime = clock();

	//QString file = "C:\\Users\\zjc98\\Desktop\\leetcode32R.exe";
	//QString file = "C:\\Users\\zjc98\\Desktop\\twain_32.dll";
	QString file = "C:\\Users\\zjc98\\Desktop\\proj4.dll";
	PE pe(file);
	//for (auto it : pe.treeList) {
	//	cout << it;
	//}
	//QVector<Node*> nodes;
	//init_pe_allnodes(pe, nodes);

	// pe.init_section(); 但是节之间存在更多的node 比如说IAT之类的

	//auto what = pe.init_edata();
	////test4(p);
	//// auto what = pe.init_section_header();
	//for (auto item : pe.init_rdata()) {
	//	test(item);
	//}

	myclock(startTime);

	// testNode(pe_file);
	//testNode(pe_dos_stub);
	//testNode(pe_nt);
	///*for (int i = 0; i < pe_section_header.size(); i++) {
	//	testNode(pe_section_header[i]);
	//}*/

	cout << "\n----bend debug\n";
	exit(0);

	return a.exec();
}

//cout << pe.file_size << "   " << (double)pe.file_size / 16 << "\n\n\n";
//
//auto pe_file = pe.init_pe_file();
//auto pe_dos_stub = pe.init_dos_stub();
//auto pe_nt = pe.init_nt_header();
//auto pe_section_header = pe.init_section();
//auto pe_section = pe.init_section();