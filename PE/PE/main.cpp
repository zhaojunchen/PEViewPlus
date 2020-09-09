#include "pch.h"
#include "PE.h"
void test(Node*node) {
	int size = node->addr.size();
	cout << node->head;
	for (int i = 0; i < size; i++) {
		cout << node->addr[i] << "\t" << node->data[i] << "\t" << node->value[i];
	}
}
void testNode(Node*pe_file) {
	cout << pe_file->addr.size() << " " << pe_file->data.size() << " " << pe_file->value.size();
	Q_ASSERT(pe_file->addr.size() == pe_file->data.size() && pe_file->data.size() == pe_file->value.size());

	test(pe_file);
}

void myclock(clock_t startTime) {
	cout << "The run time is: " << (double)(clock() - startTime) / CLOCKS_PER_SEC << "s" << endl;
}
int main(int argc, char *argv[]) {
	QCoreApplication a(argc, argv);
	clock_t startTime = clock();

	QString file = "C:\\Users\\zjc98\\Desktop\\leetcode32R.exe";
	PE pe(file);
	cout << pe.file_size << "   " << (double)pe.file_size / 16 << "\n\n\n";

	auto pe_file = pe.init_pe_file();
	auto pe_dos_stub = pe.init_dos_stub();
	auto pe_nt = pe.init_nt_header();
	auto pe_section_header = pe.init_section();
	auto pe_section = pe.init_section();
	myclock(startTime);

	// testNode(pe_file);
	//testNode(pe_dos_stub);
	//testNode(pe_nt);
	///*for (int i = 0; i < pe_section_header.size(); i++) {
	//	testNode(pe_section_header[i]);
	//}*/
	for (int i = 0; i < pe_section.size(); i++) {
		testNode(pe_section[i]);
	}

	cout << "\n----bend debug\n";
	exit(0);

	return a.exec();
}