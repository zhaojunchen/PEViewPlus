#pragma once
#include "pch.h"
class Node {
public:
	QString head;
	QStringList addr;
	QStringList data;
	QStringList value;
	QStringList desc;
	bool isSubTreeNode;
	bool hasDesc;
	Node(QString _head, bool _hasDesc = false, bool  _isSubTreeNode = false) :head(_head), hasDesc(_hasDesc), isSubTreeNode(_isSubTreeNode) {}
	~Node() {}
};

class PE {
public:
	QString file_name;
	size_t file_size;
	const us*content;
	int startVA = 0;

	PIMAGE_DOS_HEADER dos_header;// size is sizeof(IMAGE_DOS_HEADER)
	// DosStud  is start at dos_header+sizeof(IMAGE_DOS_HEADER) size is (dos_header->e_lfanew-sizeof(IMAGE_DOS_HEADER))
	PIMAGE_NT_HEADERS32 nt_header;// (PIMAGE_NT_HEADERS32)((char*)dos_header+(dos_header->e_lfanew))
	PIMAGE_SECTION_HEADER section_header;

	PE(QString _file) :file_name(_file) {
		init(file_name);
	}
	// 使用pe文件 初始化PE类及其成员变量
	void init(const QString& _file) {
		const string file = _file.toStdString();

		ifstream in(file, ios::binary);

		if (!in) {
			perror("file open error");
			exit(-1);
		}

		in.seekg(0, in.end);
		this->file_size = in.tellg();
		in.seekg(0, in.beg); // 定位到文件开始
		us*file_content = new us[file_size];
		memset(file_content, 0, file_size);
		in.read(reinterpret_cast<char *>(file_content), file_size);
		in.close();
		this->content = file_content;
		bool ispe32 = isPE32(content);
		bool ispe64 = isPE64(content);

		if (!ispe32 && !ispe64) {
			error("文件类型错误");
		}
		if (ispe64) {
			error("文件打开方式错误 64位pe文件,请使用32位打开");
		}
		startVA = 0;
		// DOS HEADER
		dos_header = (PIMAGE_DOS_HEADER)content;
		// NT  HEADER
		nt_header = (PIMAGE_NT_HEADERS32)((char*)dos_header + (dos_header->e_lfanew));

		//nt_header->Signature;
		//nt_header->FileHeader
		//nt_header->OptionalHeader;

		auto size_nt_header = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
			nt_header->FileHeader.SizeOfOptionalHeader;

		auto numberOfSection = nt_header->FileHeader.NumberOfSections;

		section_header = (PIMAGE_SECTION_HEADER)((char*)nt_header + size_nt_header);
	}
	// 地址的偏移暂时实现VA和RVA_offset的显示
	// 初始化整个PE文件显示
	Node* init_pe_file() {
		Node* node = new Node(file_name, false, false);

		auto raw_offset = 0;
		auto raw_size = file_size;
		auto RVA_offset = raw_offset;
		auto RVA_size = raw_size;

		fillContent(node, raw_offset, raw_size, RVA_offset, startVA);
		return node;
	}
	// 初始化dos头显示
	Node*init_dos_header() {
		Node*node = new Node("IMAGE_DOS_HEADER", true, false);

		QStringList desc = { "Magic number","Bytes on last page of file","Pages in file","Relocations","Size of header in paragraphs","Minimum extra paragraphs needed","Maximum extra paragraphs needed","Initial (relative) SS value","Initial SP value","Checksum","Initial IP value","Initial (relative) CS value","File address of relocation table","Overlay number","Reserved words","Reserved words","Reserved words","Reserved words","OEM identifier (for e_oeminfo)","OEM information; e_oemid specific","Reserved words","Reserved words","Reserved words","Reserved words","Reserved words","Reserved words","Reserved words","Reserved words","Reserved words","Reserved words","File address of new exe header" };
		node->desc = desc;
		Q_ASSERT(node->desc.size() == 31);
		QVector<int> it_size;
		QVector<int> it_value;
		int RVA = startVA;
		it_size.reserve(31);
		it_size.reserve(31);

		auto it0 = dos_header->e_magic;
		auto it1 = dos_header->e_cblp;
		auto it2 = dos_header->e_cp;
		auto it3 = dos_header->e_crlc;
		auto it4 = dos_header->e_cparhdr;
		auto it5 = dos_header->e_minalloc;
		auto it6 = dos_header->e_maxalloc;
		auto it7 = dos_header->e_ss;
		auto it8 = dos_header->e_sp;
		auto it9 = dos_header->e_csum;
		auto it10 = dos_header->e_ip;
		auto it11 = dos_header->e_cs;
		auto it12 = dos_header->e_lfarlc;
		auto it13 = dos_header->e_ovno;
		auto it14 = dos_header->e_res[0];
		auto it15 = dos_header->e_res[1];
		auto it16 = dos_header->e_res[2];
		auto it17 = dos_header->e_res[3];

		auto it18 = dos_header->e_oemid;
		auto it19 = dos_header->e_oeminfo;

		auto it20 = dos_header->e_res2[0];
		auto it21 = dos_header->e_res2[1];
		auto it22 = dos_header->e_res2[2];
		auto it23 = dos_header->e_res2[3];
		auto it24 = dos_header->e_res2[4];
		auto it25 = dos_header->e_res2[5];
		auto it26 = dos_header->e_res2[6];
		auto it27 = dos_header->e_res2[7];
		auto it28 = dos_header->e_res2[8];
		auto it29 = dos_header->e_res2[9];

		auto it30 = dos_header->e_lfanew;

		it_size.push_back(sizeof(it0));
		it_size.push_back(sizeof(it1));
		it_size.push_back(sizeof(it2));
		it_size.push_back(sizeof(it3));
		it_size.push_back(sizeof(it4));
		it_size.push_back(sizeof(it5));
		it_size.push_back(sizeof(it6));
		it_size.push_back(sizeof(it7));
		it_size.push_back(sizeof(it8));
		it_size.push_back(sizeof(it9));
		it_size.push_back(sizeof(it10));
		it_size.push_back(sizeof(it11));
		it_size.push_back(sizeof(it12));
		it_size.push_back(sizeof(it13));
		it_size.push_back(sizeof(it14));
		it_size.push_back(sizeof(it15));
		it_size.push_back(sizeof(it16));
		it_size.push_back(sizeof(it17));
		it_size.push_back(sizeof(it18));
		it_size.push_back(sizeof(it19));
		it_size.push_back(sizeof(it20));
		it_size.push_back(sizeof(it21));
		it_size.push_back(sizeof(it22));
		it_size.push_back(sizeof(it23));
		it_size.push_back(sizeof(it24));
		it_size.push_back(sizeof(it25));
		it_size.push_back(sizeof(it26));
		it_size.push_back(sizeof(it27));
		it_size.push_back(sizeof(it28));
		it_size.push_back(sizeof(it29));
		it_size.push_back(sizeof(it30));

		it_value.push_back(it0);
		it_value.push_back(it1);
		it_value.push_back(it2);
		it_value.push_back(it3);
		it_value.push_back(it4);
		it_value.push_back(it5);
		it_value.push_back(it6);
		it_value.push_back(it7);
		it_value.push_back(it8);
		it_value.push_back(it9);
		it_value.push_back(it10);
		it_value.push_back(it11);
		it_value.push_back(it12);
		it_value.push_back(it13);
		it_value.push_back(it14);
		it_value.push_back(it15);
		it_value.push_back(it16);
		it_value.push_back(it17);
		it_value.push_back(it18);
		it_value.push_back(it19);
		it_value.push_back(it20);
		it_value.push_back(it21);
		it_value.push_back(it22);
		it_value.push_back(it23);
		it_value.push_back(it24);
		it_value.push_back(it25);
		it_value.push_back(it26);
		it_value.push_back(it27);
		it_value.push_back(it28);
		it_value.push_back(it29);
		it_value.push_back(it30);

		node->addr.reserve(31);
		node->data.reserve(31);
		for (int i = 0; i < it_value.size(); i++) {
			node->addr.push_back(Addr(RVA, 4));
			RVA += 4;

			node->data.push_back(Addr(it_value[i], sizeof(it_size[i])));
		}

		// 特殊处理
		node->value.push_back("IMAGE_DOS_SIGNATURE_MZ");
		int dis = node->addr.size() - node->value.size();
		while (dis--) {
			node->value.push_back("");
		}

		return node;
	}

	Node*init_dos_stub() {
		Node*node = new Node("IMAGE_DOS_STUB", false, false);
		auto raw_offset = sizeof(IMAGE_DOS_HEADER);
		auto raw_size = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
		auto RVA_offset = raw_offset;
		auto RVA_size = raw_size;
		fillContent(node, raw_offset, raw_size, RVA_offset, startVA);
		return node;
	}
	Node*init_nt_header(int startVA = 0) {
		Node*node = new Node("IMAGE_NT_HEADERS", false, false);
		auto size_nt_header = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
			nt_header->FileHeader.SizeOfOptionalHeader;

		auto raw_offset = dos_header->e_lfanew;
		auto raw_size = size_nt_header;
		auto RVA_offset = raw_offset;
		auto RVA_size = raw_size;
		fillContent(node, raw_offset, raw_size, RVA_offset, startVA);

		return node;
	}

	Node*init_nt_headers_signature(int startVA = 0) {
		Node*node = new Node("Signature", true, true);
		int RVA = dos_header->e_lfanew + startVA;
		node->addr.push_back(Addr(RVA, 4));
		node->data.push_back(Addr(nt_header->Signature, sizeof(nt_header->Signature)));
		node->desc.push_back("Signature");
		node->value.push_back("IMAGE_NT_HEADER_SIGNATURE");
		return node;
	}

	Node*init_nt_headers_file_header(int startVA = 0) {
		Node*node = new Node("IMAGE_FILE_HEADER", true, true);

		/*
			WORD    Machine;
			WORD    NumberOfSections;
			DWORD   TimeDateStamp;
			DWORD   PointerToSymbolTable;
			DWORD   NumberOfSymbols;
			WORD    SizeOfOptionalHeader;
			WORD    Characteristics;
		*/
		QStringList desc = { "Machine","NumberOfSections","TimeDateStamp","PointerToSymbolTable","NumberOfSymbols","SizeOfOptionalHeader","Characteristics" };
		node->desc = desc;
		PIMAGE_FILE_HEADER header = &nt_header->FileHeader;
		QVector<int> it_size;
		it_size.reserve(7);
		QVector<int> it_value;
		it_value.reserve(7);

		auto it0 = header->Machine;
		auto it1 = header->NumberOfSections;
		auto it2 = header->TimeDateStamp;
		auto it3 = header->PointerToSymbolTable;
		auto it4 = header->NumberOfSymbols;
		auto it5 = header->SizeOfOptionalHeader;
		auto it6 = header->Characteristics;

		it_size.push_back(sizeof(it0));
		it_size.push_back(sizeof(it1));
		it_size.push_back(sizeof(it2));
		it_size.push_back(sizeof(it3));
		it_size.push_back(sizeof(it4));
		it_size.push_back(sizeof(it5));
		it_size.push_back(sizeof(it6));

		it_value.push_back(it0);
		it_value.push_back(it1);
		it_value.push_back(it2);
		it_value.push_back(it3);
		it_value.push_back(it4);
		it_value.push_back(it5);
		it_value.push_back(it6);

		int RVA = dos_header->e_lfanew + sizeof(nt_header->Signature);
		for (int i = 0; i < 7; i++) {
			node->addr.push_back(Addr(RVA, 4));
			RVA += 4;
			node->data.push_back(Addr(it_value[i], it_size[i]));
		}

		// 对character的特殊处理
		// 同时还要保证 Addr desc value data 这4个vector长度的一致性
		// data addr desc 已经对齐 并且他们的长度均为7
		// 设置value的Machine type的值

		QVector<WORD> machine_value = { 0,0x0001,0x014c,0x0162,0x0166,0x0168,0x0169,0x0184,0x01a2,0x01a3,0x01a4,0x01a6,0x01a8,0x01c0,0x01c2,0x01c4,0x01d3,0x01F0,0x01f1,0x0200,0x0266,0x0284,0x0366,0x0466,0x0520,0x0CEF,0x0EBC,0x8664,0x9041,0xAA64,0xC0EE };
		QVector<QString> machine_type = { "IMAGE_FILE_MACHINE_UNKNOWN","IMAGE_FILE_MACHINE_TARGET_HOST","IMAGE_FILE_MACHINE_I386","IMAGE_FILE_MACHINE_R3000","IMAGE_FILE_MACHINE_R4000","IMAGE_FILE_MACHINE_R10000","IMAGE_FILE_MACHINE_WCEMIPSV2","IMAGE_FILE_MACHINE_ALPHA","IMAGE_FILE_MACHINE_SH3","IMAGE_FILE_MACHINE_SH3DSP","IMAGE_FILE_MACHINE_SH3E","IMAGE_FILE_MACHINE_SH4","IMAGE_FILE_MACHINE_SH5","IMAGE_FILE_MACHINE_ARM","IMAGE_FILE_MACHINE_THUMB","IMAGE_FILE_MACHINE_ARMNT","IMAGE_FILE_MACHINE_AM33","IMAGE_FILE_MACHINE_POWERPC","IMAGE_FILE_MACHINE_POWERPCFP","IMAGE_FILE_MACHINE_IA64","IMAGE_FILE_MACHINE_MIPS16","IMAGE_FILE_MACHINE_ALPHA64","IMAGE_FILE_MACHINE_MIPSFPU","IMAGE_FILE_MACHINE_MIPSFPU16","IMAGE_FILE_MACHINE_TRICORE","IMAGE_FILE_MACHINE_CEF","IMAGE_FILE_MACHINE_EBC","IMAGE_FILE_MACHINE_AMD64","IMAGE_FILE_MACHINE_M32R","IMAGE_FILE_MACHINE_ARM64","IMAGE_FILE_MACHINE_CEE" };
		Q_ASSERT(machine_type.size() == machine_value.size());
		auto find = qBinaryFind(machine_value.begin(), machine_value.end(), nt_header->FileHeader.Machine);
		if (find == machine_value.end()) {
			node->value.append("Unknown Machine");
		} else {
			node->value.append(machine_type[find - machine_value.begin()]);
		}

		int dis = node->addr.size() - node->value.size();

		while (dis-- > 0) {
			node->value.push_back("");
		}
		// 在此之前
		Q_ASSERT(node->data.size() == node->addr.size() && node->value.size() == node->desc.size() && node->data.size() == node->value.size());

		QStringList type = { "IMAGE_FILE_RELOCS_STRIPPED","IMAGE_FILE_EXECUTABLE_IMAGE","IMAGE_FILE_LINE_NUMS_STRIPPED","IMAGE_FILE_LOCAL_SYMS_STRIPPED","IMAGE_FILE_AGGRESIVE_WS_TRIM","IMAGE_FILE_LARGE_ADDRESS_AWARE","Unknown","IMAGE_FILE_BYTES_REVERSED_LO","IMAGE_FILE_32BIT_MACHINE","IMAGE_FILE_DEBUG_STRIPPED","IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP","IMAGE_FILE_NET_RUN_FROM_SWAP","IMAGE_FILE_SYSTEM","IMAGE_FILE_DLL","IMAGE_FILE_UP_SYSTEM_ONLY","IMAGE_FILE_BYTES_REVERSED_HI" };
		int bits = sizeof(header->Characteristics) << 3;

		// 0000 0000 0000 0000   & 0000 0000 0000 0001
		WORD factor = 0x0001;
		const WORD character = header->Characteristics;
		dis = 0;
		DWORD value;
		for (int i = 0; i < type.size(); i++) {
			value = factor & character;
			character << 1;
			if (value) {
				node->value.push_back(type[i]);
				node->desc.push_back(Addr(value, sizeof(DWORD)));
				dis++;
			}
		}

		// 对其 addr和data
		while (dis--) {
			node->addr.push_back("");
			node->data.push_back("");
		}
		Q_ASSERT(node->data.size() == node->addr.size() && node->value.size() == node->desc.size() && node->data.size() == node->value.size());

		return node;
	}
	Node*init_nt_header_optional_header(int startVA = 0) {
		Node*node = new Node("IMAGE_OPTIONAL_HEADER", true, true);

		return node;
	}

	QVector<Node*> init_section_header() {
		auto p = section_header;
		int NumberOfSections = nt_header->FileHeader.NumberOfSections;
		QVector<Node*>ret;
		QString name;
		int RVA;
		for (int i = 0; i < NumberOfSections; i++) {
			name = "IMAGE_SECTION_HEADER " + QString((char*)p->Name);
			Node* node = new Node(name, true, false);
			//********************//
			RVA = (us*)p - content;

			//********************//
			p++;
			ret.push_back(node);
		}
		return ret;
	}
	void init_section_header_1(int RVA, Node*node, PIMAGE_SECTION_HEADER header) {
		RVA += startVA;
		// 设置Name
		node->addr.push_back(Addr(RVA, 4));
		RVA += 4;
		node->addr.push_back(Addr(RVA, 4));
		RVA += 4;

		QByteArray byte = QByteArray((char*)header->Name, 8);
		QString hex_byte = byte.toHex(' ').toUpper();

		node->data.push_back(hex_byte.mid(0, 4));
		node->data.push_back(hex_byte.mid(4, 4));

		node->desc.push_back("Name");
		node->desc.push_back("");

		node->value.push_back(QString::fromLocal8Bit(byte));
		node->value.push_back("");
		// 9个项目
		// 设置余下元素
		QStringList desc = { "VirtualAddress","SizeOfRawData","PointerToRawData","PointerToRelocations","PointerToLinenumbers","NumberOfRelocations","NumberOfLinenumbers","Characteristics" };
		Q_ASSERT(desc.size() == 9);
		for (auto item : desc) {
			node->desc.append(item);
		}

		QVector<int> it_size;
		it_size.reserve(9);
		QVector<int> it_value;
		it_value.reserve(9);

		auto it0 = header->Misc.VirtualSize;
		auto it1 = header->VirtualAddress;
		auto it2 = header->SizeOfRawData;
		auto it3 = header->PointerToRawData;
		auto it4 = header->PointerToRelocations;
		auto it5 = header->PointerToLinenumbers;
		auto it6 = header->NumberOfRelocations;
		auto it7 = header->NumberOfLinenumbers;
		auto it8 = header->Characteristics;

		it_size.push_back(sizeof(it0));
		it_size.push_back(sizeof(it1));
		it_size.push_back(sizeof(it2));
		it_size.push_back(sizeof(it3));
		it_size.push_back(sizeof(it4));
		it_size.push_back(sizeof(it5));
		it_size.push_back(sizeof(it6));
		it_size.push_back(sizeof(it7));
		it_size.push_back(sizeof(it8));

		it_value.push_back(it0);
		it_value.push_back(it1);
		it_value.push_back(it2);
		it_value.push_back(it3);
		it_value.push_back(it4);
		it_value.push_back(it5);
		it_value.push_back(it6);
		it_value.push_back(it7);
		it_value.push_back(it8);
		for (int i = 0; i < 9; i++) {
			node->addr.push_back(Addr(RVA, 4));
			RVA += it_size[i];
			node->data.push_back(Addr(it_value[i], it_size[i]));
		}

		// 对齐value
		int dis = node->addr.size() - node->value.size();
		while (dis--) {
			node->value.push_back("");
		}
	

		// 设置characters
		QVector<DWORD> characteristics_value = { 0x00000020,0x00000040,0x00000080,0x00000200,0x00000800,0x00001000,0x00004000,0x00008000,0x00020000,0x00040000,0x00080000,0x00100000,0x00200000,0x00300000,0x00400000,0x00500000,0x00600000,0x00700000,0x00800000,0x00900000,0x00A00000,0x00B00000,0x00C00000,0x00D00000,0x00E00000,0x00F00000,0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000 };
		QVector<QString> characteristics_type = { "IMAGE_SCN_CNT_CODE","IMAGE_SCN_CNT_INITIALIZED_DATA","IMAGE_SCN_CNT_UNINITIALIZED_DATA","IMAGE_SCN_LNK_INFO","IMAGE_SCN_LNK_REMOVE","IMAGE_SCN_LNK_COMDAT","IMAGE_SCN_NO_DEFER_SPEC_EXC","IMAGE_SCN_GPREL","IMAGE_SCN_MEM_PURGEABLE","IMAGE_SCN_MEM_LOCKED","IMAGE_SCN_MEM_PRELOAD","IMAGE_SCN_ALIGN_1BYTES","IMAGE_SCN_ALIGN_2BYTES","IMAGE_SCN_ALIGN_4BYTES","IMAGE_SCN_ALIGN_8BYTES","IMAGE_SCN_ALIGN_16BYTES","IMAGE_SCN_ALIGN_32BYTES","IMAGE_SCN_ALIGN_64BYTES","IMAGE_SCN_ALIGN_128BYTES","IMAGE_SCN_ALIGN_256BYTES","IMAGE_SCN_ALIGN_512BYTES","IMAGE_SCN_ALIGN_1024BYTES","IMAGE_SCN_ALIGN_2048BYTES","IMAGE_SCN_ALIGN_4096BYTES","IMAGE_SCN_ALIGN_8192BYTES","IMAGE_SCN_ALIGN_MASK","IMAGE_SCN_LNK_NRELOC_OVFL","IMAGE_SCN_MEM_DISCARDABLE","IMAGE_SCN_MEM_NOT_CACHED","IMAGE_SCN_MEM_NOT_PAGED","IMAGE_SCN_MEM_SHARED","IMAGE_SCN_MEM_EXECUTE","IMAGE_SCN_MEM_READ","IMAGE_SCN_MEM_WRITE" };
		Q_ASSERT(characteristics_type.size() == characteristics_value.size());
		auto find = qBinaryFind(characteristics_value.begin(), characteristics_value.end(), header->Characteristics);
		if(find==characteristics_value.end()){
			
		}
		// 对齐

	}

	QVector<Node*> init_section() {
		auto header = section_header;
		int NumberOfSections = nt_header->FileHeader.NumberOfSections;
		QString name;
		QVector<Node*> ret;
		for (int i = 0; i < NumberOfSections; i++) {
			name = "SECTION " + QString((char*)header->Name);
			Node* node = new Node(name, false, false);
			// 实际大小是 Misc 的 VirtualSize(但是也不一定)   SizeOfRawData文件的大小
			auto raw_offset = header->PointerToRawData;
			auto raw_size = header->SizeOfRawData;
			auto RVA_offset = header->VirtualAddress;

			fillContent(node, raw_offset, raw_size, RVA_offset, startVA);

			header++;
			ret.push_back(node);
		}
		return ret;
	}
	/* 产生解释内容  1. node节点 2. 文件偏移开始地址 3.文件块实际大小
	 * node 节点
	 * raw_offset 相对于文件的偏移
	 * raw_size文件的实际尺寸
	 * RVA_offset相对的内存布局地址
	 * 内存布局的imageBase
	 */
	void fillContent(Node*node, int raw_offset, int raw_size, int RVA_offset, int startVA = 0) {
		if (node->hasDesc == true) {
			return;
		}

		int turn = (raw_size % 16 == 0) ? raw_size / 16 : (raw_size / 16) + 1;
		us*c = (us*)content + raw_offset;

		QByteArray byte = QByteArray((char*)c, raw_size);
		QString hex_byte = byte.toHex(' ').toUpper();
		RVA_offset += startVA;// 当前地址VA地址
		for (int i = 0; i < turn; i++) {
			//  c 指向此段的内容
			node->addr.append(Addr(RVA_offset, 4));
			RVA_offset += 16;
		}
		QString s;

		for (int i = 0; i < turn; i++) {
			s = hex_byte.mid(i * 48, 24);
			s += " ";
			s += hex_byte.mid(i * 48 + 24, 24);
			node->data.push_back(s);
		}

		stringToAcsII(c, raw_size, node);
	}
	void stringToAcsII(us*str, int size, Node*node) {
		int integer = size / 16;
		int remainder = size % 16;
		char space = '.';
		char ch;
		QString s;
		s.reserve(16);
		node->value.clear();
		int i, j, k;
		for (i = 0; i < integer; i++) {
			s.clear();
			k = i * 16;
			for (j = 0; j < 16; j++) {
				ch = str[k++];
				if ((ch >= 0x20) && (ch <= 0x7E)) {
					s.append(ch);
				} else {
					s.append(space);
				}
			}
			node->value.append(s);
		}
		s.clear();
		k = integer * 16;
		if (remainder > 0) {
			for (i = 0; i < remainder; i++) {
				ch = str[k++];
				if ((ch >= 0x20) && (ch <= 0x7E)) {
					s.append(ch);
				} else {
					s.append(space);
				}
			}
			node->value.append(s);
		}
	}
	void QByteArrayToACSIIString(const QByteArray& byte, Node*node) {
		QString     s;
		s.reserve(16);
		char space = '.';
		char ch = byte.at(0);
		ch = (ch >= 0x20 && ch <= 0x7E) ? ch : space;
		s.append(ch);
		int i;

		for (i = 1; i < byte.size(); ++i) {
			if (i % 16 == 0) {
				node->value.push_back(s);
				s.clear();
			}
			ch = byte.at(i);

			if ((ch >= 0x20) && (ch <= 0x7E)) {
				s.append(ch);
			} else {
				s.append(space);
			}
		}

		if ((i % 16 != 0) && !s.isEmpty()) {
			node->value.push_back(s);
		}
	}

	void savenFile(QString& file, us*content) {
		ofstream f(file.toStdString(), ios::binary);
		if (f) {
			f.write((char*)content, file_size);
		} else {
		}
	}

	~PE() {
		delete content;
	}

	static bool isPE32(const us* content) {
		PIMAGE_DOS_HEADER pDH = NULL;
		PIMAGE_NT_HEADERS pNtH = NULL;

		if (!content) return FALSE;

		/* DOS 数据结构解析！*/
		pDH = (PIMAGE_DOS_HEADER)content;

		if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
			return FALSE;

		pNtH = (PIMAGE_NT_HEADERS32)((DWORD)pDH + pDH->e_lfanew);

		if (pNtH->Signature != IMAGE_NT_SIGNATURE)
			return FALSE;

		if (pNtH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			return TRUE;

		return FALSE;
	}

	static bool isPE64(const us* content) {
		PIMAGE_DOS_HEADER   pDH = NULL;
		PIMAGE_NT_HEADERS64 pNtH = NULL;

		if (!content) return FALSE;

		/* DOS 数据结构解析！*/
		pDH = (PIMAGE_DOS_HEADER)content;

		if (pDH->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

		pNtH = (PIMAGE_NT_HEADERS64)((DWORD)pDH + pDH->e_lfanew);

		if (pNtH->Signature != IMAGE_NT_SIGNATURE) {
			return FALSE;
		}

		if (pNtH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return TRUE;
		}
		return FALSE;
	}
};
