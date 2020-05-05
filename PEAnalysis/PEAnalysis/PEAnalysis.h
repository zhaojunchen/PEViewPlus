#pragma once
#include <Windows.h>
#include <winnt.h>
#include <QDebug>
#include <fstream>
#include <iostream>
#include <string>

#include "data.h"
#include "tools.h"

class Info;
using std::string;
using std::ios;
using std::ifstream;
using std::ofstream;
using std::map;

// PE文件解构 https://blog.csdn.net/adam001521/article/details/84658708
// Qt Hex View
#ifndef __WIN64

brief init_rawData(int startVa, QByteArray byte);
QVector<QByteArray> init(const QString _file) {
	const string file = _file.toStdString();
	ifstream in(file, ios::binary);
	if (!in) {
		perror("file open error");
		exit(-1);
	}
	QVector<QByteArray>result;

	in.seekg(0, in.end);
	const size_t fileSize = in.tellg();
	in.seekg(0, in.beg);// 定位到文件开始
	us *content = new us[fileSize];
	memset(content, 0, fileSize);
	in.read(reinterpret_cast<char*>(content), fileSize);
	in.close();
	if (!isPE32(content)) {
		cout << "The File is not a PE32 file";
		exit(-1);
	}
	// PE FILE
	QByteArray peFile((char*)content, fileSize);
	result.push_back(peFile);
	// DOS HEADER
	PIMAGE_DOS_HEADER pimage_dos_header = (PIMAGE_DOS_HEADER)content;
	QByteArray dosHeader((char*)content, sizeof(IMAGE_DOS_HEADER));
	result.push_back(dosHeader);
	// DOS dosStub
	QByteArray dosStub(((char*)pimage_dos_header + sizeof(IMAGE_DOS_HEADER)), pimage_dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
	result.push_back(dosStub);
	// NT HEADER
	PIMAGE_NT_HEADERS32 pimage_nt_headers32 = (PIMAGE_NT_HEADERS32)((char*)pimage_dos_header + pimage_dos_header->e_lfanew);
	QByteArray ntHeader((char*)(pimage_nt_headers32), sizeof(IMAGE_NT_HEADERS32));
	result.push_back(ntHeader);

	auto numberOfSection = pimage_nt_headers32->FileHeader.NumberOfSections;
	// section table
	PIMAGE_SECTION_HEADER pimage_section_header = (PIMAGE_SECTION_HEADER)((char*)pimage_nt_headers32 + sizeof(IMAGE_NT_HEADERS32));
	QVector<DWORD> rawSize(numberOfSection);
	QVector<DWORD> rawStart(numberOfSection);

	DWORD t;
	for (auto i = 0; i < numberOfSection; ++i) {
		QByteArray sectionHeader((char*)pimage_section_header, sizeof(IMAGE_SECTION_HEADER));
		t = pimage_section_header->SizeOfRawData;
		rawSize[i] = (t % 0x200 == 0) ? t : ((t / 0x200) + 1) * 0x200;
		rawStart[i] = pimage_section_header->PointerToRawData;
		pimage_section_header++;
		result.push_back(sectionHeader);
	}
	// section
	char* sectionStart = (char*)pimage_section_header;
	for (int i = 0; i < numberOfSection; ++i) {
		QByteArray section((char*)content + rawStart[i], rawSize[i]);
		sectionStart += rawSize[i];
		result.push_back(section);
	}
	delete[]content;
	return result;
}

QVector<Info> init_listView() {
	QVector<QByteArray> raw = init("C:/test.exe");
	// DOS Header
	QByteArray pe_byte = raw.at(0);
	QByteArray dos_byte = raw.at(1);
	QByteArray stub_byte = raw.at(2);
	QByteArray nt_byte = raw.at(3);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dos_byte.data();
	PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)nt_byte.data();
	//foreach(auto it, raw) {
	//	show(it.data(), 20);
	//}
	//show(nt, 20);

	DWORD signature = nt->Signature;
	IMAGE_FILE_HEADER file = nt->FileHeader;
	IMAGE_OPTIONAL_HEADER32 option = nt->OptionalHeader;
	QVector<PIMAGE_SECTION_HEADER> sectionTable;
	auto numberSection = file.NumberOfSections;

	QVector<PIMAGE_SECTION_HEADER> sectiontable;
	sectiontable.reserve(numberSection);
	for (int i = 0; i < numberSection; ++i) {
		PIMAGE_SECTION_HEADER p = (PIMAGE_SECTION_HEADER)raw.at(4 + i).data();
		sectiontable.push_back(p);
	}
	brief b = init_rawData(0x400040, stub_byte);
	for (int i = 0; i < b.Va.size(); ++i) {
		cout << b.Va.at(i);
	}
	for (int i = 0; i < b.RawData.size(); ++i) {
		cout << b.RawData.at(i);
	}
	for (int i = 0; i < b.Value.size(); ++i) {
		cout << b.Value.at(i);
	}
	QVector<Info> s;
	return s;
}

QStringList QByteArrayToACSIIString(const QByteArray& byte) {
	QStringList result;
	QString s;
	s.reserve(16);
	char space = '.';
	char ch = byte.at(0);
	ch = (ch >= 0x20 && ch <= 0x7E) ? ch : space;
	s.append(ch);
	int i;
	for (i = 1; i < byte.size(); ++i) {
		if (i % 16 == 0) {
			result.push_back(s);
			s.clear();
		}
		ch = byte.at(i);
		if (ch >= 0x20 && ch <= 0x7E) {
			s.append(ch);
		} else {
			s.append(space);
		}
	}
	if (i % 16 != 0 && !s.isEmpty()) {
		result.push_back(s);
	}
	return result;
}

brief init_rawData(int startVa, QByteArray byte) {
	brief b;
	auto byteSize = byte.size();
	int turn = (byteSize % 16 == 0) ? byteSize / 16 : byteSize / 16 + 1;
	// VA init
	for (int i = 0; i < turn; i++) {
		b.Va.append(QString("%1").arg(startVa, 8, 16, QChar('0')).toUpper());
		startVa += 16;
	}
	// RAW init
	QString raw = byte.toHex(' ').toUpper();
	// 48 QString QString::mid(int position, int n = -1) const
	int i;
	for (i = 0; i < turn - 1; ++i) {
		b.RawData.append(raw.mid(i * 48, 48));
	}
	b.RawData.append(raw.mid(i * 48));
	b.Value = QByteArrayToACSIIString(byte);

	return b;
}

#else

#endif
