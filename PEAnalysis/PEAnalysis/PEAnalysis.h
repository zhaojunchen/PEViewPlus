#pragma once
#include <Windows.h>
#include <winnt.h>
#include <QDebug>
#include <fstream>
#include <iostream>
#include <string>

#include "tools.h"

using std::string;
using std::ios;
using std::ifstream;
using std::ofstream;


// PE文件解构 https://blog.csdn.net/adam001521/article/details/84658708
#ifndef __WIN64

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

	// DOS HEADER
	PIMAGE_DOS_HEADER pimage_dos_header = (PIMAGE_DOS_HEADER)content;
	//show(pimage_dos_header, 20);
	QByteArray dosHeader((char*)content, sizeof(IMAGE_DOS_HEADER));
	result.push_back(dosHeader);
	// DOS dosStub
	QByteArray dosStub(((char*)pimage_dos_header + sizeof(IMAGE_DOS_HEADER)), pimage_dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
	result.push_back(dosStub);
	// NT HEADER
	PIMAGE_NT_HEADERS32 pimage_nt_headers32 = (PIMAGE_NT_HEADERS32)((char*)pimage_dos_header + pimage_dos_header->e_lfanew);
	/*//show(pimage_nt_headers32, 0x30);*/

	QByteArray ntHeader((char*)(pimage_nt_headers32), sizeof(IMAGE_NT_HEADERS32));
	result.push_back(ntHeader);

	auto numberOfSection = pimage_nt_headers32->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pimage_section_header = (PIMAGE_SECTION_HEADER)((char*)pimage_nt_headers32 + sizeof(IMAGE_NT_HEADERS32));
	//show(pimage_section_header, 20);
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
	char* sectionStart = (char*)pimage_section_header;
	for (int i = 0; i < numberOfSection; ++i) {
		QByteArray section((char*)content + rawStart[i], rawSize[i]);
		sectionStart += rawSize[i];
		result.push_back(section);
	}
	delete[]content;
	return result;
}
#else

#endif
