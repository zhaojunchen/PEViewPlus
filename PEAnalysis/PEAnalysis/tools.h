#pragma once
#include <QDebug>
#define cout qDebug() <<"LINE "<<__LINE__<<":"
typedef  unsigned char us;

/** 只是用在标准输出
 *  输入指针 输入大小
 *  输出指针内容的byte!
 *  */

void show(void *src, int size) {
	char *p = (char *)src;
	for (int i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("\n");
		}
		printf("%02X ", static_cast<unsigned char>(*p));
		p++;
	}
}

/**
 * 输入PE指针 PE文件是否为PE格式
 * */
bool isPE32(LPVOID ImageBase) {
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (!ImageBase)
		return FALSE;
	/* DOS 数据结构解析！*/
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	pNtH = (PIMAGE_NT_HEADERS32)((DWORD)pDH + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	if (pNtH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return TRUE;
	return FALSE;
}

bool isPE64(LPVOID ImageBase) {
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (!ImageBase)
		return FALSE;
	/* DOS 数据结构解析！*/
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	pNtH = (PIMAGE_NT_HEADERS32)((DWORD)pDH + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	if (pNtH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return TRUE;
	return FALSE;
}

#ifndef  __WIN64

/* This part code is only for PE32 */

#else

#endif
