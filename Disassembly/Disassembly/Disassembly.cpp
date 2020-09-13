#include <iostream>
#include <stdio.h>
#include <string>
#include <cinttypes>
#include "capstone/capstone.h"
using namespace std;
#pragma comment(lib, "legacy_stdio_definitions.lib")

#ifndef  _WIN64
#pragma comment(lib,"capstone_static_x86.lib")
#else
#pragma comment(lib,"capstone_static_x64.lib")
#endif

#if _MSC_VER>=1900
#include "stdio.h"
_ACRTIMP_ALT FILE* __cdecl __acrt_iob_func(unsigned);
#ifdef __cplusplus
extern "C"
#endif
FILE* __cdecl __iob_func(unsigned i) {
	return __acrt_iob_func(i);
}
#endif /* _MSC_VER>=1900 */

/**
 * 计算汇编指令中大于等于base的指令地址
 */

int code_prefixsize(unsigned char* code, int base = 5, int code_size = 20) {
	csh handle;
	cs_insn* insn;
	int result = -1;
#ifndef _WIN64
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
#else
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
#endif
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
	if (base > code_size) {
		return -1;
	}
	size_t count = cs_disasm(handle, (unsigned char*)code, code_size, 0x00, 0, &insn);
	if (count) {
		for (size_t j = 0; j < count; j++) {
			if (insn[j].address >= base) {
				result = insn[j].address;
				break;
			}
		}
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
		exit(-1);
	}
	cs_free(insn, count);
	return result;
}

string code_disassembly(unsigned char* code, int code_size, int start = 0) {
	csh handle;
	cs_insn* insn;
#ifndef _WIN64
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
#else
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
#endif

		printf("ERROR: Failed to initialize engine!\n");
		exit(-1);
	}

	size_t count = cs_disasm(handle, (unsigned char*)code, code_size, start, 0, &insn);
	string result, tmp;
	if (count) {
		for (size_t j = 0; j < count; j++) {
			char buffer[80];
			memset(buffer, 0, 80);
#ifndef _WIN64
			sprintf_s(buffer, "%08llX:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
#else
			sprintf_s(buffer, "%016I64X:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
#endif
			result.append(buffer);
		}
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
		exit(-1);
	}
	cs_free(insn, count);
	return result;
}

unsigned char code_64[85] = {
	0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4, 0x65, 0x48, 0x8B,
	0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B,
	0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE,
	0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57,
	0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48,
	0x01, 0xF7, 0x99, 0xFF, 0xD7
};
unsigned char code_32[72] = {
0x31, 0xD2, 0x52, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x52, 0x51, 0x64, 0x8B, 0x72, 0x30,
0x8B, 0x76, 0x0C, 0x8B, 0x76, 0x0C, 0xAD, 0x8B, 0x30, 0x8B, 0x7E, 0x18, 0x8B, 0x5F, 0x3C, 0x8B,
0x5C, 0x3B, 0x78, 0x8B, 0x74, 0x1F, 0x20, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C,
0x17, 0x42, 0x42, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xF0, 0x8B, 0x74, 0x1F,
0x1C, 0x01, 0xFE, 0x03, 0x3C, 0xAE, 0xFF, 0xD7
};

int main() {
#ifndef _WIN64
	//int s = code_prefixsize((unsigned char*)code_32);
	//cout << s << endl;
	//string s1 = code_disassembly((unsigned char*)code_32, 72);
	//cout << s1;
	int s = code_prefixsize((unsigned char*)code_64);
	cout << s << endl;
	string s1 = code_disassembly((unsigned char*)code_64, 85);
	cout << s1;

#else
	//int s = code_prefixsize((unsigned char*)code_32);
	//cout << s << endl;
	//string s1 = code_disassembly((unsigned char*)code_32, 72);
	//cout << s1;
	int s = code_prefixsize((unsigned char*)code_64);
	cout << s << endl;
	string s1 = code_disassembly((unsigned char*)code_64, 85);
	cout << s1;
#endif
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧:
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件