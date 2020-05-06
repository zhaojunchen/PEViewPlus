#include <iostream>
#include <stdio.h>
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

//#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
#define CODE "\x31\xD2\x68\x74\x69\x70\x00\x54\x58\x6A\x00\x68\x30\x31\x38\x34\x68\x30\x31\x35\x30\x68\x30\x31\x37\x33\x68\x47\x31\x3A\x32\x54\x59\x52\x50\x51\x52\x31\xC9\x64\x8B\x41\x30\x8B\x40\x0C\x8B\x70\x14\xAD\x96\xAD\x8B\x58\x10\x8B\x53\x3C\x01\xDA\x8B\x52\x78\x01\xDA\x8B\x72\x20\x01\xDE\x31\xC9\x41\xAD\x01\xD8\x81\x38\x47\x65\x74\x50\x75\xF4\x81\x78\x04\x72\x6F\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72\x65\x75\xE2\x8B\x72\x24\x01\xDE\x66\x8B\x0C\x4E\x49\x8B\x72\x1C\x01\xDE\x8B\x14\x8E\x01\xDA\x52\x31\xC9\x51\x68\x61\x72\x79\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F\x61\x64\x54\x53\xFF\xD2\x83\xC4\x10\x68\x6C\x6C\x00\x00\x68\x33\x32\x2E\x64\x68\x75\x73\x65\x72\x54\xFF\xD0\x83\xC4\x0C\x5A\x31\xC9\x68\x6F\x78\x41\x00\x68\x61\x67\x65\x42\x68\x4D\x65\x73\x73\x54\x50\xFF\xD2\x83\xC4\x0C\xFF\xD0\x83\xC4\x18"
int main() {
	csh handle;
	cs_insn* insn;
	size_t count;
	// CS_ARCH_X86,		///< X86 架构 (包括 x86 & x86-64)
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
	// 反汇编
	count = cs_disasm(handle, (unsigned char*)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
	if (count) {
		size_t j;

		for (j = 0; j < count; j++) {
			printf("%x:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

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