#pragma once
#include <string>


/**
 * 计算汇编指令中大于等于base的指令地址
 */
int code_prefixsize(unsigned char* code, int base = 5, int code_size = 20);
std::string code_disassembly(unsigned char* code, int code_size, int start = 0);

