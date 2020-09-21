#ifndef RELOC_H
#define RELOC_H

#include"PE.h"

int Test(const PE* pe){
    pe->changeImageBase(0x500000);
    return 0;
}

#endif // RELOC_H
