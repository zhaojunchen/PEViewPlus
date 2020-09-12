#include <QtCore/QCoreApplication>
#include<qfile.h>
#include<qdebug.h>
#include<stdexcept>

typedef struct _IMAGE_BASE_RELOCATION {
	uint32_t VirtualAddress;
	uint32_t sizeOfBlock;
} IMAGE_BASE_RELOCATION;

uint32_t reloc(uint32_t virtualAddressBase, uint16_t typeOffset, uint32_t imageBaseOffset) {
    auto relocType = typeOffset >> 12;
	switch (relocType)
	{
	case 3:
		return virtualAddressBase + typeOffset | 0xFFF + imageBaseOffset;
		break;
	default:
		throw std::runtime_error{ "Invalid relocType" };
		break;
	}
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
	QFile* peFile = new QFile("d:/python_fake.exe");
	peFile->open(QIODevice::ReadWrite);
	//读取PE文件
	QByteArray peData = peFile->readAll();
	//读取RelocationTable
	peFile->seek(0x16A00);
	QByteArray relocationTable = peFile->read(0x1C);
	//qDebug() << relocationTable[0];
	auto relocData = relocationTable.constData();
	const IMAGE_BASE_RELOCATION* pReloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(relocData);
	qDebug() << pReloc->sizeOfBlock;
	return a.exec();
}

