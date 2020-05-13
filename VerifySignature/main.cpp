#include <QtCore/QCoreApplication>
#include<qdebug.h>
#include<qfile.h>
#include<openssl/ssl.h>
#pragma comment(lib,"libssl.lib")

/*
The Certificate Table entry points to a table of attribute certificates.
These certificates are not loaded into memory as part of the image. 
As such, the first field of this entry, which is normally an RVA, is a file pointer instead.

Attribute certificates can be associated with an image by adding an attribute certificate table.
The attribute certificate table is composed of a set of contiguous,
quadword-aligned attribute certificate entries. 
Zero padding is inserted between the original end of the file and the beginning of the attribute certificate table to achieve this alignment. 
Each attribute certificate entry contains the following fields.


Offset	Size				Field				Description
0		4					dwLength			Specifies the length of the attribute certificate entry.
4		2					wRevision			Contains the certificate version number. For details, see the following text.
6		2					wCertificateType	Specifies the type of content in bCertificate. For details, see the following text.
8		See the following	bCertificate		Contains a certificate, such as an Authenticode signature. For details, see the following text.
*/

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	qDebug() << "sfy";
	QFile* peFile = new QFile("d:test.exe");
	QByteArray peData = peFile->readAll();

	SSL_library_init();

	return a.exec();
}

bool verifySignature(QByteArray signedData) {
	return true;
}