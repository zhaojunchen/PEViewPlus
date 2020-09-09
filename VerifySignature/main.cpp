#include <QtCore/QCoreApplication>
#include<qdebug.h>
#include<qfile.h>
#include<openssl/ssl.h>
#include<openssl/pkcs7.h>
#include<openssl/crypto.h>
#include<openssl/safestack.h>
#include"uthenticode.h"
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

using namespace uthenticode;

//DEFINE_STACK_OF(PKCS7_SIGNER_INFO);

/*
The Certificate Table entry points to a table of attribute certificates .
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

bool verifySignature(QByteArray signedData) {
	unsigned char derData[0x2048];
	std::move(signedData.begin(), signedData.end(), derData);
	//const unsigned char* p_signature_msg = reinterpret_cast<const unsigned char*>(signedData.constData());
	const unsigned char* p_signature_msg = derData;

	BIO* p7bio;
	p7bio = BIO_new_mem_buf(derData, signedData.length());
	auto* p7 = d2i_PKCS7_bio(p7bio, nullptr);
	if (p7 == nullptr) {
		//qDebug << "Couldn't parse PKCS#7 SignedData";
		return false;
	}
	auto* contents = p7->d.sign->contents;
	if (contents == nullptr) {
		return false;
	}
	OBJ_create(impl::SPC_INDIRECT_DATA_OID, NULL, NULL);
	auto* spc_indir_oid_ptr = OBJ_txt2obj(impl::SPC_INDIRECT_DATA_OID, 1);
	if (spc_indir_oid_ptr == nullptr) {
		return false;
	}
	if (ASN1_TYPE_get(contents->d.other) != V_ASN1_SEQUENCE ||
		OBJ_cmp(contents->type, spc_indir_oid_ptr)) {
		return false;
	}

	//9.5
	const auto* indir_data_inc_ptr = contents->d.other->value.sequence->data;
	auto* indir_data = impl::d2i_Authenticode_SpcIndirectDataContent(
		nullptr, &indir_data_inc_ptr, contents->d.other->value.sequence->length);
	if (indir_data == nullptr) {
		return false;
	}

	/* Sanity checks against SpcIndirectDataContent. It's not clear to me
		 * whether a non-nullptr above guarantees any of these fields, so check
		 * them manually.
		 */
	if (indir_data->messageDigest->digest->data == nullptr ||
		indir_data->messageDigest->digest->length >= contents->d.other->value.sequence->length) {
		return false;
	}

	//Now verify the signature
	STACK_OF(X509)* certs = nullptr;
	switch (OBJ_obj2nid(p7->type)) {
	case NID_pkcs7_signed: {
		certs = p7->d.sign->cert;
		break;
	}
	/* NOTE(ww): I'm pretty sure Authenticode signatures are always SignedData and never
	 * SignedAndEnvelopedData, but it doesn't hurt us to handle the latter as well.
	 */
	case NID_pkcs7_signedAndEnveloped: {
		certs = p7->d.signed_and_enveloped->cert;
		break;
	}
	}

	if (certs == nullptr) {
		return false;
	}

	/* NOTE(ww): What happens below is a bit dumb: we convert our SpcIndirectDataContent back
	 * into DER form so that we can unwrap its ASN.1 sequence and pass the underlying data
	 * to PKCS7_verify for verification. This displays our intent a little more clearly than
	 * our previous approach, which was to walk the PKCS#7 structure manually.
	 */
	std::uint8_t* indirect_data_buf = nullptr;
	auto buf_size = impl::i2d_Authenticode_SpcIndirectDataContent(indir_data, &indirect_data_buf);
	if (buf_size < 0 || indirect_data_buf == nullptr) {
		return false;
	}
	auto indirect_data_ptr =
		impl::OpenSSL_ptr(reinterpret_cast<char*>(indirect_data_buf), impl::OpenSSL_free);

	const auto* signed_data_seq = reinterpret_cast<std::uint8_t*>(indirect_data_ptr.get());
	long length = 0;
	int tag = 0, tag_class = 0;
	ASN1_get_object(&signed_data_seq, &length, &tag, &tag_class, buf_size);
	if (tag != V_ASN1_SEQUENCE) {
		return false;
	}

	auto* signed_data_ptr = BIO_new_mem_buf(signed_data_seq, length);
	if (signed_data_ptr == nullptr) {
		return false;
	}
	impl::BIO_ptr signed_data(signed_data_ptr, BIO_free);

	/* Our actual verification happens here.
	 *
	 * We pass `certs` explicitly, but (experimentally) we don't have to -- the function correctly
	 * extracts then from the SignedData in `p7_`.
	 *
	 * We pass `nullptr` for the X509_STORE, since we don't do full-chain verification
	 * (we can't, since we don't have access to Windows's Trusted Publishers store on non-Windows).
	 */
	auto status = PKCS7_verify(p7, certs, nullptr, signed_data.get(), nullptr, PKCS7_NOVERIFY);

	return status == 1;


	STACK_OF(PKCS7_SIGNER_INFO)* signer_info = p7->d.sign->signer_info;

	//获得签名者个数，可以有多个签名者  
	int signCount1 = sk_PKCS7_SIGNER_INFO_num(signer_info);
	qDebug() << signCount1;

	for (int i = 0; i < signCount1; i++)
	{
		//获得签名者信息  
		PKCS7_SIGNER_INFO* signInfo = sk_PKCS7_SIGNER_INFO_value(signer_info, i);
		//qDebug << *(signInfo->issuer_and_serial->issuer);
	}
	//auto* indir_data_inc_ptr = contents->d.other->value.sequence->data;
	//auto* indir_data = d2i_Authenticode_SpcIndirectDataContent(
	//	nullptr, &indir_data_inc_ptr, contents->d.other->value.sequence->length);
	//if (indir_data == nullptr) {
	//	return nullptr;
	//}

	

	/*
	//DER编码转换为PKCS7结构体  
	PKCS7* p7 = d2i_PKCS7(NULL, &p_signature_msg, signedData.length());
	qDebug() << signedData.length();
	if (p7 == nullptr) {
		qDebug() << "Failed To Decode PKCS7";
		return false;
	}
	//解析出原始数据  
	BIO* p7bio = PKCS7_dataDecode(p7, NULL, NULL, NULL);

	//从BIO中读取原始数据,这里是明文
	char message[2048];
	int dwMessageLen = BIO_read(p7bio, message, 2048);
	qDebug() << message;
	*/

	//获得签名者信息stack  
	STACK_OF(PKCS7_SIGNER_INFO)* sk = PKCS7_get_signer_info(p7);

	//获得签名者个数，可以有多个签名者  
	int signCount = sk_PKCS7_SIGNER_INFO_num(sk);
	qDebug() << signCount;

	for (int i = 0; i < signCount; i++)
	{
		//获得签名者信息  
		PKCS7_SIGNER_INFO* signInfo = sk_PKCS7_SIGNER_INFO_value(sk, i);

		//获得签名者证书  
		X509* cert = PKCS7_cert_from_signer_info(p7, signInfo);

		//验证签名  
		if (PKCS7_signatureVerify(p7bio, p7, signInfo, cert) != 1)
		{
			qDebug() << ("signature verify error.\n");
			return false;
		}
	}
	return true;
}

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	QFile* peFile = new QFile("d:/python_fake.exe");
	peFile->open(QIODevice::ReadWrite);
	//读取PE文件
	QByteArray peData = peFile->readAll();
	//读取SignedData
	peFile->seek(0x16c00 + 8);
	QByteArray signedData = peFile->read(0x1A48 - 8);
	verifySignature(signedData);
	//qDebug() << (int)signedData.at(1);
	//SSL_library_init();

	return a.exec();
}

