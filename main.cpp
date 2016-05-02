#include "stdafx.h"
using namespace CryptoPP;


string RSAEncrypt(string keyfile);
string RSADecrypt(string RSACipher);
void AesEncrypt(string temp, string keyfile);
void AesDecrypt(string ciphertxt, string keyfile);
void GenerateRSAPrivetKey();
void GenerateRSAPublicKey();
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);
void Save(const string& filename, const BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
void Load(const string& filename, BufferedTransformation& bt);
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void SaveHex(const string& filename, const BufferedTransformation& bt);



int main(char* argv[])
{
	int selection;

	std::ifstream key("key.txt", std::ios::binary);
	std::ifstream file("file.txt", std::ios::binary);

	string keyfile, plaintext = "", temp;
	string RSAKey1, RSAKey2;

	while (key) {
		getline(key, keyfile);
	}
	while (getline(file, temp)) {
		plaintext.append(temp);
	}

	//generating
	GenerateRSAPrivetKey();
	GenerateRSAPublicKey();
	//encrypting
	RSAKey1 = RSAEncrypt(keyfile);

	AesEncrypt(plaintext, keyfile);


	cout << "Encryption done, press to start decrytion 3\n";
	system("pause");
	//decryption
	std::ifstream cipher_file("ciphertext.txt", std::ios::binary);
	string cipherfile = "", temp1;

	while (cipher_file)
	{
		temp.append(cipherfile);
		getline(cipher_file, cipherfile);

	}

	RSAKey2 = RSADecrypt(RSAKey1);
	AesDecrypt(cipherfile, RSAKey2);


	key.close();
	file.close();
	cout << "Decryption done\n";
	system("pause");

	return 0;
}




string RSAEncrypt(string keyfile)
{
	AutoSeededRandomPool rng, rnd, rndtest, rndtest2;
	string Strsecretekey;
	string StrPublickey;
	string plain = keyfile, cipher, recovered;
	string decoded, strDecode;
	std::string encoded;

	std::ifstream PublicKey("public.txt");
	std::ifstream SecreatKey("private.txt");


	while (PublicKey) {
		getline(PublicKey, StrPublickey);
	}
	while (SecreatKey) {
		getline(SecreatKey, Strsecretekey);
	}

	RSA::PublicKey  public_key;
	StringSource file_pk1(StrPublickey, true, new HexDecoder);
	public_key.Load(file_pk1);


	RSA::PrivateKey private_key;
	StringSource file_pk(Strsecretekey, true, new HexDecoder);
	private_key.Load(file_pk);



	RSAES_OAEP_SHA_Encryptor e(public_key);

	StringSource(plain, true,
		new PK_EncryptorFilter(rndtest, e,
		new StringSink(cipher)
		));

	StringSource(cipher, true,
		new HexEncoder(
		new StringSink(encoded)
		)
		);

	return encoded;

}

string RSADecrypt(string RSACipher)
{
	AutoSeededRandomPool rng, rnd, rndtest, rndtest2;
	string Strsecretekey;
	RSA::PrivateKey private_key;
	std::ifstream SecreatKey("private.txt");


	while (SecreatKey)
	{

		getline(SecreatKey, Strsecretekey);

	}

	StringSource file_pk(Strsecretekey, true, new HexDecoder);

	private_key.Load(file_pk);




	std::string cipher, recovered;

	StringSource(RSACipher, true,
		new HexDecoder(
		new StringSink(cipher)
		)
		);


	RSAES_OAEP_SHA_Decryptor d(private_key);

	StringSource(cipher, true, new PK_DecryptorFilter(rndtest2, d, new StringSink(recovered)));


	return recovered;
}

void AesEncrypt(string plaintxt, string keyfile)
{
	std::string key = keyfile.c_str();
	std::string iv = "0";
	std::string InputText = plaintxt;
	std::string ciphertext;


	CryptoPP::AES::Encryption aesEncryption((byte *)key.c_str(), CryptoPP::AES::MAX_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (byte *)iv.c_str());

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(InputText.c_str()), InputText.length() + 1);
	stfEncryptor.MessageEnd();


	string encoded;
	StringSource(ciphertext, true, new HexEncoder(new StringSink(encoded)));

	std::ofstream cipher_file("ciphertext.txt");
	cipher_file << encoded.length() << endl;
	cipher_file << encoded;
	cipher_file.close();

}


void AesDecrypt(string ciphertxt, string keyfile)
{


	std::string ciphertext = ciphertxt;

	std::string iv = "0";



	std::string key = keyfile.c_str();

	char *name2;
	name2 = (char*)malloc(ciphertxt.length() + 1);

	strcpy(name2, ciphertxt.c_str());

	const char* hex_str = name2;

	std::string result_string;
	unsigned int ch;
	for (; std::sscanf(hex_str, "%2x", &ch) == 1; hex_str += 2)
		result_string += ch;



	std::string decryptedtext;
	CryptoPP::AES::Decryption aesDecryption((byte *)key.c_str(), CryptoPP::AES::MAX_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (byte *)iv.c_str());

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(result_string.c_str()), result_string.size());
	stfDecryptor.MessageEnd();

	std::ofstream plaintext("newfile.txt");

	plaintext << decryptedtext;


	while (decryptedtext.find("\r") != string::npos)
	{
		decryptedtext.erase(decryptedtext.find("\r"), 1);
	}

	plaintext.close();



}

RSA::PrivateKey rsaPrivate;

void GenerateRSAPrivetKey()
{
	AutoSeededRandomPool rng, rnd, rndtest, rndtest2;

	rsaPrivate.GenerateRandomWithKeySize(rnd, 1024);

	SaveHexPrivateKey("private.txt", rsaPrivate);

}

void GenerateRSAPublicKey()
{
	AutoSeededRandomPool rng, rnd, rndtest, rndtest2;
	string Strsecretekey;

	std::ifstream SecreatKey("private.txt");
	while (SecreatKey)
	{


		getline(SecreatKey, Strsecretekey);

	}


	RSA::PrivateKey private_key;
	RSA::PublicKey  public_key;

	StringSource file_pk(Strsecretekey, true, new HexDecoder);

	private_key.Load(file_pk);

	RSA::PublicKey rsaPublic(private_key);

	SaveHexPublicKey("public.txt", rsaPublic);

}

void SaveHexPrivateKey(const string& filename, const PrivateKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveHex(filename, queue);
}

void SaveHexPublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveHex(filename, queue);
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
	HexEncoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void Save(const string& filename, const BufferedTransformation& bt)
{

	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}