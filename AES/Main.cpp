#include "AES.h"

int main() {

	/*
	AES aes(AESKeyLength::AES_128);
	
	std::vector<unsigned char> key = aes.GenerateKey();
	bitmap_image image("sova.bmp");
	bitmap_image encoded_image(image.width(), image.height());
	bitmap_image result_image(image.width(), image.height());

	aes.EncryptECB(&image, key, &encoded_image);
	aes.DecryptECB(&encoded_image, key, &result_image);

	*/

	/*
	AES aes(AESKeyLength::AES_128);
	std::vector<unsigned char> key = aes.GenerateKey();
	std::vector<unsigned char> iv = aes.GenerateKey();
	aes.EncryptOFB("mama.txt", key, "encodeofb.txt",iv);
	aes.DecryptOFB("encodeofb.txt", key, "resultofb.txt",iv);
	return 0;
	*/

	AES aes(AESKeyLength::AES_128);
	std::vector<unsigned char> key = aes.GenerateKey();
	std::vector<unsigned char> iv = aes.GenerateKey();
	bitmap_image image("sova.bmp");
	bitmap_image encoded_image(image.width(), image.height());
	bitmap_image result_image(image.width(), image.height());
	aes.EncryptOFB(&image, key, &encoded_image,iv);
	aes.DecryptOFB(&encoded_image, key, &result_image, iv);



	return 0;
}