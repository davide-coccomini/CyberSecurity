#include <string>
#include <string.h>
#include <vector>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <fstream>
#include <experimental/filesystem>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include<stdint.h>

#include "const.h"

using namespace std;

unsigned char* securityKey;
unsigned char* authenticationKey;
const EVP_MD* md = EVP_sha256();
const size_t authenticationKeySize = sizeof(authenticationKey);
const size_t blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
const size_t hashSize = EVP_MD_size(md);
const size_t ivLength = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

size_t counter = 0;
unsigned char ivChar[sizeof(size_t)];
size_t iv = 0;

void createDigest(unsigned char* plainText, int plainTextSize, unsigned char* digest){
	unsigned char bufferCounter[sizeof(size_t)+plainTextSize];

	memcpy(bufferCounter, &counter, sizeof(size_t));
	memcpy(bufferCounter + sizeof(size_t), plainText, plainTextSize);

	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t) + plainTextSize);
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);

}
int sendSize(int socket, size_t length){

	unsigned char plainText[sizeof(uint32_t)];
	unsigned char cipherText[hashSize+blockSize];
	unsigned char concatenatedText[sizeof(uint32_t)+hashSize];
	unsigned char digest[hashSize];

	uint32_t messageLength = htonl(length);
	memcpy(plainText, &messageLength, sizeof(uint32_t));


	// Create the digest
	createDigest(plainText, length+sizeof(size_t), digest);

	memcpy(concatenatedText, plainText, sizeof(uint32_t));
	memcpy(concatenatedText+sizeof(uint32_t), digest, hashSize);

	// Generate the cipherText
	int tmpLength = 0;
	int resultLength = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_EncryptUpdate(ctx, cipherText, &tmpLength, concatenatedText, sizeof(uint32_t)+hashSize);
	EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);

	// Send the message
	int done = send(socket, (void*)&cipherText, resultLength, 0);
	if(done < 0){
		cerr << "Error sending size" << endl;
		explicit_bzero(plainText, sizeof(uint32_t));
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	iv++;
	memcpy(ivChar, &iv, sizeof(size_t));
	counter++;

	explicit_bzero(plainText,sizeof(uint32_t));
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}



// AES128(k_sec, (m  || RSA256(k_aut, (m || counter) ) )
int sendString(int socket, string s){

	size_t length = s.size() + 1;
	int done = sendSize(socket,length);

	unsigned char plainText[length];
	unsigned char cipherText[length+blockSize+hashSize];
	unsigned char concatenatedText[length+hashSize];
	unsigned char digest[hashSize];

	memcpy(plainText, s.c_str(), s.size());
	plainText[s.size()] = '\0';

	// Create the digest
	createDigest(plainText, length, digest);

	memcpy(concatenatedText, plainText, s.size());
	memcpy(concatenatedText+s.size(), digest, hashSize);

	// Generate the cipherText
	int tmpLength = 0;
	int resultLength = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_EncryptUpdate(ctx, cipherText, &tmpLength, concatenatedText, length+hashSize);
	EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);

	// Send the message
	done = send(socket, (void*)&cipherText, resultLength, 0);
	if(done < 0){
		cerr << "Error sending string" << endl;
		explicit_bzero(plainText, length);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	iv++;
	memcpy(ivChar, &iv, sizeof(size_t));
	counter++;

	explicit_bzero(plainText,length);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int checkDigest(unsigned char* receivedDigest, unsigned char* message, int length){ 
	int done;
	unsigned char digest[hashSize];
	unsigned char bufferCounter[sizeof(size_t) + length];

	memcpy(bufferCounter, &counter, sizeof(size_t));
	memcpy(bufferCounter + sizeof(size_t), message, length);

	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t) + length);
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);

	// Checking if digest is correct
	done = CRYPTO_memcmp(digest, receivedDigest, hashSize);
	if(done != 0){
		cerr << "The received digest is wrong" << endl;
		return -1;
	}
	counter++;
	return 0;
}

uint32_t receiveSize(int socket){
	unsigned char plainText[sizeof(uint32_t)];
	unsigned char cipherText[blockSize+hashSize];
	unsigned char concatenatedText[sizeof(uint32_t)+hashSize];
	unsigned char digest[hashSize];
	uint32_t length;
	int done = recv(socket, (void*)&cipherText, blockSize, MSG_WAITALL);
	if(done < 0){
		cerr<<"Error receiving size"<<endl;
		return 0;
	}
	int len = 0;
	// Decrypt message
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Inizializzo un contesto per decriptare il messaggio
	EVP_DecryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_DecryptUpdate(ctx, concatenatedText, &len, cipherText, blockSize+hashSize);
	EVP_DecryptFinal(ctx, concatenatedText+len, &len);
	EVP_CIPHER_CTX_free(ctx);

	// Split the message
	memcpy(plainText, concatenatedText,sizeof(uint32_t));
	memcpy(digest, concatenatedText + sizeof(uint32_t), hashSize);

	memcpy(&length, plainText, sizeof(uint32_t));

	done = checkDigest(digest, cipherText, len);
	if(done < 0){
		cerr << "Error checking digest" << endl;
		return -1;
	}
	iv++;
	memcpy(ivChar, &iv, sizeof(size_t));
	explicit_bzero(plainText, sizeof(uint32_t));
	return (uint32_t)ntohl(length);
}

// Received message -> (m  || RSA256(k_aut, (m || counter))
string receiveString(int socket){
	int done, length = 0;
	unsigned char digest[hashSize];
	string s;
	uint32_t size = receiveSize(socket);

	unsigned char plainText[size];
	unsigned char cipherText[size+blockSize+hashSize];
	unsigned char concatenatedText[size+hashSize];

	done = recv(socket, (void*)&cipherText, size+blockSize+hashSize, MSG_WAITALL);
	if(done < 0){
		cerr << "Error receiving message" << endl;
		return s;
	}

	// Decrypt message
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_DecryptUpdate(ctx, concatenatedText, &length, cipherText, size+blockSize+hashSize);
	EVP_DecryptFinal(ctx, concatenatedText+length, &length);
	EVP_CIPHER_CTX_free(ctx);

	// Split the message
	memcpy(plainText, concatenatedText,size);
	memcpy(digest, concatenatedText + size, hashSize);

	done = checkDigest(digest, cipherText, size+blockSize+hashSize);
	if(done < 0){
		cerr << "Error checking digest" << endl;
		return s;
	}
	iv++;
	memcpy(ivChar, &iv, sizeof(size_t));
	counter++;
	s = string((char*)plainText);

	explicit_bzero(plainText, size);
	return s;
}

/*
int sendSize(int socket,size_t length){
	int done;

	// Invio il nonce
	done = sendIV(socket);
	if(done < 0){
		cerr << "Error sending initialization vector" << endl;
		return -1;
	}

	unsigned char plainText[sizeof(uint32_t)];
	unsigned char cipherText[blockSize];

	uint32_t messageLength = htonl(length);
	memcpy(plainText, &len, sizeof(uint32_t));

	// Effettuo la cifratura
	size_t tmpLength = 0;
	size_t resultLength = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, iv);
	EVP_EncryptUpdate(ctx, cipherText, &tmpLength, plainText, sizeof(uint32_t));
	EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);

	cipherTextSize = tmpLength + resultLength;

	// Invio la dimensione cifrata
	done = send(socket, (void*)&cipherText, cipherTextSize, 0);
	if(done < 0){
		cerr << "Error sending size" << endl;
		explicit_bzero(plainText, MAX_NAME_SIZE);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	done = sendDigest(socket, cipherText, cipherTextSize);
	if(done < 0){
		cerr << "Error sending digest" << endl;
		explicit_bzero(plainText, MAX_NAME_SIZE);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	explicit_bzero(plainText, MAX_NAME_SIZE);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}


int sendString(int socket, string s){
	int done;
	size_t length = s.size() + 1;
	done = sendSize(socket,length);

	if(done < 0){
		return -1;
	}
	done = sendIV(socket);
	if(done < 0){
		return -1;
	}

	unsigned char plainText[MAX_NAME_SIZE];
	unsigned char cipherText[MAX_NAME_SIZE+blockSize];
	memcpy(plainText, s.c_str(), s.size());
	plainText[s.size()] = '\0';

	// Effettuo la cifratura
	size_t tmpLength = 0;
	size_t resultLength = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, iv);
	EVP_EncryptUpdate(ctx, cipherText, &tmpLength, plainText, sizeof(uint32_t));
	EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);

	cipherTextSize = tmpLength + resultLength;

	// Invio il messaggio cifrato
	done = send(socket, (void*)&cipherText, 0);
	if(done < 0){
		cerr << "Error sending string" << endl;
		explicit_bzero(plainText, MAX_NAME_SIZE);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	done = send_digest(socket, cipherText, cipherTextSize);
	if(done < 0){
		cerr << "Error sending digest" << endl;
		explicit_bzero(plainText, MAX_NAME_SIZE);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	explicit_bzero(pt,MAX_NAME_SIZE);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}


int sendSize(int socket,size_t length){
	int done;

	// Invio il nonce
	done = sendIV(socket);
	if(done < 0){
		cerr << "Error sending initialization vector" << endl;
		return -1;
	}

	unsigned char plainText[sizeof(uint32_t)];
	unsigned char cipherText[blockSize];

	uint32_t messageLength = htonl(length);
	memcpy(plainText, &len, sizeof(uint32_t));

	// Effettuo la cifratura
	size_t tmpLength = 0;
	size_t resultLength = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, iv);
	EVP_EncryptUpdate(ctx, cipherText, &tmpLength, plainText, sizeof(uint32_t));
	EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);

	cipherTextSize = tmpLength + resultLength;

	// Invio la dimensione cifrata
	done = send(socket, (void*)&cipherText, cipherTextSize, 0);
	if(done < 0){
		cerr << "Error sending size" << endl;
		explicit_bzero(plainText, MAX_NAME_SIZE);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	done = sendDigest(socket, cipherText, cipherTextSize);
	if(done < 0){
		cerr << "Error sending digest" << endl;
		explicit_bzero(plainText, MAX_NAME_SIZE);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	explicit_bzero(plainText, MAX_NAME_SIZE);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}


int sendIV(int socket){
	int done;
	done = RAND_poll();
	if(done != 1){
		cerr << "Error in rand_poll()" << endl;
		return -1;
	}

	unsigned char ivDigest[ivLength];
	unsigned char digest[hashSize];

	// Genero un numero random
	done = RAND_bytes(iv, sizeof(unsigned char)*ivLength);
	if(done != 1){
		cerr << "Error in rand_bytes()" << endl;
		return -1;
	}
	unsigned char bufferCounter[sizeof(size_t)+cipherTextSize];
	unsigned char digest[hashSize];

	memcpy(bufferCounter, &counter, sizeof(size_t));
	memcpy(bufferCounter + sizeof(size_t), cipherText, cipherTextSize);

	// Inizio HMAC
	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, iv, ivLength);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t));
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);

	for(size_t i=0; i < ivLength; ++i){
		ivDigest[i] = iv[i];
	}
	for(size_t i=ivLength; i < ivLength; ++i){
		ivDigest[i] = digest[i-ivLength];
	}
	done = send(socket, (void*)&ivDigest, ivLength + hashSize, 0);
	if(done < 0){
		cerr<<"Error sending IV"<<endl;
		return -1;
	}
	counter++;
	return 0;
}

string receiveString(int socket){
	int done, size, length = 0;
	string s;
	uint32_t size = receiveSize(socket);

	int done = getIV(socket);

	if(done != 0){
		cerr << "Error sending IV" << endl;
		return s;
	}
	unsigned char plainText[MAX_NAME_SIZE+blockSize];
	unsigned char cipherText[MAX_NAME_SIZE+blockSize];

	size = ((length/blockSize)+1)*blockSize;

	done = recv(socket, (void*)&cipherText, size, MSG_WAITALL);
	if(done <= 0 || done < (int)(size)){
		cerr << "Error receiving size" << endl;
		return s;
	}

	done = checkDigest(socket, cipherText, size);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Inizializzo un contesto per decriptare il messaggio
	EVP_DecryptInit(ctx, EVP_aes_128_cbc(), securityKey, iv);
	EVP_DecryptUpdate(ctx, plainText, &length, cipherText, size);
	EVP_DecryptFinal(ctx, plainText+length, &length);
	EVP_CIPHER_CTX_free(ctx);

	s = string((char*)plainText);

	explicit_bzero(plainText, MAX_FILENAME_SIZE+blockSize);
	return s;
}


uint32_t receiveSize(int socket){
	int done;
	done = receiveIV(socket);
	if(done != 0){
		cerr << "Error sending IV"<<endl;
		return 0;
	}

	unsigned char plainText[blockSize];
	unsigned char cipherText[blockSize];

	uint32_t length;
	done = recv(socket, (void*)&cipherText, blockSize, MSG_WAITALL);

	if(done <= 0 || done < (int)blockSize){
		cerr<<"Error receiving size"<<endl;
		return 0;
	}
	done = checkDigest(socket, cipherText, blockSize);
	if(done < 0){
		cerr<<"Error checking digest"<<endl;
		return 0;
	}
	int length = 0;
	EVP_CIPHER_CTX *ctx =
}
int checkDigest(int socket, unsigned char* message, int length){
	int done;
	unsigned char digest[hashSize];
	unsigned char receivedDigest[hashSize];
	unsigned char bufferCounter[sizeof(size_t) + length];

	// Get digest

	done = recv(socket, (void*)&receivedDigest, hashSize);
	if(done <= 0 || done < (int)(hashSize)){
		cerr << "Error receiving counter" << endl;
		return -1;
	}
	memcpy(bufferCounter, &counter, sizeof(size_t));
	memcpy(bufferCounter + sizeof(size_t), message, length);

	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t) + length);
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);

	// Checking if digest is correct

	done = CRYPTO_memcmp(digest, receivedDigest, hashSize);
	if(done != 0){
		cerr << "The received digest is wrong" << endl;
		return -1;
	}
	counter++;
	return 0;
}
int receiveIV(int socket){
	int done;
	unsigned char digest[hashSize];
	unsigned char receivedDigest[hashSize];
	unsigned char ivDigest[hashSize+ivLength];
	unsigned char ivTmp[ivLength];

	done = recv(socket, (void*)&ivDigest, ivLength + hashSize, MSG_WAITALL);

	if(done <= 0 || done < (int)(ivLength+hashSize)){
		cout << "Error receive IV" <<endl;
		return -1;
	}

	// Splitto
	for(size_t i=0; i < ivLength; ++i){
		ivTmp[i] = ivDigest[i];
	}
	for(size_t i=0; i < hashSize; ++i){
		receivedDigest[i] = ivDigest[i+ivLength];
	}

	unsigned char bufferCounter[sizeof(size_t)];
	memcpy(bufferCounter, &counter, sizeof(size_t));

	// Effettuo HMAC
	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, ivTmp, ivLength);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t));
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);

	done = CRYPTO_memcmp(digest, receivedDigest, hashSize);
	if(done != 0){
		cerr << "Error checking digest" << endl;
		return -1;
	}
	memcpy(iv, ivTmp, ivLength);
	counter++;

	return 0;
}
int receiveFile(int socket, string file){
	int done;
	uint32_t fullSize = 0;
	ofstream os;
	os.open(file);

	if(os){
		done = getIV(socket);
		if(done < 0){
			cerr << "Error sending IV" << endl;
			return -1;
		}

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(ctx, EVP_aes_128_cbc(), securityKey, iv);

		fullSize = receiveSize(socket);
		if(length <= 0){ // TO BE CHECKED
			cerr << "Error receiving size" << endl;
			fs::remove(fs::path(file));
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		unsigned char digest[hashSize];
		unsigned char receivedDigest[hashSize];
		unsigned char plainText[BUF_SIZE+blockSize];
		unsigned char cipherText[BUF_SIZE+blockSize];
		unsigned char cipherTextDigest[BUF_SIZE+hashSize];
		unsigned char cipherTextCount[BUF_SIZE+sizeof(size_t)];

		int packets = fullSize/BUF_SIZE;
		int lastSize = fullSize - (BUF_SIZE*packets);

		if(lastSize == 0 && fullSize > 0){
			packets--;
		}
		if(packets > 0){
			packets += blockSize;
		}
		int receivedSizeTemp = ((fullSize/blockSize)+1)*blockSize - (BUF_SIZE*packets);

		unsigned char cipherTextDigestTemp[receivedSizeTemp + hashSize];
		unsigned char cipherTextCountTemp[receivedSizeTemp + hashSize];

		int length = 0;

		done = getIV(socket);
		if(done < 0){
			cerr << "Error sending the IV" << endl;
			return -1;
		}
		for(size_t i=0; i<(size_t)packets; ++i){
			explicit_bzero(plainText, BUF_SIZE+blockSize);
			explicit_bzero(cipherText, BUF_SIZE+blockSize);
			explicit_bzero(digest, hashSize);
			explicit_bzero(receivedDigest, BUF_SIZE+hashSize);
			explicit_bzero(cipherTextDigest, BUF_SIZE+hashSize);
			explicit_bzero(cipherTextCount, BUF_SIZE+hashSize);

			done = receiveFile(socket, (void*)&cipherTextDigest, BUF_SIZE+hashSize, MSG_WAITALL);
			if(done <= 0 || done < (int)(BUF_SIZE+hash_size)){
				cerr << "Error receiving file" << endl;
				fs:remove(fs::path(filename));
				explicit_bzero(cipherTextDigest, BUF_SIZE+hashSize);
				EVP_CIPHER_CTX_free(ctx);
				return -1;
			}
			for(size_t i = 0; i<(size_t)hashSize; ++i){
				receivedDigest[i] = cipherTextDigest[i+BUF_SIZE];
			}
			memcpy(cipherTextCount+BUF_SIZE, &counter, sizeof(size_t));

			HMAC_CTX* ctx = HMAC_CTX_new();
			HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
			HMAC_Update(ctx, cipherTextCount, BUF_SIZE+sizeof(size_t));
			HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
			HMAC_CTX_free(ctx);

			done = CRYPTO_memcmp(digest, receivedDigest, hashSize);
			if(done != 0){
				cerr << "Error checking digest" << endl;
				explicit_bzero(plainText, BUF_SIZE+blockSize);
				explicit_bzero(cipherText, BUF_SIZE+blockSize);
				explicit_bzero(digest, hashSize);
				explicit_bzero(receivedDigest, hashSize);
				explicit_bzero(cipherTextDigest, hashSize);
				explicit_bzero(receivedDigest, hashSize);
				EVP_CIPHER_CTX_free(ctx);
				return -1;
			}
			counter++;
			EVP_DecryptUpdate(ctx, plainText, &length, cipherText, BUF_SIZE);
			os.write((char*)plainText, length);
		}
		explicit_bzero(plainText, BUF_SIZE+blockSize);
		explicit_bzero(cipherText, BUF_SIZE+blockSize);
		explicit_bzero(digest, hashSize);
		explicit_bzero(receivedDigest, hashSize);
		explicit_bzero(cipherTextDigest, hashSize);
		explicit_bzero(receivedDigest, hashSize);
		explicit_bzero(cipherTextDigestTemp, receivedSizeTemp + hashSize);
		explicit_bzero(cipherTextCountTemp, receivedSizeTemp+sizeof(size_t));

		done = recv(socket, (void*)&cipherTextDigestTemp, receivedSizeTemp+hashSize, MSG_WAITALL);
		if(done <= 0 || done < (int)(receivedSizeTemp+hashSize)){
			cerr << "Error receiving file" << endl;
			fs::remove(fs::path(file));
			explicit_bzero(plainText, BUF_SIZE+blockSize);
			explicit_bzero(cipherText, BUF_SIZE+blockSize);
			explicit_bzero(cipherTextDigestTemp, receivedSizeTemp+hashSize);
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		unsigned char cipherTextCrypcount[receivedSizeTemp+blockSize]; // !!
		explicit_bzero(cipherTextCrypcount, receivedSizeTemp+blockSize);

		// Deconcateno
		for(size_t i=0; i<(size_t)receivedSizeTemp; ++i){
			cipherTextCountTemp[i] = cipherTextDigestTemp[i];
			cipherText[i] = cipherTextDigestTemp[i];
		}

		for(size_t i=0; i<(size_t)hashSize; ++i){
			receivedDigest[i] = cipherTextDigestTemp[i+receivedSizeTemp];
		}

		memcpy(cipherTextCountTemp+receivedSizeTemp, &counter, sizeof(size_t));

		HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
		HMAC_Update(ctx, cipherTextCountTemp, receivedSizeTemp+sizeof(size_t));
		HMAC_FINAL(ctx, digest, (unsigned int*)&hashSize);
		HMAC_CTX_free(ctx);

		done = CRYPTO_memcmp(digest, receivedDigest, hashSize);
		if(done != 0){
			cerr << "Error checking digest" << endl;
			explicit_bzero(plainText, BUF_SIZE+blockSize);
			explicit_bzero(cipherText, BUF_SIZE+blockSize);
			explicit_bzero(digest, hashSize);
			explicit_bzero(receivedDigest, hashSize);
			explicit_bzero(cipherTextDigest, BUF_SIZE+hashSize);
			explicit_bzero(cipherTextCount, BUF_SIZE+hashSize);
			explicit_bzero(cipherTextDigestTemp, receivedSizeTemp+hashSize);
			explicit_bzero(cipherTextCountTemp, receivedSizeTemp+sizeof(size_t));
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}
		counter++;
		EVP_DecryptUdate(ctx, plainText, &length, cipherText, receivedSizeTemp);
		EVP_DecryptFinal(ctx, plainText+length, &length);
		os.write((char*)plainText, lastSize);
		explicit_bzero(plainText, BUF_SIZE+blockSize);
		EVP_CIPHER_CTX_free(ctx);
		os.close();
		return fullSize;
	}
}









*/
