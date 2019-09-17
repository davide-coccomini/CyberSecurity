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
namespace fs = std::experimental::filesystem;
using namespace std;

int connectionStatus;

unsigned char* securityKey;
unsigned char* authenticationKey;
const EVP_MD* md = EVP_sha256();
const size_t authenticationKeySize = sizeof(authenticationKey);
const size_t blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
const size_t hashSize = EVP_MD_size(md);
const size_t ivLength = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

size_t counter = 0;
size_t iv = 0;
unsigned char ivChar[sizeof(size_t)];

//COME CIFRARE I MESSAGGI:
//1) ciphertext = AES128(K_sec, m)
//2) digest = SHA256(K_aut, counter || ciphertext)
//3) mandiamo digest || ciphertext

void createDigest(unsigned char* ct, int ctSize, unsigned char* digest){
	unsigned char bufferCounter[sizeof(size_t)+ctSize];

	memcpy(bufferCounter, &counter, sizeof(size_t));
	memcpy(bufferCounter + sizeof(size_t), ct, ctSize);

	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t) + ctSize);
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);
}

int sendSize(int socket, size_t length){

	unsigned char plainText[sizeof(uint32_t)];
	unsigned char cipherText[blockSize];
	unsigned char concatenatedText[blockSize+hashSize];
	unsigned char digest[hashSize];

	uint32_t messageLength = htonl(length);
	memcpy(plainText, &messageLength, sizeof(uint32_t));

	// Generate the cipherText
	int tmpLength = 0;
	int resultLength = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_EncryptUpdate(ctx, cipherText, &tmpLength, plainText, sizeof(uint32_t));
	EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);
	resultLength+=tmpLength;

	// Create the digest
	createDigest(cipherText, blockSize, digest);

	memcpy(concatenatedText, cipherText, blockSize);
	memcpy(concatenatedText+blockSize, digest, hashSize);

	// Send the message
	int done = send(socket, (void*)&concatenatedText, blockSize+hashSize, 0);
	if(done <= 0){
		cerr << "Error sending size" << endl;
		explicit_bzero(plainText, sizeof(uint32_t));
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//iv++;
	memcpy(ivChar, &iv, sizeof(size_t));
	//counter++;

	explicit_bzero(plainText,sizeof(uint32_t));
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}



int sendString(int socket, string s){

	size_t length = s.size() + 1;
	int done = sendSize(socket,length);
	if(done<0) return -1;

	unsigned char plainText[length];
	unsigned char cipherText[length+blockSize];
	unsigned char concatenatedText[length+blockSize+hashSize];
	unsigned char digest[hashSize];

	memcpy(plainText, s.c_str(), s.size());
	plainText[s.size()] = '\0';

	// Generate the cipherText
	int tmpLength = 0;
	int resultLength = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_EncryptUpdate(ctx, cipherText, &tmpLength, plainText, length);
	EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);
	resultLength+=tmpLength;

	// Create the digest
	createDigest(cipherText, resultLength, digest);

	memcpy(concatenatedText, cipherText, resultLength);
	memcpy(concatenatedText+resultLength, digest, hashSize);


	// Send the message
	done = send(socket, (void*)&concatenatedText, resultLength+hashSize, 0);
	if(done < 0){
		cerr << "Error sending string" << endl;
		explicit_bzero(plainText, length);
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//iv++;
	memcpy(ivChar, &iv, sizeof(size_t));
	//counter++;

	explicit_bzero(plainText,length);
	EVP_CIPHER_CTX_free(ctx);

	return 0;
}

int checkDigest(unsigned char* receivedDigest, unsigned char* ct, int ctSize){
	int done;
	unsigned char digest[hashSize];
	unsigned char bufferCounter[sizeof(size_t) + ctSize];

	memcpy(bufferCounter, &counter, sizeof(size_t));
	memcpy(bufferCounter + sizeof(size_t), ct, ctSize);

	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t) + ctSize);
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);

	// Checking if digest is correct
	done = CRYPTO_memcmp(digest, receivedDigest, hashSize);
	if(done != 0){
		cerr << "The received digest is wrong" << endl;
		return -1;
	}
	//counter++;
	return 0;
}

uint32_t receiveSize(int socket){
	unsigned char plainText[blockSize];
	unsigned char cipherText[blockSize];
	unsigned char concatenatedText[blockSize+hashSize];
	unsigned char digest[hashSize];
	uint32_t length;
	int done = recv(socket, (void*)&concatenatedText, blockSize+hashSize, MSG_WAITALL);
	if(done < 0){
		connectionStatus=ERROR_IN_CONNECTION;
		return 0;
	}
	if(done==0){
		connectionStatus=CLIENT_DISCONNECTED;
		return 0;
	}
	int len = 0;

	// Split the message
	memcpy(cipherText, concatenatedText,blockSize);
	memcpy(digest, concatenatedText + blockSize, hashSize);

	done = checkDigest(digest, cipherText, blockSize);
	if(done < 0){
		cerr << "Error checking digest" << endl;
		return 0;
	}
	// Decrypt message
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_DecryptUpdate(ctx, plainText, &len, cipherText, blockSize);
	EVP_DecryptFinal(ctx, plainText+len, &len);
	EVP_CIPHER_CTX_free(ctx);


	memcpy(&length, plainText, sizeof(uint32_t));

	//iv++;
	//memcpy(ivChar, &iv, sizeof(size_t));
	//explicit_bzero(plainText, sizeof(uint32_t));
	return (uint32_t)ntohl(length);
}

string receiveString(int socket){
	int done, length = 0;
	unsigned char digest[hashSize];
	string s;
	uint32_t sizePt = receiveSize(socket);
	if(sizePt == 0){ return s;}

	uint32_t numBlock = (sizePt/blockSize)+1;
	unsigned char plainText[sizePt];
	unsigned char cipherText[sizePt+blockSize];
	unsigned char concatenatedText[sizePt+blockSize+hashSize];

	done = recv(socket, (void*)&concatenatedText, numBlock*blockSize+hashSize, MSG_WAITALL);
	if(done <= 0){
		connectionStatus = ERROR_IN_CONNECTION;
		cerr << "Error receiving message" << endl;
		return s;
	}
	// Split the message
	memcpy(cipherText, concatenatedText, numBlock*blockSize);
	memcpy(digest, concatenatedText + numBlock*blockSize, hashSize);
	done = checkDigest(digest, cipherText, numBlock*blockSize);
	if(done < 0){
		cerr << "Error checking digest" << endl;
		return s;
	}
	// Decrypt message
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
	EVP_DecryptUpdate(ctx, plainText, &length, cipherText, numBlock*blockSize);
	EVP_DecryptFinal(ctx, plainText+length, &length);
	EVP_CIPHER_CTX_free(ctx);

	//iv++;
	memcpy(ivChar, &iv, sizeof(size_t));
	//counter++;
	s = string((char*)plainText);
	explicit_bzero(plainText, sizePt);
	return s;
}

int sendFile(int socket, string fileName, uint32_t fileSize){
	ifstream is;
	is.open(fileName);
	if(is){

		int tmpLength = 0;
		int resultLength = 0;
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);

		// Calculate the number of blocks to be sent
		int blocks = (fileSize / BUFFER_SIZE);
		int lastBlockSize = fileSize - (BUFFER_SIZE * blocks);

		if(lastBlockSize == 0 && fileSize > 0){
			lastBlockSize = BUFFER_SIZE;
		}else{
			blocks++;
		}

		unsigned char cipherText[BUFFER_SIZE+blockSize];
		unsigned char plainText[BUFFER_SIZE];
		unsigned char digest[hashSize];
		unsigned char concatenatedText[BUFFER_SIZE+blockSize+hashSize];

		// Send the size of the file
		int done = sendSize(socket, fileSize);
		if(done < 0){
			cerr << "Error sending file size" << endl;
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}
		for(size_t i=0; i<(size_t)blocks-1; i++){//--------------------------------------------------------------------
			explicit_bzero(cipherText, BUFFER_SIZE+blockSize);
			explicit_bzero(concatenatedText, hashSize+BUFFER_SIZE+blockSize);
			explicit_bzero(plainText, BUFFER_SIZE);
			explicit_bzero(digest, hashSize);

			// Read the block to be sent
			is.read((char*)plainText, BUFFER_SIZE);

			// Create the digest and concatenate
			createDigest(plainText, BUFFER_SIZE, digest);
			memcpy(concatenatedText, plainText, BUFFER_SIZE);
			memcpy(concatenatedText+BUFFER_SIZE, digest, hashSize);

			// Generate the cipherText
			EVP_EncryptUpdate(ctx, cipherText, &tmpLength, concatenatedText, BUFFER_SIZE+hashSize);

			// Send the block
			done = send(socket, (void*)&cipherText, tmpLength, 0);
			if(done < 0){
				cerr << "Error sending block" << endl;
				explicit_bzero(plainText, BUFFER_SIZE);
				EVP_CIPHER_CTX_free(ctx);
				return -1;
			}
			//counter++;
		}
		// Send the last block
		explicit_bzero(cipherText, BUFFER_SIZE+blockSize);
		explicit_bzero(concatenatedText, hashSize+BUFFER_SIZE+blockSize);
		explicit_bzero(plainText, BUFFER_SIZE);
		explicit_bzero(digest, hashSize);

		is.read((char*)plainText, lastBlockSize);

		// Generate the cipherText
		EVP_EncryptUpdate(ctx, cipherText, &tmpLength, plainText, lastBlockSize);
		EVP_EncryptFinal(ctx, cipherText+tmpLength, &resultLength);
		resultLength+=tmpLength;

		// Create the digest and concatenate
		createDigest(cipherText, resultLength, digest);
		memcpy(concatenatedText, cipherText, resultLength);
		memcpy(concatenatedText+resultLength, digest, hashSize);



		// Send the block
		done = send(socket, (void*)&concatenatedText, resultLength+hashSize, 0);
		if(done < 0){
			cerr << "Error sending the last block" << endl;
			explicit_bzero(plainText, BUFFER_SIZE);
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		//iv++;
		memcpy(ivChar, &iv, sizeof(size_t));
		//counter++;
		explicit_bzero(plainText, BUFFER_SIZE);
		EVP_CIPHER_CTX_free(ctx);
	}

	is.close();
	return 0;
}

int receiveFile(int socket, string fileName){
	int done, length = 0;
	ofstream os;
	os.open(fileName);
	if(os) {
		int fileSize = receiveSize(socket);
		if(fileSize <=0){
			fs::remove(fs::path(fileName));
			return -1;
		}

		unsigned char cipherText[BUFFER_SIZE+blockSize];
		unsigned char plainText[BUFFER_SIZE];
		unsigned char digest[hashSize];
		unsigned char concatenatedText[BUFFER_SIZE+blockSize+hashSize];

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(ctx, EVP_aes_128_cbc(), securityKey, ivChar);
		// Calculate the number of blocks to be received
		int blocks = (fileSize / BUFFER_SIZE);
		int lastBlockSize = fileSize - (BUFFER_SIZE * blocks);

		if(lastBlockSize == 0 && fileSize > 0){
			lastBlockSize = BUFFER_SIZE;
		}else{
			blocks++;
		}
		for(size_t i=0; i<(size_t)blocks-1; i++){
			explicit_bzero(cipherText, BUFFER_SIZE+blockSize);
			explicit_bzero(plainText, BUFFER_SIZE);
			explicit_bzero(concatenatedText, hashSize+BUFFER_SIZE+blockSize);
			explicit_bzero(digest, hashSize);
			done = recv(socket, (void*)&cipherText, ((BUFFER_SIZE/blockSize)+1)*blockSize+hashSize, MSG_WAITALL);
			if(done < 0){
				cerr << "Error receiving block" << endl;
				fs::remove(fs::path(fileName));
				explicit_bzero(cipherText, BUFFER_SIZE+blockSize);
				EVP_CIPHER_CTX_free(ctx);
				return -1;
			}

			length = 0;
			// Decrypt message
			EVP_DecryptUpdate(ctx, concatenatedText, &length, cipherText, ((BUFFER_SIZE/blockSize)+1)*blockSize+hashSize);

			// Split the message
			memcpy(plainText, concatenatedText, BUFFER_SIZE);
			memcpy(digest, concatenatedText + BUFFER_SIZE, hashSize);

			done = checkDigest(digest, plainText, BUFFER_SIZE);
			if(done < 0){
				cerr << "Error checking digest" << endl;
				return -1;
			}
			//counter++;
		}

		// Receive the last block
		explicit_bzero(cipherText, BUFFER_SIZE+blockSize);
		explicit_bzero(plainText, BUFFER_SIZE);
		explicit_bzero(concatenatedText, hashSize+blockSize+BUFFER_SIZE);
		explicit_bzero(digest, hashSize);

		done = recv(socket, (void*)&concatenatedText, ((lastBlockSize/blockSize)+1)*blockSize+hashSize, MSG_WAITALL);
		if(done < 0){
			cerr << "Error receiving the last block" << endl;
			fs::remove(fs::path(fileName));
			explicit_bzero(concatenatedText, BUFFER_SIZE+blockSize+hashSize);
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}
		length = 0;

		// Split the message
		memcpy(cipherText, concatenatedText,((lastBlockSize/blockSize)+1)*blockSize);
		memcpy(digest, concatenatedText + ((lastBlockSize/blockSize)+1)*blockSize, hashSize);

		done = checkDigest(digest, cipherText, ((lastBlockSize/blockSize)+1)*blockSize);
		if(done < 0){
			cerr << "Error checking digest" << endl;
			return -1;
		}

		// Decrypt message
		EVP_DecryptUpdate(ctx, plainText, &length, cipherText, ((lastBlockSize/blockSize)+1)*blockSize+hashSize);
		EVP_DecryptFinal(ctx, plainText+length, &length);


//counter++;
		EVP_CIPHER_CTX_free(ctx);
		os.write((char*)plainText, lastBlockSize);

		explicit_bzero(plainText, BUFFER_SIZE);
		explicit_bzero(digest, hashSize);
	}

	os.close();
	return 0;
}
X509* loadCertificate(string fileName){
    FILE * certFile = fopen(fileName.c_str(), "r");
    if(!certFile){
        cerr << "Error while opening file "<< fileName << endl;
        exit(1);
    }
    X509* cert = PEM_read_X509(certFile, NULL, NULL, NULL);
    fclose(certFile);
    if(!cert) {
        cerr << "Error: PEM_read_X509 returned NULL\n"; //modificare cout
        exit(1);
    }
    return cert;
}

X509_CRL* loadCrl(string fileName){
    FILE* certFile = fopen(fileName.c_str(), "r");
    if(!certFile){
        cerr << "Error while opening file "<< fileName << endl;
        exit(1);
    }
    X509_CRL* crl = PEM_read_X509_CRL(certFile, NULL, NULL, NULL);
    fclose(certFile);
    if(!crl) {
        cerr << "Error: PEM_read_X509 returned NULL\n"; //modificare cout
        exit(1);
    }
    return crl;
}

X509_STORE* createStore(X509* CACertification, X509_CRL* crl){
    X509_STORE* store = X509_STORE_new();
    if(!store) {
        cerr << "ERROR: store not allocated"<<endl;
        exit(1);
    }

    int ret = X509_STORE_add_cert(store, CACertification);
    if(ret != 1) {
        cerr << "ERROR: error in adding CA certification in the store"<<endl;
        exit(1);
    }

    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) {
        cerr << "ERROR: error in adding CRL in the store"<<endl;
        exit(1);
    }

    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) {
        cerr << "ERROR: error in setting flag in the store"<<endl;
        exit(1);
    }
    return store;
}

EVP_PKEY* loadPrivateKey(string fileName){
    FILE* keyFile = fopen(fileName.c_str(), "r");
    if(!keyFile){
        cerr << "Error: cannot open file '" << fileName << endl;
        exit(1);
    }
    EVP_PKEY* privateKey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
    fclose(keyFile);
    if(!privateKey){
        cerr << "Error: PEM_read_PrivateKey returned NULL\n"; //DA RIVEDERE
        exit(1);
    }
    return privateKey;
}

int builtSessionKeys(unsigned char* Kab, int keyLen){
    unsigned char digest[EVP_MD_size(EVP_sha512())];
    unsigned int digestLen;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha512());
    EVP_DigestUpdate(ctx, Kab, keyLen);
    EVP_DigestFinal(ctx, digest, &digestLen);
    EVP_MD_CTX_free(ctx);

    securityKey = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    if(!securityKey) {
        cerr << "Error in built session keys, malloc returned NULL"<<endl;
        return -1;
    }
    authenticationKey = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if(!authenticationKey) {
        cerr << "Error in built session keys, malloc returned NULL"<<endl;
        return false;
    }

    memcpy(securityKey, digest, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    memcpy(authenticationKey, digest+EVP_CIPHER_key_length(EVP_aes_128_cbc()), EVP_MD_size(EVP_sha256()));
    explicit_bzero(Kab, keyLen);
return 1;
}

void deleteKeys() {
    explicit_bzero(securityKey, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    free(securityKey);
    explicit_bzero(authenticationKey, EVP_MD_size(EVP_sha256()));
    free(authenticationKey);
}
