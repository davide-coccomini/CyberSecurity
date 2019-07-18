#include <string>
#include <iostream>
#include <string.h>
#include <fstream>



#include "const.h"
unsigned char* securityKey;
unsigned char* authenticationKey;
const size_t authenticationKeySize = sizeof(authenticationKey);
const size_t blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
const size_t hashSize = EVP_MD_size(md);
const size_t ivLength = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
const EVP_MD* md = EVP_sha256();
size_t counter = 0;
unsigned char* iv;


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

int sendDigest(int socket, unsigned char* cipherText, int cipherTextSize){
	int done;
	unsigned char bufferCounter[sizeof(size_t)+cipherTextSize];
	unsigned char digest[hashSize];
	
	memcpy(bufferCounter, &counter, sizeof(size_t));
	memcpy(bufferCounter + sizeof(size_t), cipherText, cipherTextSize);
	
	// Inizio HMAC
	HMAC_CTX* ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, authenticationKey, authenticationKeySize, md, NULL);
	HMAC_Update(ctx, bufferCounter, sizeof(size_t) + cipherTextSize);
	HMAC_Final(ctx, digest, (unsigned int*)&hashSize);
	HMAC_CTX_free(ctx);
	
	// Invio il digest
	done = send(socket,(void*)&digest, hashSize, 0);
	if(done < 0){
		cerr << "Error sending counter"<<endl;
		return -1;
	}	
	counter++;
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
	string s;
	uint32_t size = receiveSize(socket, &e);

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
int checkDigest(){
	
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


























