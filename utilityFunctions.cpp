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

#include "const.h"

#include <signal.h>

namespace fs = std::experimental::filesystem;
using namespace std;


//copiati dal file functions.cpp
const size_t blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
const EVP_MD* md = EVP_sha256();

unsigned char* Ksec;
unsigned char* Kaut;
size_t counter = 0;
size_t iv = 0;

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

    if(keyLen<(EVP_CIPHER_key_length(EVP_aes_128_cbc())+EVP_MD_size(EVP_sha256()))){
        cout<<"Error in built session keys, Kab is too short"<<endl;
        return -1;
    }
    Ksec = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    if(!Ksec) {
        cerr << "Error in built session keys, malloc returned NULL"<<endl;
        return -1;
    }
    Kaut = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if(!Kaut) {
        cerr << "Error in built session keys, malloc returned NULL"<<endl;
        return false;
    }
    for(int i=0; i<EVP_CIPHER_key_length(EVP_aes_128_cbc()); ++i){
        Ksec[i]=Kab[i];
    }
    for(int i=0; i<EVP_MD_size(EVP_sha256()); ++i){
        Kaut[i]=Kab[keyLen-EVP_MD_size(EVP_sha256())+i];
    }
    explicit_bzero(Kab, keyLen);
return 1;
}

void deleteKeys() {
    explicit_bzero(sec_key, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    free(sec_key);
    explicit_bzero(aut_key, EVP_MD_size(EVP_sha256()));
    free(aut_key);
}
