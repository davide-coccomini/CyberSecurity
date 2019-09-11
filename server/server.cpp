#include <string>
#include <string.h>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <fstream>
#include <unistd.h>
#include "../const.h"
#include "../utilityFunctions.cpp"
#include "../DH.h"
#include <experimental/filesystem> //

using namespace std;
namespace fs = std::experimental::filesystem;//

class file {

	unsigned long dimension;
	string name;

	public:
		file(string givenName, unsigned long givenDimension){
			name = givenName;
			dimension = givenDimension;
		}
		string getName(){
			return name;
		}
		unsigned long getDimension(){
			return dimension;
		}
};

class Server {

	const char* allowedChars = ".-_@qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890";

	vector<string> authorizedClients;
	vector<file> files;

	int clientFd;
	int socketFd;

	struct sockaddr_in serverAddress, clientAddress;

	EVP_PKEY* privateKey;

	X509_CRL* crl;
	X509* serverCertification;
	X509* CACertification;

	X509_STORE* store;

	public:

	Server(){
		loadCertificates();
		createStore();
		loadClients();
		socketActivation();
	}

	void loadCertificates(){

		//apertura file
		string fileName = "../certificates/Server_cert.pem";
		FILE * certFile = fopen(fileName.c_str(), "r");
		if(!certFile){
			cerr << "Error while opening file "<< fileName << endl;
			exit(1);
		}
		//lettura certificato
		serverCertification = PEM_read_X509(certFile, NULL, NULL, NULL);
		fclose(certFile);
		if(!serverCertification) {
			cerr << "Error: PEM_read_X509 returned NULL\n"; //DA RIVEDERE
			exit(1);
		}

		//apertura file
		fileName = "../certificates/CoccominiPulizzi_CA_cert.pem";
		certFile = fopen(fileName.c_str(), "r");
		if(!certFile){
			cerr << "Error while opening file "<< fileName << endl;
			exit(1);
		}
		//lettura certificato
		CACertification = PEM_read_X509(certFile, NULL, NULL, NULL);
		fclose(certFile);
		if(!CACertification) {
			cerr << "Error: PEM_read_X509 returned NULL\n";//DA RIVEDERE
			exit(1);
		}

		fileName = "../certificates/CoccominiPulizzi_CA_crl.pem";
		certFile = fopen(fileName.c_str(), "r");
		if(!certFile){
			cerr << "Error while opening file "<< fileName << endl;
			exit(1);
		}
		crl = PEM_read_X509_CRL(certFile, NULL, NULL, NULL);
		fclose(certFile);
		if(!crl){
			cerr << "Error: PEM_read_X509_CRL returned NULL\n"; //DA RIVEDERE
			exit(1);
		}

	}

	void createStore(){
		store = X509_STORE_new();
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
	}

	void loadClients(){ // Read and save the authorized clients
		ifstream f("authorizedClients.txt");
		if(!f.is_open()){
			cout << "Errors while opening authorized clients" <<endl;
			exit(1);
		}
		string client;
		do {
			getline(f,client);
			if(f)
				authorizedClients.push_back(client);
		} while(f);

	}

	void showClients(){ //funzione di test, DA CANCELLARE
		for(int i = 0; i < (int)authorizedClients.size(); i++){
			cout<<authorizedClients[i]<<endl;
		}
		cout<<"num clients: "<<(int)authorizedClients.size()<<endl;
	}

	void socketActivation(){
		socketFd = socket(AF_INET, SOCK_STREAM, 0);

		memset(&serverAddress, 0, sizeof(serverAddress));
		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port = htons(SERVER_PORT); //Da vedere
		serverAddress.sin_addr.s_addr = INADDR_ANY;

		int ret = bind(socketFd, (sockaddr*)&serverAddress, sizeof(serverAddress));
		if (ret < 0) {
			cerr<<"ERROR: error in binding the socket"<<endl;
			close(socketFd);
			exit(1);
		}

		ret = listen(socketFd, 10);
		if(ret < 0) {
			cerr<<"ERROR: error in listening" <<endl;
			close(socketFd);
			exit(1);
		}
		cout<<"Server is listening to port " << SERVER_PORT <<endl;
	}

	int keySharing(){
		//caricamento chiave privata
		privateKey = loadPrivateKey("../certificates/Server_key.pem");

		//caricamento sessione dh
		DH *dhSession;
		dhSession = get_dh3072(); //carica i valori p e g presenti sul file DH.h
		DH_generate_key(dhSession); //sceglie random la chiave privata e calcola di conseguenza la chiave pubblica
		//DH public key of the server
		const BIGNUM *Ya;
		DH_get0_key(dhSession, &Ya, NULL); //ritorna la chiave pubblica, c'è però un'altra funzione che hanno spiegato in classe che fa la stessa cosa: BIGNUM* DH_get0_pub_key(DH* dh)

		//M1: invio Ya
		unsigned char YaBin[SIZE_Y_DH];
		int ret = BN_bn2bin(Ya, YaBin);
		if( ret < SIZE_Y_DH){
			EVP_PKEY_free(privateKey);
			cerr<<"Error converting in binary"<<endl;
			return -1;
		}

		ret = send(clientFd, (void*)&YaBin, SIZE_Y_DH, 0);
		if (ret < 0) {
			EVP_PKEY_free(privateKey);
			cerr<<"Error sending Ya"<<endl;
			return -1;
		}

		//M2: Ricezione Yb, {<Ya,Yb>B}Kab, Bcert
		//Ricezione lunghezza certificato client
		int certSize;
		ret = recv(clientFd, (void*)&certSize, sizeof(int), MSG_WAITALL);
		if (ret < (int)sizeof(int)){
			EVP_PKEY_free(privateKey);
			cerr<<"Error receiving certificate"<<endl; //DA RIVEDERE
			return -1;
		}
		certSize = ntohl(certSize);
		//Ricezione M2
		unsigned char M2[SIZE_Y_DH+EVP_PKEY_size(privateKey)+(int)blockSize+certSize];

		ret = recv(clientFd, (void*)M2, SIZE_Y_DH+EVP_PKEY_size(privateKey)+(int)blockSize+certSize, MSG_WAITALL);
		if (ret < SIZE_Y_DH+EVP_PKEY_size(privateKey)+(int)blockSize+certSize) {
			EVP_PKEY_free(privateKey);
			cerr << "Error receiving M2"<<endl;
			return -1;
		}

		unsigned char YbBin[SIZE_Y_DH];
		unsigned char ciphertext[EVP_PKEY_size(privateKey)+(int)blockSize];
		unsigned char* certBuf = (unsigned char*)malloc(certSize);

		for(int i=0; i<SIZE_Y_DH; ++i){
        	YbBin[i] = M2[i];
        }
        for(int i=0; i<(EVP_PKEY_size(privateKey)+(int)blockSize); ++i){
            ciphertext[i] = M2[i+SIZE_Y_DH];
        }
        for(int i=0; i<certSize; ++i){
            certBuf[i]=M2[i+SIZE_Y_DH+EVP_PKEY_size(privateKey)+(int)blockSize];
        }

		//verifica certificato client tramite store
		X509 *receivedCertificate = d2i_X509(NULL, (const unsigned char**)&certBuf, certSize);
		if(!receivedCertificate) {
			EVP_PKEY_free(privateKey);
			free(certBuf);
			cerr<<"Error converting certificate"<<endl;
			return -1;
		}
		free(certBuf-certSize);
		X509_STORE_CTX* certCtx = X509_STORE_CTX_new();
		if(!certCtx) {
			EVP_PKEY_free(privateKey);
			cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
			return -1;
		}
		ret = X509_STORE_CTX_init(certCtx, store, receivedCertificate, NULL);
		if(ret != 1) {
			EVP_PKEY_free(privateKey);
			cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
			return -1;
		}
		ret = X509_verify_cert(certCtx);
		if(ret != 1) {
			EVP_PKEY_free(privateKey);
			cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
			return -1;
		}
		X509_STORE_CTX_free(certCtx);

		//verifica se il client è autorizzato a connettersi
		X509_NAME *cn = X509_get_subject_name(receivedCertificate);
		char *tempVar = X509_NAME_oneline(cn, NULL, 0);
		string clientName = string(tempVar);
		free(tempVar);
		bool authorized = false;
		for(int i = 0; i < (int)authorizedClients.size(); i++){
			if(clientName.compare(authorizedClients[i]) == 0){
				authorized = true;
				break;
			}
		}
		if(!authorized){
			EVP_PKEY_free(privateKey);
			cerr << "Client with name " << clientName << " has tried to connect but is not authorized" << endl;
			return -1;
		}

		//calcolo Kab
		BIGNUM* Yb;
		Yb = BN_bin2bn(YbBin, SIZE_Y_DH, NULL);
        if(Yb == NULL){
            EVP_PKEY_free(privateKey);
            cout<<"Error in converting client's Yb"<<endl;
            return -1;
        }
		const BIGNUM* p;
        DH_get0_pqg(dhSession, &p, NULL, NULL);
        unsigned char Kab[BN_num_bytes(p)];

        ret = DH_compute_key(Kab, Yb, dhSession);
        if(ret < 0){
            EVP_PKEY_free(privateKey);
            cout<<"Error in comute shared key Kab"<<endl;
			return -1;
        }

		BN_free(Yb);
		cout<<"Kab CALCOLATA!"<<endl;

		ret = builtSessionKeys(Kab, BN_num_bytes(p));
		if(ret < 0){
			return -1;
        }
		//decripta M2 con Kab
		unsigned char receivedSign[EVP_PKEY_size(privateKey)+(int)blockSize];
		int plainlen, outlen;

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(ctx, EVP_aes_128_ecb(), Ksec, NULL);
		EVP_DecryptUpdate(ctx, receivedSign, &outlen, ciphertext, EVP_PKEY_size(privateKey)+(int)blockSize);
		plainlen=outlen;
		EVP_DecryptFinal(ctx, receivedSign+plainlen, &outlen);
		plainlen += outlen;
		EVP_CIPHER_CTX_free(ctx);

		//lettura publicKey del client dal certificato
		EVP_PKEY *clientPublicKey = X509_get_pubkey(receivedCertificate);
		if(clientPublicKey == NULL) {
			EVP_PKEY_free(privateKey);
			cerr << "Error getting client public key" <<endl;
			return -1;
		}

		//verifica la firma
		unsigned char YaConcatYb[2*SIZE_Y_DH];
        for(int i=0; i<SIZE_Y_DH; ++i){
            YaConcatYb[i] = YaBin[i];
        }
        for(int i=0; i<SIZE_Y_DH; ++i){
            YaConcatYb[i+SIZE_Y_DH] = YbBin[i];
        }

		EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
		if(!mdctx){
			deleteKeys();
			EVP_PKEY_free(privateKey);
			cerr << "Error: EVP_MD_CTX_new returned NULL\n";
			return -1;
		}
		ret = EVP_VerifyInit(mdctx, md);
		if(ret == 0){
			deleteKeys();
			EVP_PKEY_free(privateKey);
			cerr << "Error: EVP_VerifyInit returned " << ret << "\n";
			return -1;
		}
		ret = EVP_VerifyUpdate(mdctx, YaConcatYb, 2*SIZE_Y_DH);
		if(ret == 0){
			deleteKeys();
			EVP_PKEY_free(privateKey);
			cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";
			return -1;
		}
		ret = EVP_VerifyFinal(mdctx, receivedSign, EVP_PKEY_size(privateKey), clientPublicKey);
		if(ret != 1){
			deleteKeys();
			EVP_PKEY_free(privateKey);
			cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
			return -1;
		}
		EVP_MD_CTX_free(mdctx);
		cout<<"verifica di M2 andata a buon fine"<<endl;

		//M3

		//firma di <Ya,Yb>
		unsigned char signature[EVP_PKEY_size(privateKey)];
		unsigned int signatureLen;
		mdctx = EVP_MD_CTX_new();
        if(!mdctx){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cout<< "Error: EVP_MD_CTX_new returned NULL"<<endl; //DA MODIFICARE
            exit(1);
        }

        ret = EVP_SignInit(mdctx, md);
        if(ret == 0){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cerr << "Error: EVP_SignInit returned " << ret << "\n"; //DA MODIFICARE
            exit(1);
        }

        ret = EVP_SignUpdate(mdctx, YaConcatYb, 2*SIZE_Y_DH);
        if(ret == 0){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; //DA MODIFICARE
            exit(1);
        }

        ret = EVP_SignFinal(mdctx, signature, &signatureLen, privateKey);
        if(ret == 0){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cerr << "Error: EVP_SignFinal returned " << ret << "\n"; //DA MODIFICARE
            exit(1);
        }
        EVP_MD_CTX_free(mdctx);

		//Cifratura di <Ya,Yb>A
        int cipherLen, outLen;
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_aes_128_ecb(), Ksec, NULL);
        EVP_EncryptUpdate(ctx, ciphertext, &outLen, signature, EVP_PKEY_size(privateKey));
        cipherLen = outLen;
        EVP_EncryptFinal(ctx, ciphertext+cipherLen, &outLen);
        cipherLen += outLen;
        EVP_CIPHER_CTX_free(ctx);
		//in ciphertext c'è il mess cifrato

		//Serializzazione certificato
        certBuf = NULL;
        certSize = i2d_X509(serverCertification, &certBuf); //serializza il certificato

		//Composizione di M3
		unsigned char M3[cipherLen+certSize];
        for(int i=0; i<(int)cipherLen; ++i){
            M3[i]=ciphertext[i];
        }
        for(int i=0; i<certSize; ++i){
            M3[i+(int)cipherLen]=certBuf[i];
        }
		OPENSSL_free(certBuf);

		//M3: Invio {<Ya,Yb>A}Kab, Acert
        // Invio lunghezza certification
        int cs=htonl(certSize);
        ret = send(clientFd, (void*)&cs, sizeof(int), 0);
        if (ret < 0) {
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cerr << "Error sending certificate" <<endl; //DA RIVEDERE
            exit(1);
        }

        //invio M3
        ret = send(clientFd, (void*)M3, (int)cipherLen+certSize, 0);
        if (ret < 0) {
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cerr << "Error sending M2" <<endl;//DA RIVEDERE
            exit(1);
        }
		cout<<"M3 inviato."<<endl;
	return 0;
	}

	void startToRun(){
		while(true){
			unsigned int len = sizeof(clientAddress);
			clientFd = accept(socketFd, (struct sockaddr*)&clientAddress, (socklen_t*)&len);
			if(clientFd<0){
				cout<<"Accept goes wrong"<<endl;
				continue;
			}

			// inizializzo iv e counter
			iv = 0;
			counter = 0;

			int ret = keySharing();
			if(ret<0){
				close(clientFd);
				continue;
			}
		}
		/*
		unsigned int len = sizeof(clientAddress);
		clientFd = accept(socketFd, (struct sockaddr*)&clientAddress, (socklen_t*)&len);
		if(clientFd<0){
			cout<<"Accept goes wrong"<<endl;
			exit(1); //MODIFICARE
		}
*/
	}

	void handleClient(){
		// !!! CONTROLLARE IL WARP-AROUND !!!

		//RICEVERE COMANDO
	}
/*
void loadPrivateKey(){
string fileName = "ertificates/Server_key.pem";
FILE* fileK = fopen(fileName.c_str(), "r");
if(!fileK){
	cerr << "ERROR: Error while opening server key file"<<endl;
	exit(1);
}

privateKey = = PEM_read_PrivateKey(fileK, NULL, NULL, NULL);
fclose(fileK);
if(!privateKey){
	cerr << "ERROR: error in reading private key"<<endl;
	exit(1);
}
}


void initFileList(){ // Read and save the files on the server
	files.clear();
	string dir = "server/files";
	for(const auto & entry : fs::directory_iterator(dir)){
		file f = file(fs::file_size(entry.path()),string(entry.path().filename()));
		files.push_back(f);
	}
}

void getFiles(){ // Print the files on the server
	string dir = "server/files";
	cout << "Files on the server:"<<endl;
	for(const auto & entry : fs::directory_iterator(dir))
		cout << "- " << string(entry.path().filename()) << "\t "<< fs::file_size(entry.path()) << endl;

}


void executeCommand(){ // Manage the received command
	while(1){*/
		/*
		if((SIZE_MAX - counter) < MAX_COUNTER){
			counter = 0;
			keySharing();
		}
		int flags = 0;
		string cmd = recv_string(clientFd, &flags);
		*//*
		if(!cmd.compare("list")){
			cout << "Listing request received..."<<endl;
			initFileList();
			ofstream os;
			os.open("server/files");

			string filesOnServer;
			for(size_t i = 0; i < files.size(); ++i)
				filesOnServer += files[i].get_name() + '\t';
			const char *a = files.c_str();
			os.write(a, files.size()+1);
			os.close();

			size_t length = 0;
			for(const auto & entry : fs::directory_iterator("files")){
				if(string(!entry.path().filesname()).compare("list.txt")){
					length = fs::file_size(entry.path());
					break;
				}
			}
			int ret = sendFile(clientFd, "server/list.txt", length);
			if(ret < 0){
				cerr << "Error while sending the list of files on the server" << endl;
				continue;
			}
			fs::remove(fs::path("server/list.txt"));
		}else if(!cmd.compare("download")){
			initFileList();
			int flags = 0;
			string fileName = receiveString(clientFd, &flags);

			string dir = "server/files/" + fileName;
			if(flags == 1)
				continue;

			size_t length = 0;
			bool found = false;
			for(size_t i = 0; i < files.size(); i++){
				length = files[i].get_size();
				size_t maxSize = pow(2,32); // 4GB
				if(length < maxSize){
					cout << "Sending file ... "<<endl;
					bool found = true;
					int ret = sendFile(clientFd, dir, length);
					if(ret < 0)
						break;
				}else{
					cout << "Invalid file size" << endl;
					found = true;
					break;
				}
			}
			if(!found){
				cout << "File not found" << endl;
			}
			continue;
		}



	}

}


void keyGeneration(unsigned char *g_ab, int length){} // Generate keys
int keySharing(){} // Implements the sharing of the keys for station-to-station
void resetKeys(){} // Delete all the keys generated
}

*/
};









int main(){
	system("clear");
	Server s;
	cout << "The server is ready" <<endl;
	//s.listen();
	s.startToRun();
	s.keySharing();
	return 0;

}
