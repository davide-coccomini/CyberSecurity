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
#include "../const.h"
#include "../utilityFunctions.cpp"
#include "../DH.h"
#include <signal.h>
namespace fs = std::experimental::filesystem;
using namespace std;


class Client {
    string allowedCommands[5] = {"list", "help", "quit", "download", "upload"};
    const char* allowedChars = ".-_qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890";

    string typedCommand;
    string typedFileName;

    X509* clientCertification, *CACertification;
    EVP_PKEY* privateKey;
    X509_STORE* store;
    X509_CRL* crl;

    sockaddr_in svAddr;
    int sd;

    const string SERVER_NAME = "/C=IT/CN=Server";

public:
    Client(){
        //load certificates and crl
        clientCertification = loadCertificate("../certificates/Client1_cert.pem");
        CACertification = loadCertificate("../certificates/CoccominiPulizzi_CA_cert.pem");
        crl = loadCrl("../certificates/CoccominiPulizzi_CA_crl.pem");

        //create store
        store = createStore(CACertification, crl);

        sd = socket(AF_INET, SOCK_STREAM, 0);
        memset(&svAddr, 0, sizeof(svAddr));
        svAddr.sin_family = AF_INET;
        svAddr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, "127.0.0.1", &svAddr.sin_addr);

        int ret = connect(sd, (struct sockaddr*)&svAddr, sizeof(svAddr));
        if (ret < 0) {
            cerr<<"Error connecting to the server"<<endl;
            exit(1);
        }
    }

    void keySharing(){
        privateKey = loadPrivateKey("../certificates/Client1_key.pem");
        //caricamento sessione dh
		DH *dhSession;
		dhSession = get_dh3072(); //carica i valori p e g presenti sul file DH.h
		DH_generate_key(dhSession); //sceglie random la chiave privata e calcola di conseguenza la chiave pubblica

        //DH public key of the server
		const BIGNUM *Yb;
		DH_get0_key(dhSession, &Yb, NULL);

        unsigned char YbBin[SIZE_Y_DH];
		int ret = BN_bn2bin(Yb, YbBin);
		if( ret < SIZE_Y_DH){
			EVP_PKEY_free(privateKey);
			cerr<<"Error converting in binary"<<endl;
			exit(1);
		}

        //M1: ricezione Ya
        BIGNUM* Ya;
        unsigned char YaBin[SIZE_Y_DH];

        ret = recv(sd, (void*)&YaBin, SIZE_Y_DH, MSG_WAITALL);
        if (ret < 0) {
			EVP_PKEY_free(privateKey);
			cerr<<"Error in receiving Ya"<<endl;
			exit(1);
		}
        //Calcolo chiave condivisa
        Ya = BN_bin2bn(YaBin, SIZE_Y_DH, NULL);
        if(Ya == NULL){
            EVP_PKEY_free(privateKey);
            cout<<"Error in converting server's Ya"<<endl;
            exit(1);
        }
        const BIGNUM* p;
        DH_get0_pqg(dhSession, &p, NULL, NULL);
        unsigned char Kab[BN_num_bytes(p)];

        ret = DH_compute_key(Kab, Ya, dhSession);
        if(ret < 0){
            EVP_PKEY_free(privateKey);
            cout<<"Error in comute shared key Kab"<<endl;
            exit(1);
        }

        ret = builtSessionKeys(Kab,BN_num_bytes(p));
		if(ret < 0){
			exit(1);
        }

        DH_free(dhSession);
		BN_free(Ya);

        //Firma <Ya,Yb>B
        unsigned char YaConcatYb[2*SIZE_Y_DH];
        for(int i=0; i<SIZE_Y_DH; ++i){
            YaConcatYb[i] = YaBin[i];
        }
        for(int i=0; i<SIZE_Y_DH; ++i){
            YaConcatYb[i+SIZE_Y_DH] = YbBin[i];
        }

        unsigned char signature[EVP_PKEY_size(privateKey)];
        unsigned int signatureLen;

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if(!mdctx){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cout<< "Error in signign"<<endl;
            exit(1);
        }

        ret = EVP_SignInit(mdctx, md);
        if(ret == 0){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cout<< "Error in signign"<<endl;
            exit(1);
        }

        ret = EVP_SignUpdate(mdctx, YaConcatYb, 2*SIZE_Y_DH);
        if(ret == 0){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cout<< "Error in signign"<<endl;
            exit(1);
        }

        ret = EVP_SignFinal(mdctx, signature, &signatureLen, privateKey);
        if(ret == 0){
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cout<< "Error in signign"<<endl;
            exit(1);
        }
        EVP_MD_CTX_free(mdctx);

        //Cifratura di <Ya,Yb>B
        unsigned char ciphertext[EVP_PKEY_size(privateKey)+blockSize];
        int cipherLen, outLen;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_aes_128_ecb(), securityKey, NULL);
        EVP_EncryptUpdate(ctx, ciphertext, &outLen, signature, EVP_PKEY_size(privateKey));
        cipherLen = outLen;
        EVP_EncryptFinal(ctx, ciphertext+cipherLen, &outLen);
        cipherLen += outLen;
        EVP_CIPHER_CTX_free(ctx);

        //Serializzazione certificato
        int certSize;
        unsigned char* certBuf = NULL;
        certSize = i2d_X509(clientCertification, &certBuf); //serializza il certificato

        //Composizione di M2

        unsigned char M2[SIZE_Y_DH+cipherLen+certSize];
        for(int i=0; i<SIZE_Y_DH; ++i){
            M2[i]=YbBin[i];
        }
        for(int i=0; i<cipherLen; ++i){
            M2[i+SIZE_Y_DH]=ciphertext[i];
        }
        for(int i=0; i<certSize; ++i){
            M2[i+SIZE_Y_DH+cipherLen]=certBuf[i];
        }

        OPENSSL_free(certBuf);

        //M2: Invio Yb, {<Ya,Yb>B}Kab, Bcert
        // Invio lunghezza certification
        int cs=htonl(certSize);
        ret = send(sd, (void*)&cs, sizeof(int), 0);
        if (ret < 0) {
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cerr << "Error sending certificate" <<endl;
            exit(1);
        }

        //invio M2
        ret = send(sd, (void*)M2, SIZE_Y_DH+cipherLen+certSize, 0);
        if (ret < 0) {
            deleteKeys();
            EVP_PKEY_free(privateKey);
            cerr << "Error sending M2" <<endl;
            exit(1);
        }

        //M3

		ret = recv(sd, (void*)&certSize, sizeof(int), MSG_WAITALL);
		if (ret != (int)sizeof(int)){
			EVP_PKEY_free(privateKey);
			cerr<<"Error receiving certificate"<<endl;
            exit(1);
		}
		certSize = ntohl(certSize);
		//Ricezione M3
		unsigned char M3[EVP_PKEY_size(privateKey)+(int)blockSize+certSize];

		ret = recv(sd, (void*)M3, EVP_PKEY_size(privateKey)+(int)blockSize+certSize, MSG_WAITALL);
		if (ret != EVP_PKEY_size(privateKey)+(int)blockSize+certSize) {
			EVP_PKEY_free(privateKey);
			cerr << "Error receiving M3"<<endl;
            exit(1);
        }
        certBuf=(unsigned char*)malloc(certSize);
        for(int i=0; i<(EVP_PKEY_size(privateKey)+(int)blockSize); ++i){
            ciphertext[i] = M3[i];
        }
        for(int i=0; i<certSize; ++i){
            certBuf[i]=M3[i+EVP_PKEY_size(privateKey)+(int)blockSize];
        }
        //verifica certificato server tramite store
		X509 *receivedCertificate = d2i_X509(NULL, (const unsigned char**)&certBuf, certSize);
		if(!receivedCertificate) {
			EVP_PKEY_free(privateKey);
			free(certBuf);
			cerr<<"Error converting certificate"<<endl;
            exit(1);
		}
		free(certBuf-certSize);
		X509_STORE_CTX* certCtx = X509_STORE_CTX_new();
		if(!certCtx) {
			EVP_PKEY_free(privateKey);
			cout<<"Error in verifying certificate"<<endl;
            exit(1);
		}
		ret = X509_STORE_CTX_init(certCtx, store, receivedCertificate, NULL);
		if(ret != 1) {
			EVP_PKEY_free(privateKey);
            cout<<"Error in verifying certificate"<<endl;
            exit(1);
		}
		ret = X509_verify_cert(certCtx);
		if(ret != 1) {
			EVP_PKEY_free(privateKey);
            cout<<"Error in verifying certificate"<<endl;
            exit(1);
		}
		X509_STORE_CTX_free(certCtx);

        //verifica se il server è quello corretto
		X509_NAME *sn = X509_get_subject_name(receivedCertificate);
		char *tempVar = X509_NAME_oneline(sn, NULL, 0);
		string serverName = string(tempVar);
		free(tempVar);
        if(serverName.compare(SERVER_NAME) != 0){
		    EVP_PKEY_free(privateKey);
			cout << "ERROR: the server io not the legittimate one!" << endl;
			exit(1);
		}

        //Decifriamo il ciphertext
        unsigned char receivedSign[EVP_PKEY_size(privateKey)+(int)blockSize];
		int plainlen, outlen;

		ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(ctx, EVP_aes_128_ecb(), securityKey, NULL);
		EVP_DecryptUpdate(ctx, receivedSign, &outlen, ciphertext, EVP_PKEY_size(privateKey)+(int)blockSize);
		plainlen=outlen;
		EVP_DecryptFinal(ctx, receivedSign+plainlen, &outlen);
		plainlen += outlen;
		EVP_CIPHER_CTX_free(ctx);

        //lettura publicKey del client dal certificato
		EVP_PKEY *serverPublicKey = X509_get_pubkey(receivedCertificate);
		if(serverPublicKey == NULL) {
			EVP_PKEY_free(privateKey);
			cerr << "Error getting server public key" <<endl;
            exit(1);
		}

        //verifica la firma
		mdctx = EVP_MD_CTX_new();
		if(!mdctx){
			deleteKeys();
			EVP_PKEY_free(privateKey);
			cout<<"Error in verifying the signature"<<endl;
            exit(1);
		}
		ret = EVP_VerifyInit(mdctx, md);
		if(ret == 0){
			deleteKeys();
			EVP_PKEY_free(privateKey);
            cout<<"Error in verifying the signature"<<endl;
            exit(1);
		}
		ret = EVP_VerifyUpdate(mdctx, YaConcatYb, 2*SIZE_Y_DH);
		if(ret == 0){
			deleteKeys();
			EVP_PKEY_free(privateKey);
            cout<<"Error in verifying the signature"<<endl;
            exit(1);
		}
		ret = EVP_VerifyFinal(mdctx, receivedSign, EVP_PKEY_size(privateKey), serverPublicKey);
		if(ret != 1){
			deleteKeys();
			EVP_PKEY_free(privateKey);
            cout<<"Error in verifying the signature"<<endl;
            exit(1);
		}
		EVP_MD_CTX_free(mdctx);

    }

    void startToRun(){
        iv = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_128_cbc()));
		if(!iv){
			cout<<"Error in allocating iv, malloc returned null."<<endl;
			exit(1);
		}
        cout<<"WELCOME!"<<endl;

        ivCounter=0;
        counter=0;
        createNextIV(ivCounter, iv);

        helpCommand();
        int ret;
        while(true){
            // !!! CONTROLLARE WARP-AROUND !!!

            string typedString;

            cout << ">";
            getline(cin, typedString);

            if(!verifyAndAcquireInput(typedString)){
                continue;
            }
            cout<<endl;
            if(typedCommand.compare("help")==0){
                helpCommand();
            }
            else if(typedCommand.compare("quit")==0){
                deleteKeys();
                X509_STORE_free(store);
                close(sd);
                return;
            }
            else if(typedCommand.compare("list")==0){
                ret = sendString(sd, typedCommand);
                if(ret < 0) {
                    deleteKeys();
                    cerr<<"Error sending command" <<endl;
                    exit(1);
                }

                ret = receiveFile(sd, "listDirectory/filelist.txt");
                if(ret < 0) {
                    deleteKeys();
                    cerr<<"Error getting the file" <<endl;
                    exit(1);
                }

                string fileName;
                ifstream is;
                cout<<"The files on the server are the following:"<<endl;
                is.open("listDirectory/filelist.txt");
                while(!is.eof()){
                    getline(is, fileName);
                    cout<<fileName<<endl;
                }
                is.close();
                fs::remove(fs::path("listDirectory/filelist.txt"));

            }
            else if(typedCommand.compare("download")==0){
                string toSend = typedCommand+" "+typedFileName;
                ret = sendString(sd, toSend);
                if(ret < 0) {
                    deleteKeys();
                    cerr<<"Error sending command" <<endl;
                    exit(1);
                }
                int serverResponse = receiveSize(sd);
                if(receiveSize<=0){
                    cerr<<"Error in receiving response to server" <<endl;
                    exit(1);
                }
                if(serverResponse == FILE_NOT_PRESENT){
                    cerr << "The file requested is not found on the server." << endl;
                    continue;
                }
                else if(serverResponse == FILE_TOO_LONG) {
                    cerr << "The file requested is too long." << endl;
                    continue;
                }
                else if(serverResponse == FILE_PRESENT){
                    typedFileName =  "filesDirectory/" + typedFileName;
                    int ret = receiveFile(sd, typedFileName);
                    if(ret < 0) {
                        deleteKeys();
                        cerr<<"Error in downloading the file." <<endl;
                        exit(1);
                    }
                    cout<<"File received correctly!"<<endl;
                }

            }
            else if(typedCommand.compare("upload")==0){

                //ceck if the name is allowed
                if(strspn(typedFileName.c_str(), allowedChars) < strlen(typedFileName.c_str())) {
					cerr<<"Name of file not valid!"<<endl;
					continue;
				}
				string path = "filesDirectory";

				//ceck if the file is persent
				int statusFile= FILE_NOT_PRESENT;
				size_t length;
				for (const auto & entry : fs::directory_iterator(path)){
					if(string(entry.path().filename()).compare(typedFileName) == 0){
						length = fs::file_size(entry.path());
						//ceck size
						if(fs::file_size(entry.path()) < MAX_FILE_SIZE){
							statusFile = FILE_PRESENT;
						}else{
							statusFile = FILE_TOO_LONG;
						}
						break;
					}
				}
                if(statusFile == FILE_NOT_PRESENT){
                    cout<<"File not found."<<endl;
                    continue;
                }
                if(statusFile == FILE_TOO_LONG){
                    cout<<"File too long to be sent."<<endl;
                    continue;
                }

                string toSend = typedCommand+" "+typedFileName;
                ret = sendString(sd, toSend);
                if(ret < 0) {
                    deleteKeys();
                    cerr<<"Error sending command" <<endl;
                    exit(1);
                }

                int serverResponse = receiveSize(sd);
                if(receiveSize<=0){
                    cerr<<"Error in receiving response to server." <<endl;
                    exit(1);
                }
                if(serverResponse == OK){
                    typedFileName = "filesDirectory/"+typedFileName;
                    ret = sendFile(sd, typedFileName, length);
                    if(ret < 0) {
                        deleteKeys();
                        cerr<<"Error in sending file." <<endl;
                        exit(1);
                    }
                    cout<<"File sent correctly!"<<endl;
                }else{
                    cout<<"Name of file not valid!"<<endl;
                }

            }
            cout<<endl;
        }
    }

    void helpCommand(){
        cout<<"The commands that can be typed are:"<<endl;
        cout<<"    help                --> show the allowed commands"<<endl;
        cout<<"    list                --> show the list of files on the server "<<endl;
        cout<<"    upload [filename]   --> for uploading a file on the serever"<<endl;
        cout<<"    download [filename] --> for downloading a file from the server"<<endl;
        cout<<"    quit                --> to end the program"<<endl<<endl;
    }
    
    bool verifyAndAcquireInput(string s){
        if(s.length()<4){
            cout<<"The command is incorrect."<<endl;
            cout<<"Type \"hepl\" for more informations."<<endl;
            return false;
        }
        string command;
        string fileName;

        int commandLen = s.find(' ', 0);
        if(commandLen<0){
            //nessuno spazio presente
            command = s;
        }else if((commandLen>=0 && commandLen<4) || (commandLen==((int)s.length()-1))){
            //il primo spazio è nelle prime 4 posizioni o per ultimo
            cout<<"The command is incorrect."<<endl;
            cout<<"Type \"hepl\" for more informations."<<endl;
            return false;
        }else{
            command = s.substr(0,commandLen);
            fileName =s.substr(commandLen+1);
        }

        size_t i;
        for(i=0; i<5; ++i) {
            if(allowedCommands[i].compare(command)==0) {
                if (command.compare("download")==0 || command.compare("upload")==0) {

                    if((fileName.size())>MAX_FILENAME_SIZE) {
                        cerr<<"Filename is too long, try again."<<endl;
                        return false;
                    }
                    else if (fileName.empty()) {
                        cout<<"Filename is needed for command \""<<command<<"\". "<<endl;
                        return false;
                    }
                }else if(!fileName.empty()){
                    cout<<"Command \""<<command<<"\" must be typed alone. "<<endl;
                    return false;
                }
                break;
            }
        }
        if (i==5){
            cout<<"The command is incorrect."<<endl;
            cout<<"Type \"hepl\" for more informations."<<endl;
            return false;
        }

        typedCommand= command;
        typedFileName=fileName;
        return true;
    }
};

int main(){
    Client c;
    c.keySharing();
    c.startToRun();
    return 0;
}
