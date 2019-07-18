#include <string>
#include <string.h>
#include <sys/socket.h>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <math.h>
#include "../const.h"


using namespace std;
namespace fs = std::experimental::filesystem;

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
}

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
	
	X509_STORE* store:

	public:
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/	
	Server(){
		loadCertificates();
		createStore();
		loadClients();
	}
	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/	
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
			close(socket_fd);
			exit(1);
		}
		cout<<"Server is listening to port " << SERVER_PORT <<endl;	
	}
	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/	
	void createStore(){
		store = X509_STORE_new();
		if(!store) { 
			cerr << "ERROR: store not allocated"<<endl;; 
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
	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
	void loadCertificates(){ 
	
		//apertura file
		string fileName = "certificates/serverCertificate.pem";
		FILE * certFile = fopen(fileName.c_str(), "r");	
		if(!certFile){
			cerr << "Error while opening file "<< fileName << endl;
			exit(1);
		}	
		//lettura certificato
		serverCertification = PEM_read_X509(certFile, NULL, NULL, NULL);
		fclose(certFile);
		if(!serverCertification) {
			cerr << "Error: PEM_read_X509 returned NULL\n"; //modificare cout
			exit(1);
		}
		
		//apertura file
		fileName = "certificates/CACertificate.pem";
		certFile = fopen(fileName.c_str(), "r");	
		if(!certFile){
			cerr << "Error while opening file "<< fileName << endl;
			exit(1);
		}	
		//lettura certificato
		CACertification = PEM_read_X509(certFile, NULL, NULL, NULL);
		fclose(certFile);
		if(!CACertification) {
			cerr << "Error: PEM_read_X509 returned NULL\n";//modificare cout
			exit(1);
		}
		
		fileName = "certificates/CRL170519.pem";//Da modificare
		certFile = fopen(fileName.c_str(), "r");
		if(!certFile){ 
			cerr << "Error while opening file "<< fileName << endl;
			exit(1); 
		}
		crl = PEM_read_X509_CRL(certFile, NULL, NULL, NULL);
		fclose(certFile);
		if(!crl){ 
			cerr << "Error: PEM_read_X509_CRL returned NULL\n"; //modificare cout
			exit(1);
		}
		
	}
	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/		
	void loadClients(){ // Read and save the authorized clients
		ifstream f("authorizedClients.txt");
		if(!f.is_open()){
			cout << "Errors while opening authorized clients" <<endl;
			exit(1);
		}
		string client;
		while(f){
			getline(f,client);	
			authorizedClients.push_back(client);
		}
	}


/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
	int keySharing(){
		
		//caricamento chiave privata
		
		//caricamento sessione dh
		
		//generazione coppia chiavi
		
		//M1: invio Ya
		
		//ricezione M2
		
		//verifica certificato client tramite store
		
		//verifica se il client è legittimato a connettersi
		
		//calcolo g_ab
		
		//decripta M2.2 con g_ab
		
		//verifica la firma
		
		//invio M3
		
	}

/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
void loadPrivateKey(){
	string fileName = "ertificates/server_key.pem";
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

/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
	
	

/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/		
	void initFileList(){ // Read and save the files on the server
		files.clear();
		string dir = "server/files";
		for(const auto & entry : fs::directory_iterator(dir)){
			file f = file(fs::file_size(entry.path()),string(entry.path().filename()));
			files.push_back(f);
		}
	}
	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/	
	void getFiles(){ // Print the files on the server
		string dir = "server/files";
		cout << "Files on the server:"<<endl;
		for(const auto & entry : fs::directory_iterator(dir))
			cout << "- " << string(entry.path().filename()) << "\t "<< fs::file_size(entry.path()) << endl;

	}
	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/		
	void executeCommand(){ // Manage the received command
		while(1){
			/*
			if((SIZE_MAX - counter) < MAX_COUNTER){
				counter = 0;
				keySharing();
			}
			int flags = 0;
			string cmd = recv_string(clientFd, &flags);
			*/
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
	
/*-----------------------------------------------------------------------------------------------------------------------------------------------------------------*/	 
	void keyGeneration(unsigned char *g_ab, int length){} // Generate keys
	int keySharing(){} // Implements the sharing of the keys for station-to-station
	void resetKeys(){} // Delete all the keys generated
}


int main(){
	system("clear");
	Server s;
	cout << "The server is ready" <<endl;
	//s.listen();
	return 0;

}
