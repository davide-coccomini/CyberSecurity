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

	public:
	Server(){
		//loadCertificates();
		loadClients();
		//createStore();
	}
	void loadCertificates(){ // Load certificates
		string fileName = "certificates/server_key.pem";
		FILE * privateKeyFile = fopen(fileName.c_str(), "r");	
		if(!privateKeyFile){
			cerr << "Error while opening file "<< fileName << endl;
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
		while(f){
			getline(f,client);	
			authorizedClients.push_back(client);
		}
	}
	void init(){ // Initialize the connection socket and start listening
		socketFd = socket(AF_INET, SOCK_STREAM, 0);
		memset(&serverAddress, 0, sizeof(serverAddress);
		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port = htons(SERVER_PORT);
		serverAddress.sin_addr.s_addr = INADDR_ANY;
		
		int ret = bind(socketFd, (sockaddr*)&serverAddress, sizeof(serverAddress));
		if(ret < 0){
			cerr << "Error while binding the socket" << endl;
			close(socketFd);
			exit(1);
		}
		ret = listen(socketFd, 15);
		if(ret < 0){
			cerr<<"Error while listening"<<endl;
			close(socketFd);
			exit(1);	
		}
		cout << "Server is now listening on " << SERVER_PORT << endl; 
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
	void keyGeneration(unsigned char *g_ab, int length){} // Generate keys
	int keySharing(){} // Implements the sharing of the keys for station-to-station
	void resetKeys(){} // Delete all the keys generated
}


int main(){
	system("clear");
	Server s;
	cout << "The server is running" <<endl;
	s.init();
	s.listen();
	return 0;

}
