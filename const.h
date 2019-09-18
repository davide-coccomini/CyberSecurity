#define SERVER_PORT 4242
#define MAX_FILENAME_SIZE 64
#define SIZE_Y_DH 384
#define MAX_COUNTER 10000000
#define BUFFER_SIZE 512

#define MAX_FILE_SIZE 4294967296 // 4 giga (2^32)

#define SECURITY_NUMBER 4286578685 // 2^32 - (MAX_FILE_SIZE / BUFFER_SIZE) - 3

//for the response to the upload and download commands
#define FILENAME_NOT_VALID 	100
#define OK					101
#define FILE_PRESENT		102
#define FILE_NOT_PRESENT	103
#define FILE_TOO_LONG		104

//for connectionStatus variable
#define	CLIENT_DISCONNECTED 0
#define CLIENT_CONNECTED 1
#define	ERROR_IN_CONNECTION 2

