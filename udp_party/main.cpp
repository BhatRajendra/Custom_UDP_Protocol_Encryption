#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "client.h"
#include "server.h"
#include "eliza.h"
#include <string>


#define NAME "udp_party"
static constexpr size_t MAX_ARG_LENGTH = 100;


void printUsage()
{
    printf("For create a new user:\n");
    printf("Usage: <name>\n");
    printf("For existing user:\n");
    printf("\nUsage for server:\n %s -port LOCAL_PORT_NUMBER -key KEY_FILENAME [-pwd KEY_FILE_PASSWORD] -cert SERVER_CERTIFICATE_FILENAME -root ROOT_CA_CERTIFICATE_FILENAME -peer CLIENT_IDENTITY_STRING\n", NAME);
    printf("\nUsage for client:\n %s -ip REMOTE_IP_ADDRESS -port LOCAL_PORT_NUMBER -key KEY_FILENAME [-pwd KEY_FILE_PASSWORD] -cert CLIENT_CERTIFICATE_FILENAME -root ROOT_CA_CERTIFICATE_FILENAME -peer SERVER_IDENTITY_STRING\n", NAME);
}

void newUser(const char *name){
  char command[512];

  // Generate RSA key
  snprintf(command, sizeof(command),
           "openssl genpkey -algorithm RSA -out %s.key -pkeyopt "
           "rsa_keygen_bits:3072",
           name);
  system(command);

  // Create certificate signing request
  snprintf(command, sizeof(command),
           "openssl req -new -key %s.key -out %s.csr ", name, name);
  system(command);

  // Sign certificate with root CA
  snprintf(command, sizeof(command),
           "openssl x509 -req -in %s.csr -CA rootCA.crt -CAkey rootCA.key "
           "-CAcreateserial -out %s.crt -days 365 -sha384  "
           "-extensions v3_req",
           name, name);
  system(command);
}

/*


int main(int argc, char** argv)
{
    Eliza eliza;
    char input[1024];
    std::string result;

    result = eliza.start();
    printf("%s\n", result.c_str());

    bool toContinue = true;
    while (toContinue)
    {
        bool toFinish = false;
        readline(input);
        result = eliza.getResponse(input, toFinish);
        printf("%s\n", result.c_str());
        toContinue = !toFinish;
    }
}
*/

int main(int argc, char** argv) 
{
    const char* keyFilename = NULL;
    char* keyPassword = NULL;
    const char* certFilename = NULL;
    const char* rootCaFilename = NULL;
    const char* peerIdentity = NULL;
    unsigned int port = 0;
    const char* remoteIp = NULL;
    const char* name = NULL;

    if (argc == 1)
    {
        printf("No parameters provided!\n");
        printUsage();
        return -1;
    }
    if(argc == 3) {
        printf("%s",argv[1]);
        printf("%d",argv[1]=="-newuser");
        if (strncmp(argv[1], "-newuser", MAX_ARG_LENGTH) == 0){
            name = argv[2];
            newUser(name);
            
        } else {
            printUsage();
            return -1;
        }
    }
    else{
for (unsigned int i = 1; i < (unsigned int)argc - 1; i++)
    {
        const char* arg = argv[i];
        if (strncmp(arg, "-key", MAX_ARG_LENGTH) == 0)
        {
            keyFilename = argv[i + 1];
            i++;
        }
        else if (strncmp(arg, "-pwd", MAX_ARG_LENGTH) == 0)
        {
            keyPassword = argv[i + 1];
            i++;
        }
        else if (strncmp(arg, "-cert", MAX_ARG_LENGTH) == 0)
        {
            certFilename = argv[i + 1];
            i++;
        }
        else if (strncmp(arg, "-peer", MAX_ARG_LENGTH) == 0)
        {
            peerIdentity = argv[i + 1];
            i++;
        }
        else if (strncmp(arg, "-ip", MAX_ARG_LENGTH) == 0)
        {
            remoteIp = argv[i + 1];
            i++;
        }
        else if (strncmp(arg, "-port", MAX_ARG_LENGTH) == 0)
        {
            port = atoi(argv[i + 1]);
            i++;
        }
        else if (strncmp(arg, "-root", MAX_ARG_LENGTH) == 0)
        {
            rootCaFilename = argv[i + 1];
            i++;
        }
    }

    bool paramsValid = true;

    // check params validity
    if (port == 0)
    {
        printf("Error - bad port provided!\n");
        paramsValid = false;
    }
    if (peerIdentity == NULL && remoteIp != NULL)
    {
        printf("Error - no peer identity provided!\n");
        paramsValid = false;
    }
    if (rootCaFilename == NULL)
    {
        printf("Error - no Root CA certificate filename provided!\n");
        paramsValid = false;
    }
    if (certFilename == NULL)
    {
        printf("Error - no certificate filename provided!\n");
        paramsValid = false;
    }
    if (keyFilename == NULL)
    {
        printf("Error - no private key filename provided!\n");
        paramsValid = false;
    }

    // TODO = check existense and validity of files to avoit later errors
    // TODO - check that certificate and key files have read-only access

    if (!paramsValid)
    {
        printUsage();
        return -1;
    }

    if (remoteIp == NULL)
    {
        return playServerSession(port, keyFilename, keyPassword, certFilename, rootCaFilename, peerIdentity) ? 0 : -1;
    }
    else
    {
        return playClientSession(remoteIp, port, keyFilename, keyPassword, certFilename, rootCaFilename, peerIdentity) ? 0 : -1;
    }
    }
    
}

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>

// int main(int argc, char *argv[]) {
//   if (argc != 2) {
//     fprintf(stderr, "Usage: %s <name>\n", argv[0]);
//     return 1;
//   }

//   char *name = argv[1];
//   char command[512];

//   // Generate RSA key
//   snprintf(command, sizeof(command),
//            "openssl genpkey -algorithm RSA -out %s.key -pkeyopt "
//            "rsa_keygen_bits:3072",
//            name);
//   system(command);

//   // Create certificate signing request
//   snprintf(command, sizeof(command),
//            "openssl req -new -key %s.key -out %s.csr ", name, name);
//   system(command);

//   // Sign certificate with root CA
//   snprintf(command, sizeof(command),
//            "openssl x509 -req -in %s.csr -CA rootCA.crt -CAkey rootCA.key "
//            "-CAcreateserial -out %s.crt -days 365 -sha384 -extfile %s_cert.cnf "
//            "-extensions v3_req -set_serial 02",
//            name, name, name);
//   system(command);

//   return 0;
// }