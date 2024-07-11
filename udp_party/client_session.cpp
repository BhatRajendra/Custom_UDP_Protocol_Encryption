// #include "client_session.h"
// #include "crypto_wrapper.h"
// #include "utils.h"
// #include <stdio.h>
// #include <cstring>
// #include "session.h"


// ClientSession::ClientSession(unsigned int remotePort,const char* remoteIpAddress,  const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
// : Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
      
// {
//     if (!active())
//     {
//         return;
//     }

//     setRemoteAddress(remoteIpAddress, remotePort);
//     ByteSmartPtr message1 = prepareSigmaMessage(HELLO_SESSION_MESSAGE);
//     if (message1 == NULL)
//     {

//         return;
//     }

//     if (!sendMessageInternal(HELLO_SESSION_MESSAGE, message1, message1.size()))
//     {   
//         printf("inside clientsession");
//        _state = UNINITIALIZED_SESSION_STATE;
//         cleanDhData();
//         return;
//     }
//     printf("%d\n",message1.size());
//     _state = HELLO_SESSION_MESSAGE;
// }

// ClientSession::~ClientSession()
// {
//     closeSession();
//     destroySession();
// }

// Session::ReceiveResult ClientSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize)
// {
//     if (!active())
//     {
//         return RR_FATAL_ERROR;
//     }

//     struct sockaddr_in remoteAddr;
//     int remoteAddrSize = sizeof(remoteAddr);
//     memset(&remoteAddr, 0, remoteAddrSize);

//     size_t recvSize = 0;
//     Socket::ReceiveResult rcvResult = _localSocket->receive(buffer, bufferSize, timeout_sec, &recvSize, &remoteAddr);

//     switch (rcvResult)
//     {
//     case Socket::RR_TIMEOUT:
//         return RR_TIMEOUT;
//     case Socket::RR_ERROR:
//         printf("Error during client receive\n");
//         _state = UNINITIALIZED_SESSION_STATE;
//         cleanDhData();
//         return RR_FATAL_ERROR;
//     }

//     if (recvSize < sizeof(MessageHeader))
//     {
//         printf("Error during receive - message smaller than header\n");
//         return RR_BAD_MESSAGE;
//     }

//     MessageHeader* header = (MessageHeader*)buffer;

//     if (header->messageType < FIRST_SESSION_MESSAGE_TYPE || header->messageType > LAST_SESSION_MESSAGE_TYPE)
//     {
//         printf("Error during receive - bad message type %d\n", header->messageType);
//         return RR_BAD_MESSAGE;
//     }

//     if (header->payloadSize != recvSize - sizeof(MessageHeader))
//     {
//         printf("Error during receive - message size mismatch\n");
//         return RR_BAD_MESSAGE;
//     }

//     printf("Received message with session ID: %u, Expected session ID: %u\n", header->sessionId, _sessionId);

//     if (_state == HELLO_SESSION_MESSAGE && header->messageType == HELLO_BACK_SESSION_MESSAGE)
//     {
//         if (header->sessionId != 1)
//         {
//             printf("Error: Server assigned unexpected session ID %u. Expected 1.\n", header->sessionId);
//             return RR_BAD_MESSAGE;
//         }
//         printf("Received expected session ID: 1 from server\n");
//         _sessionId = 1;
//     }
//     else if (header->sessionId != _sessionId)
//     {
//         printf("Error during receive - session id mismatch. Expected %u, got %u\n", _sessionId, header->sessionId);
//         return RR_BAD_MESSAGE;
//     }

//     if (header->messageCounter != _incomingMessageCounter)
//     {
//         printf("Error during receive - message counter mismatch. Expected %u, got %u\n", _incomingMessageCounter, header->messageCounter);
//         return RR_BAD_MESSAGE;
//     }

//     switch (header->messageType)
//     {
//     case HELLO_BACK_SESSION_MESSAGE:
//         if (_state == HELLO_SESSION_MESSAGE)
//         {
//             BYTE* pPayload = buffer + sizeof(MessageHeader);
//             if (!verifySigmaMessage(HELLO_BACK_SESSION_MESSAGE, pPayload, header->payloadSize))
//             {
//                 printf("Session crypto error during HELLO_BACK_SESSION_MESSAGE\n");
//                 cleanDhData();
//                 return RR_FATAL_ERROR;
//             }

//             deriveSessionKey();

//             printf("Preparing HELLO_DONE_SESSION_MESSAGE\n");
   
//             ByteSmartPtr message3 = prepareSigmaMessage(HELLO_DONE_SESSION_MESSAGE);
  
//             if (message3 == NULL)
//             {
//                 printf("Failed to prepare HELLO_DONE_SESSION_MESSAGE\n");
//                 cleanDhData();
//                 return RR_FATAL_ERROR;
//             }

//             printf("Sending HELLO_DONE_SESSION_MESSAGE\n");
//             if (!sendMessageInternal(HELLO_DONE_SESSION_MESSAGE, message3, message3.size()))
//             {
//                 printf("Failed to send HELLO_DONE_SESSION_MESSAGE\n");
//                 cleanDhData();
//                 return RR_FATAL_ERROR;
//             }

//             _state = DATA_SESSION_MESSAGE;
//             _incomingMessageCounter++;
//             _sessionId = header->sessionId;

//             printf("Successfully processed HELLO_BACK_SESSION_MESSAGE\n");

//             if (ppPayload != NULL)
//             {
//                 *ppPayload = NULL;
//             }

//             if (pPayloadSize != NULL)
//             {
//                 *pPayloadSize = 0;
//             }

//             return RR_PROTOCOL_MESSAGE;
//         }
//         else
//         {
//             printf("Received HELLO_BACK_SESSION_MESSAGE in incorrect state: %d\n", _state);
//             return RR_BAD_MESSAGE;
//         }

//     case DATA_SESSION_MESSAGE:
//         if (_state == DATA_SESSION_MESSAGE)
//         {
//             size_t plaintextSize = 0;
//             if (!decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
//             {
//                 printf("Failed to decrypt DATA_SESSION_MESSAGE\n");
//                 return RR_BAD_MESSAGE;
//             }

//             _incomingMessageCounter++;

//             if (ppPayload != NULL)
//             {
//                 *ppPayload = buffer + sizeof(MessageHeader);
//             }

//             if (pPayloadSize != NULL)
//             {
//                 *pPayloadSize = plaintextSize;
//             }

//             printf("Successfully processed DATA_SESSION_MESSAGE\n");
//             return RR_DATA_MESSAGE;
//         }
//         else
//         {
//             printf("Received DATA_SESSION_MESSAGE in incorrect state: %d\n", _state);
//             return RR_BAD_MESSAGE;
//         }

//     case GOODBYE_SESSION_MESSAGE:
//     {
//         size_t plaintextSize = 0;
//         if (!decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
//         {
//             printf("Failed to decrypt GOODBYE_SESSION_MESSAGE\n");
//             return RR_BAD_MESSAGE;
//         }
//         printf("Session close request received, closing session %d\n", _sessionId);

//         cleanDhData();
//         _state = UNINITIALIZED_SESSION_STATE;

//         if (ppPayload != NULL)
//         {
//             *ppPayload = NULL;
//         }

//         if (pPayloadSize != NULL)
//         {
//             *pPayloadSize = 0;
//         }

//         return RR_SESSION_CLOSED;
//     }

//     default:
//         printf("Received unexpected message type %d\n", header->messageType);
//         return RR_BAD_MESSAGE;
//     }

//     return RR_BAD_MESSAGE;
// }

// bool ClientSession::sendDataMessage(const BYTE* message, size_t messageSize)
// {
//     if (!active() || _state != DATA_SESSION_MESSAGE)
//     {
//         return false;
//     }

//     ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
//     printf("encryptedMessage size: %d\n", encryptedMessage.size());
//     printf("encryptedMessage: %s\n", encryptedMessage);
//     if (encryptedMessage == NULL)
//     {
//         return false;
//     }

//     return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());;
// }

#include <stdio.h>
#include <cstring>
#include "client_session.h"
#include "crypto_wrapper.h"
#include "utils.h"

ClientSession::ClientSession(unsigned int remotePort, const char* remoteIpAddress, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity) 
    : Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
{
    if (!active())
    {
        return;
    }

    setRemoteAddress(remoteIpAddress, remotePort);

    // Prepare Sigma message #1
    ByteSmartPtr message1 = prepareSigmaMessage(HELLO_SESSION_MESSAGE);
    if (message1 == NULL)
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    if (!sendMessageInternal(HELLO_SESSION_MESSAGE, message1, message1.size()))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    _state = HELLO_SESSION_MESSAGE;

    BYTE messageBuffer[MESSAGE_BUFFER_SIZE_BYTES];
    memset(messageBuffer, '\0', MESSAGE_BUFFER_SIZE_BYTES);

    BYTE* pPayload = NULL;
    size_t payloadSize = 0;
    Session::ReceiveResult rcvResult = receiveMessage(messageBuffer, MESSAGE_BUFFER_SIZE_BYTES, 10, &pPayload, &payloadSize);
    if (rcvResult != RR_PROTOCOL_MESSAGE || _state != HELLO_BACK_SESSION_MESSAGE)
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // Verify Sigma message #2
    if (!verifySigmaMessage(HELLO_BACK_SESSION_MESSAGE, pPayload, (size_t)payloadSize))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // Prepare and send Sigma message #3
    ByteSmartPtr message3 = prepareSigmaMessage(HELLO_DONE_SESSION_MESSAGE);
    if (message3 == NULL)
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    if (!sendMessageInternal(HELLO_DONE_SESSION_MESSAGE, message3, message3.size()))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // Derive session key
    deriveSessionKey();

    _state = DATA_SESSION_MESSAGE;
}

ClientSession::~ClientSession()
{
    closeSession();
    destroySession();
}

Session::ReceiveResult ClientSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize)
{
    if (!active())
    {
        return RR_FATAL_ERROR;
    }

    struct sockaddr_in remoteAddr;
    int remoteAddrSize = sizeof(remoteAddr);
    memset(&remoteAddr, 0, remoteAddrSize);

    size_t recvSize = 0;
    Socket::ReceiveResult rcvResult = _localSocket->receive(buffer, bufferSize, timeout_sec, &recvSize, &remoteAddr);

    switch (rcvResult)
    {
    case Socket::RR_TIMEOUT:
        return RR_TIMEOUT;
    case Socket::RR_ERROR:
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return RR_FATAL_ERROR;
    }

    if (recvSize < sizeof(MessageHeader))
    {
        return RR_BAD_MESSAGE;
    }

    MessageHeader* header = (MessageHeader*)buffer;

    if (header->messageType < FIRST_SESSION_MESSAGE_TYPE || header->messageType > LAST_SESSION_MESSAGE_TYPE)
    {
        return RR_BAD_MESSAGE;
    }

    if (header->payloadSize != recvSize - sizeof(MessageHeader))
    {
        return RR_BAD_MESSAGE;
    }

    if (header->messageCounter != _incomingMessageCounter)
    {
        return RR_BAD_MESSAGE;
    }

    _incomingMessageCounter++;

    switch (header->messageType)
    {
    case GOODBYE_SESSION_MESSAGE:
        return RR_SESSION_CLOSED;
    case HELLO_SESSION_MESSAGE:
        return RR_BAD_MESSAGE;
    case HELLO_BACK_SESSION_MESSAGE:
        if (_state == HELLO_SESSION_MESSAGE)
        {
            _sessionId = header->sessionId;
            _state = HELLO_BACK_SESSION_MESSAGE;

            if (ppPayload != NULL)
                *ppPayload = buffer + sizeof(MessageHeader);

            if (pPayloadSize != NULL)
                *pPayloadSize = header->payloadSize;

            printf("Session started with %s\n", _expectedRemoteIdentityString);
            return RR_PROTOCOL_MESSAGE;
        }
        else
        {
            return RR_BAD_MESSAGE;
        }
    case DATA_SESSION_MESSAGE:
        if (_state == DATA_SESSION_MESSAGE)
        {
            size_t plaintextSize = 0;
            if (!decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
            {
                return RR_BAD_MESSAGE;
            }

            if (ppPayload != NULL)
            {
                *ppPayload = buffer + sizeof(MessageHeader);
            }

            if (pPayloadSize != NULL)
            {
                *pPayloadSize = plaintextSize;
            }
            return RR_DATA_MESSAGE;
        }
        else
            return RR_BAD_MESSAGE;
    default:
        return RR_BAD_MESSAGE;
    }
}

bool ClientSession::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        return false;
    }

    return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
}
