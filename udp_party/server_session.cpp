// #include "server_session.h"
// #include "crypto_wrapper.h"
// #include "utils.h"
// #include <cstring>
// #include <stdio.h>
// #include<cstring>
// #include<string>

// ServerSession::ServerSession(unsigned int localPort, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
//     : Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
// {
//     _nextSessionId = 1;
//     if (!active())
//     {
//         return;
//     }

//     struct sockaddr_in localAddress;
//     memset(&localAddress, 0, sizeof(sockaddr_in));

//     localAddress.sin_family = AF_INET;
//     localAddress.sin_port = htons(localPort);
//     localAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

//     if (!_localSocket->bindIpAddress(&localAddress))
//     {
//         _state = UNINITIALIZED_SESSION_STATE;
//         return;
//     }

//     _state = INITIALIZED_SESSION_STATE;
// }

// ServerSession::ServerSession(const ServerSession& other, unsigned int mapKey, unsigned int sessionId, unsigned int incomingCounter, unsigned int outgoingCounter, unsigned int state)
//     : Session(other)
// {
//     _nextSessionId = mapKey + 1;
//     _state = state;
//     _sessionId = sessionId;
//     _incomingMessageCounter = incomingCounter;
//     _outgoingMessageCounter = outgoingCounter;
// }

// ServerSession::~ServerSession()
// {
//     for (auto it = _activeSessions.begin(); it != _activeSessions.end(); ++it)
//     {
//         ServerSession* childSession = it->second;
//         childSession->closeSession();
//         delete childSession;
//     }
//     _activeSessions.clear();
//     destroySession();
// }

// Session::ReceiveResult ServerSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize, ServerSession** ppChildSession, unsigned int* pChildSessionId)
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
//         printf("Error during server receive\n");
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

//     if (header->sessionId == 0) // new session request
//     {
//         if (header->messageType != HELLO_SESSION_MESSAGE || header->messageCounter != 0)
//         {
//             printf("Error during receive - message type or counter mismatch with session id of 0\n");
//             return RR_BAD_MESSAGE;
//         }

//         std::vector<MessagePart> parts;
//         if (!unpackMessageParts(buffer + sizeof(MessageHeader), header->payloadSize, parts))
//         {
//             printf("Error during receive - failed to unpack message parts\n");
//             return RR_BAD_MESSAGE;
//         }

//         if (parts.empty() || parts[0].partSize != DH_KEY_SIZE_BYTES)
//         {
//             printf("Error during receive - first part size mismatch\n");
//             return RR_BAD_MESSAGE;
//         }

//         // Create new session with the next available ID
//         ServerSession* newSession = new ServerSession(*this, _nextSessionId, _nextSessionId, 1, 0, HELLO_SESSION_MESSAGE);
//         memcpy_s(&(newSession->_remoteAddress), sizeof(struct sockaddr_in), &remoteAddr, remoteAddrSize);

//         ByteSmartPtr message2 = newSession->prepareSigmaMessage(HELLO_BACK_SESSION_MESSAGE);
//         if (message2 == NULL)
//         {
//             delete newSession;
//             return RR_FATAL_ERROR;
//         }

//         if (!newSession->sendMessageInternal(HELLO_BACK_SESSION_MESSAGE, message2, message2.size()))
//         {
//             printf("Error during receive - error sending response to new session\n");
//             newSession->cleanDhData();
//             delete newSession;
//             return RR_FATAL_ERROR;
//         }

//         newSession->_state = HELLO_BACK_SESSION_MESSAGE;

//         auto ret = _activeSessions.insert(std::make_pair(_nextSessionId, newSession));
//         if (ret.second)  // If the insertion was successful
//         {
//             if (ppChildSession)
//             {
//                 *ppChildSession = ret.first->second;
//             }
//             if (pChildSessionId)
//             {
//                 *pChildSessionId = _nextSessionId;
//             }
//             printf("New session %d created with %s\n", _nextSessionId, newSession->_expectedRemoteIdentityString != NULL ? newSession->_expectedRemoteIdentityString : "a valid peer");
            
//             _nextSessionId++;  // Increment for the next session
//         }
//         else
//         {
//             // If insertion failed, clean up and return an error
//             delete newSession;
//             return RR_FATAL_ERROR;
//         }

//         if (ppPayload != NULL)
//         {
//             *ppPayload = NULL;
//         }

//         if (pPayloadSize != NULL)
//         {
//             *pPayloadSize = 0;
//         }

//         return RR_PROTOCOL_MESSAGE;
//     }
//     else // existing session
//     {
//         auto it = _activeSessions.find(header->sessionId);
//         if (it != _activeSessions.end())
//         {
//             ServerSession* pSession = it->second;
//             if (ppChildSession)
//             {
//                 *ppChildSession = pSession;
//             }
//             if (pChildSessionId)
//             {
//                 *pChildSessionId = pSession->id();
//             }
//             if (!pSession->active())
//             {
//                 printf("Error during receive - received message for non-active session\n");
//                 return RR_BAD_MESSAGE;
//             }

//             if (header->messageCounter != pSession->_incomingMessageCounter)
//             {
//                 printf("Error during receive - message counter mismatch\n");
//                 return RR_BAD_MESSAGE;
//             }

//             switch (header->messageType)
//             {
//             case GOODBYE_SESSION_MESSAGE:
//             {
//                 size_t plaintextSize = 0;
//                 if (!pSession->decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
//                 {
//                     return RR_BAD_MESSAGE;
//                 }
//                 printf("Session close request received closing session %d\n", pSession->_sessionId);

//                 if (ppChildSession)
//                 {
//                     *ppChildSession = NULL;
//                 }
//                 delete pSession;
//                 _activeSessions.erase(header->sessionId);

//                 if (ppPayload != NULL)
//                 {
//                     *ppPayload = NULL;
//                 }

//                 if (pPayloadSize != NULL)
//                 {
//                     *pPayloadSize = 0;
//                 }

//                 return RR_SESSION_CLOSED;
//             }
//             case HELLO_DONE_SESSION_MESSAGE:
//                 if (pSession->_state == HELLO_BACK_SESSION_MESSAGE)
//                 {
//                     BYTE* pPayload = buffer + sizeof(MessageHeader);
//                     printf("Received HELLO_DONE_SESSION_MESSAGE. Payload size: %zu\n", (size_t)header->payloadSize);

//                     // Log the first few bytes of the payload (be cautious with sensitive data)
//                     printf("Payload preview: ");
//                     for (size_t i = 0; i < std::min((size_t)header->payloadSize, (size_t)16); ++i)
//                     {
//                         printf("%02X ", pPayload[i]);
//                     }
//                     printf("\n");

//                     if (!pSession->verifySigmaMessage(HELLO_DONE_SESSION_MESSAGE, pPayload, (size_t)header->payloadSize))
//                     {
//                         printf("Session crypto error closing session %d\n", pSession->_sessionId);
//                         pSession->cleanDhData();
//                         delete pSession;
//                         _activeSessions.erase(header->sessionId);
//                         return RR_SESSION_CLOSED;
//                     }

//                     pSession->deriveSessionKey();
//                     pSession->_state = DATA_SESSION_MESSAGE;
//                     pSession->_incomingMessageCounter++;

//                     // Send the welcome message
//                     std::string welcomeMessage = "HI!  I'M ELIZA.  WHAT'S YOUR PROBLEM?";
//                     if (!pSession->sendDataMessage((const BYTE*)welcomeMessage.c_str(), welcomeMessage.length() + 1))
//                     {
//                         printf("Error sending a welcome message!\n");
//                         pSession->cleanDhData();
//                         delete pSession;
//                         _activeSessions.erase(header->sessionId);
//                         return RR_FATAL_ERROR;
//                     }
//                     else
//                     {
//                         printf("Welcome message sent successfully.\n");
//                     }

//                     if (ppPayload != NULL)
//                     {
//                         *ppPayload = NULL;
//                     }

//                     if (pPayloadSize != NULL)
//                     {
//                         *pPayloadSize = 0;
//                     }

//                     return RR_NEW_SESSION_CREATED;
//                 }
//                 else
//                 {
//                     return RR_BAD_MESSAGE;
//                 }
//             case DATA_SESSION_MESSAGE:
//                 if (pSession->_state == DATA_SESSION_MESSAGE)
//                 {
//                     size_t plaintextSize = 0;
//                     if (!pSession->decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
//                     {
//                         return RR_BAD_MESSAGE;
//                     }

//                     pSession->_incomingMessageCounter++;

//                     if (ppPayload != NULL)
//                     {
//                         *ppPayload = buffer + sizeof(MessageHeader);
//                     }

//                     if (pPayloadSize != NULL)
//                     {
//                         *pPayloadSize = plaintextSize;
//                     }

//                     return RR_DATA_MESSAGE;
//                 }
//                 else
//                 {
//                     return RR_BAD_MESSAGE;
//                 }
//             }
//         }
//         else
//         {
//             return RR_BAD_MESSAGE;
//         }
//     }

//     return RR_BAD_MESSAGE;
// }

// void ServerSession::closeChildSession(unsigned int sessionId)
// {
//     auto it = _activeSessions.find(sessionId);
//     if (it != _activeSessions.end())
//     {
//         ServerSession* session = it->second;
//         session->closeSession();
//         delete session;
//         _activeSessions.erase(it);
//     }
// }

#include "server_session.h"
#include "crypto_wrapper.h"
#include "utils.h"
#include <cstring>
#include <stdio.h>
#include <string> // Add this include for std::string
#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN

ServerSession::ServerSession(unsigned int localPort, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
    : Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
{
    _nextSessionId = 1;
    if (!active())
    {
        return;
    }

    struct sockaddr_in localAddress;
    memset(&localAddress, 0, sizeof(sockaddr_in));

    localAddress.sin_family = AF_INET;
    localAddress.sin_port = htons(localPort);
    localAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (!_localSocket->bindIpAddress(&localAddress))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        return;
    }

    _state = INITIALIZED_SESSION_STATE;
    return;
}

ServerSession::ServerSession(const ServerSession& other, unsigned int mapKey, unsigned int sessionId, unsigned int incomingCounter, unsigned int outgoingCounter, unsigned int state)
    : Session(other)
{   
    //mapKey ??
    _nextSessionId = mapKey + 1;
    _state = state;
    _sessionId = sessionId;
    _incomingMessageCounter = incomingCounter;
    _outgoingMessageCounter = outgoingCounter;
}

ServerSession::~ServerSession()

{
    //change in for loop
    for (auto it = _activeSessions.begin(); it != _activeSessions.end(); ++it)
    {
        ServerSession* childSession = it->second;
        childSession->closeSession();
        delete childSession;
    }
    _activeSessions.clear();
    destroySession();
}

Session::ReceiveResult ServerSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize, ServerSession** ppChildSession, unsigned int* pChildSessionId)
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
        printf("Error during server receive\n");
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return RR_FATAL_ERROR;
    }

    if (recvSize < sizeof(MessageHeader))
    {
        printf("Error during receive - message smaller than header\n");
        return RR_BAD_MESSAGE;
    }

    MessageHeader* header = (MessageHeader*)buffer;

    if (header->messageType < FIRST_SESSION_MESSAGE_TYPE || header->messageType > LAST_SESSION_MESSAGE_TYPE)
    {
        printf("Error during receive - bad message type %d\n", header->messageType);
        return RR_BAD_MESSAGE;
    }

    if (header->payloadSize != recvSize - sizeof(MessageHeader))
    {
        printf("Error during receive - message size mismatch\n");
        return RR_BAD_MESSAGE;
    }

    if (header->sessionId == 0) // new session request
    {
        if (header->messageType != HELLO_SESSION_MESSAGE || header->messageCounter != 0)
        {
            printf("Error during receive - message type or counter mismatch with session id of 0\n");
            return RR_BAD_MESSAGE;
        }

        std::vector<MessagePart> parts;
                if (!unpackMessageParts(buffer + sizeof(MessageHeader), header->payloadSize, parts))
        {
            printf("Error during receive - failed to unpack message parts\n");
            return RR_BAD_MESSAGE;
        }

        if (parts.empty() || parts[0].partSize != DH_KEY_SIZE_BYTES)
        {
            printf("Error during receive - first part size mismatch\n");
            return RR_BAD_MESSAGE;
        }

        // Create new session with the next available ID
        ServerSession* newSession = new ServerSession(*this, _nextSessionId, _nextSessionId, 1, 0, HELLO_SESSION_MESSAGE);
        memcpy_s(&(newSession->_remoteAddress), sizeof(struct sockaddr_in), &remoteAddr, remoteAddrSize);

        ByteSmartPtr message2 = newSession->prepareSigmaMessage(HELLO_BACK_SESSION_MESSAGE);
        if (message2 == NULL)
        {
            delete newSession;
            return RR_FATAL_ERROR;
        }

        if (!newSession->sendMessageInternal(HELLO_BACK_SESSION_MESSAGE, message2, message2.size()))
        {
            printf("Error during receive - error sending response to new session\n");
            newSession->cleanDhData();
            delete newSession;
            return RR_FATAL_ERROR;
        }

        newSession->_state = HELLO_BACK_SESSION_MESSAGE;

        auto ret = _activeSessions.insert(std::make_pair(_nextSessionId, newSession));
        if (ret.second)  // If the insertion was successful
        {
            if (ppChildSession)
            {
                *ppChildSession = ret.first->second;
            }
            if (pChildSessionId)
            {
                *pChildSessionId = _nextSessionId;
            }
            printf("New session %d created with %s\n", _nextSessionId, newSession->_expectedRemoteIdentityString != NULL ? newSession->_expectedRemoteIdentityString : "a valid peer");

            _nextSessionId++;  // Increment for the next session
        }
        else
        {
            // If insertion failed, clean up and return an error
            delete newSession;
            return RR_FATAL_ERROR;
        }

        if (ppPayload != NULL)
        {
            *ppPayload = NULL;
        }

        if (pPayloadSize != NULL)
        {
            *pPayloadSize = 0;
        }

        return RR_PROTOCOL_MESSAGE;
    }
    else // existing session
    {
        auto it = _activeSessions.find(header->sessionId);
        if (it != _activeSessions.end())
        {
            ServerSession* pSession = it->second;
            if (ppChildSession)
            {
                *ppChildSession = pSession;
            }
            if (pChildSessionId)
            {
                *pChildSessionId = pSession->id();
            }
            if (!pSession->active())
            {
                printf("Error during receive - received message for non-active session\n");
                return RR_BAD_MESSAGE;
            }

            if (header->messageCounter != pSession->_incomingMessageCounter)
            {
                printf("Error during receive - message counter mismatch\n");
                return RR_BAD_MESSAGE;
            }

            switch (header->messageType)
            {
            case GOODBYE_SESSION_MESSAGE:
            {
                size_t plaintextSize = 0;
                if (!pSession->decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
                {
                    return RR_BAD_MESSAGE;
                }
                printf("Session close request received, closing session %d\n", pSession->_sessionId);

                if (ppChildSession)
                {
                    *ppChildSession = NULL;
                }
                delete pSession;
                _activeSessions.erase(header->sessionId);

                if (ppPayload != NULL)
                {
                    *ppPayload = NULL;
                }

                if (pPayloadSize != NULL)
                {
                    *pPayloadSize = 0;
                }

                return RR_SESSION_CLOSED;
            }
            case HELLO_DONE_SESSION_MESSAGE:
                if (pSession->_state == HELLO_BACK_SESSION_MESSAGE)
                {
                    BYTE* pPayload = buffer + sizeof(MessageHeader);
                    

                    // Log the first few bytes of the payload (be cautious with sensitive data)
                   

                    if (!pSession->verifySigmaMessage(HELLO_DONE_SESSION_MESSAGE, pPayload, (size_t)header->payloadSize))
                    {
                        printf("Session crypto error closing session %d\n", pSession->_sessionId);
                        pSession->cleanDhData();
                        delete pSession;
                        _activeSessions.erase(header->sessionId);
                        return RR_SESSION_CLOSED;
                    }

                    pSession->deriveSessionKey();
                    pSession->_state = DATA_SESSION_MESSAGE;
                    pSession->_incomingMessageCounter++;

                    

                    if (ppPayload != NULL)
                    {
                        *ppPayload = NULL;
                    }

                    if (pPayloadSize != NULL)
                    {
                        *pPayloadSize = 0;
                    }

                    return RR_NEW_SESSION_CREATED;
                }
                else
                {
                    printf("Received HELLO_DONE_SESSION_MESSAGE in incorrect state: %d\n", pSession->_state);
                    return RR_BAD_MESSAGE;
                }
            case DATA_SESSION_MESSAGE:
                if (pSession->_state == DATA_SESSION_MESSAGE)
                {
                    size_t plaintextSize = 0;
                    if (!pSession->decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
                    {
                        return RR_BAD_MESSAGE;
                    }

                    pSession->_incomingMessageCounter++;

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
                {
                    return RR_BAD_MESSAGE;
                }
            default:
                printf("Received unexpected message type %d\n", header->messageType);
                return RR_BAD_MESSAGE;
            }
        }
        else
        {
            return RR_BAD_MESSAGE;
        }
    }

    return RR_BAD_MESSAGE;
}

void ServerSession::closeChildSession(unsigned int sessionId)
{
    auto it = _activeSessions.find(sessionId);
    if (it != _activeSessions.end())
    {
        ServerSession* session = it->second;
        session->closeSession();
        delete session;
        _activeSessions.erase(it);
    }
}

