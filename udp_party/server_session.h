#ifndef SERVER_SESSION_H
#define SERVER_SESSION_H

#include <map>
#include "session.h"

class ServerSession : public Session
{
public:
    ServerSession(unsigned int port, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity);
    ServerSession(const ServerSession& other, unsigned int mapKey, unsigned int sessionId, unsigned int incomingCounter, unsigned int outgoingCounter, unsigned int state);
    
    ~ServerSession();
    
    ReceiveResult receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize, ServerSession** ppChildSession, unsigned int* pChildSessionId);

    void closeChildSession(unsigned int sessionId);

private:
    std::map<unsigned int, ServerSession*> _activeSessions;
    unsigned int _nextSessionId;
};

#endif // SERVER_SESSION_H