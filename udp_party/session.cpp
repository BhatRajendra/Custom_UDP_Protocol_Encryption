#include <list>
#include <stdio.h>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include "session.h"
#include "utils.h"
#include "crypto_wrapper.h"
#include "types.h"

#ifdef WIN
#pragma warning(disable:4996)
#endif // #ifdef WIN

static constexpr size_t MAX_CONTEXT_SIZE = 100;

Session::Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    _state = UNINITIALIZED_SESSION_STATE;

    _localSocket = new Socket(0);
    if (!_localSocket->valid())
    {
        return;
    }
    _pReferenceCounter = new ReferenceCounter();
    _pReferenceCounter->AddRef();

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = keyFilename;
    _privateKeyPassword = password;
    _localCertFilename = certFilename;
    _rootCaCertFilename = rootCaFilename;
    _expectedRemoteIdentityString = peerIdentity;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}

Session::Session(const Session& other)
{
    _state = UNINITIALIZED_SESSION_STATE;
    _pReferenceCounter = other._pReferenceCounter;
    _pReferenceCounter->AddRef();

    _localSocket = other._localSocket;

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = other._privateKeyFilename;
    _privateKeyPassword = other._privateKeyPassword;
    _localCertFilename = other._localCertFilename;
    _rootCaCertFilename = other._rootCaCertFilename;
    _expectedRemoteIdentityString = other._expectedRemoteIdentityString;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}

void Session::closeSession()
{
    if (active())
    {
        ByteSmartPtr encryptedMessage = prepareEncryptedMessage(GOODBYE_SESSION_MESSAGE, NULL, 0);
        if (encryptedMessage != NULL)
        {
            sendMessageInternal(GOODBYE_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
            _state = GOODBYE_SESSION_MESSAGE;
        }
    }
}

void Session::destroySession()
{
    cleanDhData();
    if (_pReferenceCounter != NULL && _pReferenceCounter->Release() == 0)
    {
        delete _localSocket;
        _localSocket = NULL;
        delete _pReferenceCounter;
        _pReferenceCounter = NULL;

        if (_privateKeyPassword != NULL)
        {
            Utils::secureCleanMemory((BYTE*)_privateKeyPassword, strlen(_privateKeyPassword));
        }
    }
    else
    {
        _pReferenceCounter = NULL;
    }

    _state = DEACTIVATED_SESSION_STATE;
}

bool Session::active()
{
    return (_state == INITIALIZED_SESSION_STATE ||
        (_state >= FIRST_SESSION_MESSAGE_TYPE && _state <= LAST_SESSION_MESSAGE_TYPE));
}

void Session::setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort)
{
    memset(&(_remoteAddress), 0, sizeof(sockaddr_in));
    _remoteAddress.sin_family = AF_INET;
    _remoteAddress.sin_port = htons(remotePort);
    _remoteAddress.sin_addr.s_addr = inet_addr(remoteIpAddress);
}

void Session::prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize)
{
    header->sessionId = _sessionId;
    header->messageType = type;
    header->messageCounter = _outgoingMessageCounter;
    header->payloadSize = (unsigned int)messageSize;
}

bool Session::sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize)
{
    if (!active())
    {
        return false;
    }

    MessageHeader header;
    prepareMessageHeader(&header, type, messageSize);

    ByteSmartPtr messageBufferSmartPtr = concat(2, &header, sizeof(header), message, messageSize);
    if (messageBufferSmartPtr == NULL)
    {
        return false;
    }

    bool result = _localSocket->send(messageBufferSmartPtr, messageBufferSmartPtr.size(), &(_remoteAddress));
    if (result)
    {
        _outgoingMessageCounter++;
    }

    return result;
}

void Session::cleanDhData()
{
    if (_dhContext != NULL)
    {
        CryptoWrapper::cleanDhContext(&_dhContext);
    }
    memset(_localDhPublicKeyBuffer, 0, DH_KEY_SIZE_BYTES);
    memset(_remoteDhPublicKeyBuffer, 0, DH_KEY_SIZE_BYTES);
    memset(_sharedDhSecretBuffer, 0, DH_KEY_SIZE_BYTES);
}

void Session::deriveMacKey(BYTE* macKeyBuffer)
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "MAC over certificate key %d", _sessionId) <= 0)
    {
        exit(0);
    }

    CryptoWrapper::deriveKey_HKDF_SHA256(NULL, 0, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES,
        (const BYTE*)keyDerivationContext, strlen(keyDerivationContext), macKeyBuffer, HMAC_SIZE_BYTES);
}

void Session::deriveSessionKey()
{

    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "ENC session key %d", _sessionId) <= 0)
    {
        printf("Failed to format key derivation context.\n");
        exit(0);
    }


    // Ensure the session key is 32 bytes (256 bits)
    CryptoWrapper::deriveKey_HKDF_SHA256(NULL, 0, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES,
        (const BYTE*)keyDerivationContext, strlen(keyDerivationContext), _sessionKey, 32);

}



ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    
    if (messageType != HELLO_SESSION_MESSAGE && 
        messageType != HELLO_BACK_SESSION_MESSAGE && 
        messageType != HELLO_DONE_SESSION_MESSAGE)
    {
        printf("Invalid message type: %d\n", messageType);
        return NULL;
    }

    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        printf("prepareSigmaMessage - Error reading certificate filename - %s\n", _localCertFilename);
        return NULL;
    }
    

    KeypairContext* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        printf("prepareSigmaMessage #%d - Error during readRSAKeyFromFile - %s\n", messageType, _privateKeyFilename);
        cleanDhData();
        return NULL;
    }

    ByteSmartPtr concatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("prepareSigmaMessage #%d failed - Error concatenating public keys\n", messageType);
        cleanDhData();
        return NULL;
    }
    

    BYTE signature[SIGNATURE_SIZE_BYTES];
    if (!CryptoWrapper::signMessageRsa3072Pss(concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(), privateKeyContext, signature, SIGNATURE_SIZE_BYTES))
    {
        printf("prepareSigmaMessage #%d failed - Error signing message\n", messageType);
        cleanDhData();
        return NULL;
    }
    

    BYTE calculatedMac[HMAC_SIZE_BYTES];
    deriveMacKey(calculatedMac);
   

    ByteSmartPtr messageToSend = packMessageParts(4, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                                  (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(),
                                                  signature, SIGNATURE_SIZE_BYTES,
                                                  calculatedMac, HMAC_SIZE_BYTES);

    if (messageToSend != NULL)
    {
        // printf("Packed message size: %zu bytes\n", messageToSend.size());
        // printf("prepareSigmaMessage succeeded for message type: %d\n", messageType);
    }
    else
    {
        printf("Failed to pack message parts\n");
        printf("prepareSigmaMessage failed for message type: %d\n", messageType);
    }

    Utils::secureCleanMemory(calculatedMac, HMAC_SIZE_BYTES);

    return messageToSend;
}

bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    if (messageType != HELLO_SESSION_MESSAGE && messageType != HELLO_BACK_SESSION_MESSAGE && messageType != HELLO_DONE_SESSION_MESSAGE)
    {
        return false;
    }

    unsigned int expectedNumberOfParts = 4;

    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        printf("verifySigmaMessage #%d failed - number of message parts is wrong\n", messageType);
        return false;
    }

    const BYTE* remoteDhPublicKey = parts[0].part;
    const BYTE* remoteCert = parts[1].part;
    const BYTE* signature = parts[2].part;
    const BYTE* calculatedMac = parts[3].part;

    // Verify the remote certificate
    KeypairContext* publicKeyContext = NULL;
    if (!CryptoWrapper::getPublicKeyFromCertificate(remoteCert, parts[1].partSize, &publicKeyContext))
    {
        printf("verifySigmaMessage #%d failed - Error getting public key from certificate\n", messageType);
        return false;
    }

    ByteSmartPtr concatenatedPublicKeysSmartPtr = concat(2, remoteDhPublicKey, DH_KEY_SIZE_BYTES, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("verifySigmaMessage #%d failed - Error concatenating public keys\n", messageType);
        return false;
    }

    bool signatureValid = false;
    if (!CryptoWrapper::verifyMessageRsa3072Pss(concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(), publicKeyContext, signature, SIGNATURE_SIZE_BYTES, &signatureValid) || !signatureValid)
    {
        printf("verifySigmaMessage #%d failed - Signature verification failed\n", messageType);
        return false;
    }

    BYTE expectedMac[HMAC_SIZE_BYTES];
    deriveMacKey(expectedMac);

    if (memcmp(calculatedMac, expectedMac, HMAC_SIZE_BYTES) != 0)
    {
        printf("verifySigmaMessage #%d failed - MAC verification failed\n", messageType);
        return false;
    }

    if (messageType == HELLO_SESSION_MESSAGE)
    {
        // Now we will calculate the shared secret
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, remoteDhPublicKey, DH_KEY_SIZE_BYTES, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("verifySigmaMessage #%d failed - Error calculating shared secret\n", messageType);
            return false;
        }
    }

    return true;
}


ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize)
{

    size_t expectedKeySize = 32; // AES-256 key size
    if (SYMMETRIC_KEY_SIZE_BYTES != expectedKeySize)
    {
        printf("Invalid session key size: %zu. Expected: %zu\n", SYMMETRIC_KEY_SIZE_BYTES, expectedKeySize);
        return NULL;
    }

    size_t ciphertextSize = CryptoWrapper::getCiphertextSizeAES_GCM256(messageSize);

    BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(ciphertextSize);
    if (ciphertext == NULL)
    {
        printf("Failed to allocate buffer for ciphertext.\n");
        return NULL;
    }

    size_t actualCiphertextSize = 0;
    if (!CryptoWrapper::encryptAES_GCM256(_sessionKey, expectedKeySize, message, messageSize, NULL, 0, ciphertext, ciphertextSize, &actualCiphertextSize))
    {
        printf("Encryption failed. Session key size: %zu, Message size: %zu, Ciphertext size: %zu\n", expectedKeySize, messageSize, ciphertextSize);
        Utils::freeBuffer(ciphertext);
        return NULL;
    }


    ByteSmartPtr result(ciphertext, actualCiphertextSize);
    return result;
}




bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
{
    size_t ciphertextSize = header->payloadSize;
    size_t plaintextSize = CryptoWrapper::getPlaintextSizeAES_GCM256(ciphertextSize);

    BYTE* plaintext = (BYTE*)Utils::allocateBuffer(plaintextSize);
    if (plaintext == NULL)
    {
        return false;
    }

    size_t actualPlaintextSize = 0;
    if (!CryptoWrapper::decryptAES_GCM256(_sessionKey, SYMMETRIC_KEY_SIZE_BYTES, buffer, ciphertextSize, NULL, 0, plaintext, plaintextSize, &actualPlaintextSize))
    {
        Utils::freeBuffer(plaintext);
        return false;
    }

    if (pPlaintextSize != NULL)
    {
        *pPlaintextSize = actualPlaintextSize;
    }

    memcpy(buffer, plaintext, actualPlaintextSize);
    Utils::freeBuffer(plaintext);
    return true;
}

bool Session::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        printf("Session is not active or in DATA_SESSION_MESSAGE state.\n");
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        printf("Failed to prepare encrypted message.\n");
        return false;
    }

    bool result = sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
    if (!result)
    {
        printf("Failed to send message internally.\n");
    }

    return result;
}

ByteSmartPtr Session::concat(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += messagePart.partSize;
        partsList.push_back(messagePart);
    }
    va_end(args);

    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}

ByteSmartPtr Session::packMessageParts(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += (messagePart.partSize + sizeof(size_t));
        partsList.push_back(messagePart);
    }
    va_end(args);

    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    std::list<MessagePart>::iterator it = partsList.begin();
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (; it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, (void*)&(it->partSize), sizeof(size_t));
        pos += sizeof(size_t);
        spaceLeft -= sizeof(size_t);
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}

bool Session::unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result)
{
    std::list<MessagePart> partsList;
    size_t pos = 0;
    while (pos < bufferSize)
    {
        if (pos + sizeof(size_t) >= bufferSize)
        {
            return false;
        }

        size_t* partSize = (size_t*)(buffer + pos);
        pos += sizeof(size_t);
        if (*partSize == 0 || (pos + *partSize) > bufferSize)
            return false;

        MessagePart messagePart;
        messagePart.partSize = *partSize;
        messagePart.part = (buffer + pos);
        partsList.push_back(messagePart);
        pos += *partSize;
    }

    result.resize(partsList.size());
    unsigned int i = 0;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        result[i].part = it->part;
        result[i].partSize = it->partSize;
        i++;
    }
    return true;
}