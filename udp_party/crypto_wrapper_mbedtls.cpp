

#include <stdlib.h>
#include <string.h>
#include "crypto_wrapper.h"
#include "utils.h"
#ifdef MBEDTLS
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include <iostream>
#include <stdio.h>
#include <cstring>
#include "../udp_party/utils.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include <mbedtls/dhm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/bignum.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include <mbedtls/error.h>


#ifdef WIN
#pragma comment (lib, "mbedtls.lib")
#endif // #ifdef WIN








int getRandom(void* contextData, BYTE* output, size_t len)
{
	if (!Utils::generateRandom(output, len))
	{
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}
	return (0);
}


bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, IN size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL)
    {
        printf("mbedtls_md_info_from_type failed\n");
        return false;
    }

    if (macBufferSizeBytes < mbedtls_md_get_size(md_info))
    {
        printf("mbedtls_md_hmac failed - output buffer too small!\n");
        return false;
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    int ret;
    if ((ret = mbedtls_md_setup(&ctx, md_info, 1)) != 0)
    {
        printf("mbedtls_md_setup failed\n");
        mbedtls_md_free(&ctx);
        return false;
    }

    if ((ret = mbedtls_md_hmac_starts(&ctx, key, keySizeBytes)) != 0)
    {
        printf("mbedtls_md_hmac_starts failed\n");
        mbedtls_md_free(&ctx);
        return false;
    }

    if ((ret = mbedtls_md_hmac_update(&ctx, message, messageSizeBytes)) != 0)
    {
        printf("mbedtls_md_hmac_update failed\n");
        mbedtls_md_free(&ctx);
        return false;
    }

    if ((ret = mbedtls_md_hmac_finish(&ctx, macBuffer)) != 0)
    {
        printf("mbedtls_md_hmac_finish failed\n");
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);
    return true;
}


bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
int ret;
    const mbedtls_md_info_t *md_info;

    // Get the message digest info for SHA-256
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return false;
    }

    // Perform HKDF
    ret = mbedtls_hkdf(md_info,
                       salt, saltSizeBytes,
                       secretMaterial, secretMaterialSizeBytes,
                       context, contextSizeBytes,
                       outputBuffer, outputBufferSizeBytes);

    // Return true if successful, false otherwise
    return (ret == 0);
}


size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}


bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	mbedtls_gcm_context ctx;
    mbedtls_entropy_context entropy;
    int ret;
    unsigned char iv[IV_SIZE_BYTES];
    unsigned char tag[TAG_SIZE];

    // Check if the output buffer is large enough
    if (ciphertextBufferSizeBytes < plaintextSizeBytes + IV_SIZE_BYTES + TAG_SIZE) {
        return false;
    }

    mbedtls_gcm_init(&ctx);
    mbedtls_entropy_init(&entropy);

    // Set the key
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keySizeBytes * 8);
    if (ret != 0) {
        goto cleanup;
    }

    // Generate a random IV
    ret = mbedtls_entropy_func(&entropy, iv, IV_SIZE_BYTES);
    if (ret != 0) {
        goto cleanup;
    }

    // Perform encryption
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintextSizeBytes,
                                    iv, IV_SIZE_BYTES, aad, aadSizeBytes,
                                    plaintext, ciphertextBuffer + IV_SIZE_BYTES, TAG_SIZE, tag);

    if (ret != 0) {
        goto cleanup;
    }

    // Copy IV to the beginning of ciphertext buffer
    memcpy(ciphertextBuffer, iv, IV_SIZE_BYTES);
    // Copy tag to the end of ciphertext buffer
    memcpy(ciphertextBuffer + IV_SIZE_BYTES + plaintextSizeBytes, tag, TAG_SIZE);

    *pCiphertextSizeBytes = plaintextSizeBytes + IV_SIZE_BYTES + TAG_SIZE;

cleanup:
    mbedtls_gcm_free(&ctx);
    mbedtls_entropy_free(&entropy);
    return (ret == 0);
}


bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	mbedtls_gcm_context ctx;
    int ret;
    const unsigned char* iv = ciphertext;
    const unsigned char* encrypted = ciphertext + IV_SIZE_BYTES;
    const unsigned char* tag = ciphertext + ciphertextSizeBytes - TAG_SIZE;
    size_t encryptedSize = ciphertextSizeBytes - IV_SIZE_BYTES - TAG_SIZE;

    // Check if the ciphertext is large enough to contain IV and TAG
    if (ciphertextSizeBytes <= IV_SIZE_BYTES + TAG_SIZE) {
        return false;
    }

    // Check if the output buffer is large enough
    if (plaintextBufferSizeBytes < encryptedSize) {
        return false;
    }

    mbedtls_gcm_init(&ctx);

    // Set the key
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keySizeBytes * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }

    // Perform decryption
      // Perform decryption
    ret = mbedtls_gcm_auth_decrypt(&ctx, encryptedSize,
                                   iv, IV_SIZE_BYTES, aad, aadSizeBytes,
                                   tag, TAG_SIZE,
                                   encrypted, plaintextBuffer);

    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }

    // Only set pPlaintextSizeBytes if it's not null
    if (pPlaintextSizeBytes != NULL) {
        *pPlaintextSizeBytes = encryptedSize;
    }

    mbedtls_gcm_free(&ctx);
    return true;
}


bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	KeypairContext* newContext = (KeypairContext*)Utils::allocateBuffer(sizeof(KeypairContext));
    if (newContext == NULL)
    {
        printf("Error during memory allocation in readRSAKeyFromFile()\n");
        return false;
    }

    mbedtls_pk_init(newContext);
    ByteSmartPtr bufferSmartPtr = Utils::readBufferFromFile(keyFilename);
    if (bufferSmartPtr == NULL)
    {
        printf("Error reading keypair file\n");
        return false;
    }

    int res = mbedtls_pk_parse_key(newContext, 
                                   bufferSmartPtr, 
                                   bufferSmartPtr.size(), 
                                   (const BYTE*)filePassword, 
                                   strnlen_s(filePassword, MAX_PASSWORD_SIZE_BYTES));
    if (res != 0)
    {
        char error_buf[100];
        mbedtls_strerror(res, error_buf, sizeof(error_buf));
        printf("Error during mbedtls_pk_parse_key(): %s (%d)\n", error_buf, res);
        cleanKeyContext(&newContext);
        return false;
    }
    else
    {
        cleanKeyContext(pKeyContext);
        *pKeyContext = newContext;
        return true;
    }
}

//===============================change only in this section=====================================================//
bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
    if (signatureBufferSizeBytes != SIGNATURE_SIZE_BYTES)
    {
        printf("Signature buffer size is wrong!\n");
        return false;
    }

    int ret;
    mbedtls_pk_context* pk = privateKeyContext;

    // Verify the private key context
    if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_RSA)
    {
        printf("Invalid key type, expected RSA\n");
        return false;
    }

    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    // Hash the message
    BYTE hash[HASH_SIZE_BYTES];
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), message, messageSizeBytes, hash);
    if (ret != 0)
    {
        printf("Failed to hash the message\n");
        return false;
    }

    // Generate the signature
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0)
    {
        printf("Failed to initialize random generator\n");
        return false;
    }

    ret = mbedtls_rsa_rsassa_pss_sign(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, HASH_SIZE_BYTES, hash, signatureBuffer);
    if (ret != 0)
    {
        printf("Failed to sign the message\n");
        return false;
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return true;
}

bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
    if (signatureSizeBytes != SIGNATURE_SIZE_BYTES)
    {
        printf("Signature size is wrong!\n");
        return false;
    }

    int ret;
    mbedtls_pk_context* pk = publicKeyContext;

    // Verify the public key context
    if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_RSA)
    {
        printf("Invalid key type, expected RSA\n");
        return false;
    }

    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    // Hash the message
    BYTE hash[HASH_SIZE_BYTES];
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), message, messageSizeBytes, hash);
    if (ret != 0)
    {
        printf("Failed to hash the message\n");
        return false;
    }

    // Verify the signature
    ret = mbedtls_rsa_rsassa_pss_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, HASH_SIZE_BYTES, hash, signature);
    if (ret == 0)
    {
        *result = true;
    }
    else
    {
        *result = false;
    }

    return (ret == 0);
}
//=======================================till here=================================================================//

void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		mbedtls_pk_free(*pKeyContext);
		Utils::freeBuffer(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN mbedtls_pk_context* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	memset(publicKeyPemBuffer, 0, publicKeyBufferSizeBytes);
	if (mbedtls_pk_write_pubkey_pem(keyContext, publicKeyPemBuffer, publicKeyBufferSizeBytes) != 0)
	{
		printf("Error during mbedtls_pk_write_pubkey_pem()\n");
		return false;
	}

	return true;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	mbedtls_pk_init(context);
	if (mbedtls_pk_parse_public_key(context, publicKeyPemBuffer, strnlen_s((const char*)publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES) + 1) != 0)
	{
		printf("Error during mbedtls_pk_parse_key() in loadPublicKeyFromPemBuffer()\n");
		return false;
	}
	return true;
}


bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{

    DhContext* dhContext = (DhContext*) malloc(sizeof(DhContext));
    if (dhContext == NULL)
    {
        printf("Error during memory allocation in startDh()\n");
        return false;
    }
    mbedtls_dhm_init(dhContext);
    mbedtls_mpi P;
    mbedtls_mpi G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    const BYTE pBin[] = MBEDTLS_DHM_RFC3526_MODP_3072_P_BIN;
    const BYTE gBin[] = MBEDTLS_DHM_RFC3526_MODP_3072_G_BIN;
    
    // select the finite group modulus
    int ret = mbedtls_mpi_read_binary(&P, pBin, sizeof(pBin));
    if (ret != 0)
    {
        printf("Error reading P: %d\n", ret);
        cleanDhContext(&dhContext);
        return false;
    }
    
    // select the pre-agreed generator element of the finite group
    ret = mbedtls_mpi_read_binary(&G, gBin, sizeof(gBin));
    if (ret != 0)
    {
        printf("Error reading G: %d\n", ret);
        cleanDhContext(&dhContext);
        return false;
    }
    
    // Set P and G in the DH context
    ret = mbedtls_dhm_set_group(dhContext, &P, &G);
    if (ret != 0)
    {
        printf("Error setting DH group: %d\n", ret);
        cleanDhContext(&dhContext);
        return false;
    }
    
    // Generate public key
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        // Handle error
        printf("Error seed");
        cleanDhContext(&dhContext);
        return false;
    }

    size_t publicKeyLen = 0;
    ret = mbedtls_dhm_make_public(dhContext, (int)mbedtls_mpi_size(&P), publicKeyBuffer, publicKeyBufferSizeBytes, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        printf("Error generating public key: %d\n", ret);
        cleanDhContext(&dhContext);
        return false;
    }

    // Clean up temporary MPIs
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);
    
    // Set the output parameter
    *pDhContext = dhContext;
    
    return true;

}


bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
    // printf("getDhSharedSecret\n\n\n\n\n");
	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
    {
        printf("Invalid input parameters in getDhSharedSecret()\n");
        return false;
    }

    int ret;
    size_t sharedSecretLen = 0;

    // Set the peer's public key
    ret = mbedtls_dhm_read_public(dhContext, peerPublicKey, peerPublicKeySizeBytes);
    if (ret != 0)
    {
        printf("Error reading peer's public key: %d\n", ret);
        return false;
    }

     mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

mbedtls_ctr_drbg_init(&ctr_drbg);
mbedtls_entropy_init(&entropy);

if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
    // Handle error
    printf("Error seed");
        cleanDhContext(&dhContext);
        return false;
}
    // Calculate the shared secret
    ret = mbedtls_dhm_calc_secret(dhContext, sharedSecretBuffer, sharedSecretBufferSizeBytes, &sharedSecretLen, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        printf("Error calculating shared secret: %d\n", ret);
        return false;
    }

    // Optional: You might want to check if the shared secret length matches your expectations
    if (sharedSecretLen != sharedSecretBufferSizeBytes)
    {
        printf("Warning: Shared secret length (%zu) differs from buffer size (%zu)\n", sharedSecretLen, sharedSecretBufferSizeBytes);
    }

    return true;
}


void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		mbedtls_dhm_free(*pDhContext);
		Utils::freeBuffer(*pDhContext);
		*pDhContext = NULL;
	}
}


bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    uint32_t flags;
    int res = -1;

    if (mbedtls_x509_crt_parse(&cacert, cACcertBuffer, cACertSizeBytes) != 0)
    {
        printf("Error parsing CA certificate\n");
        return false;
    }

    if (mbedtls_x509_crt_parse(&clicert, certBuffer, certSizeBytes) != 0)
    {
        printf("Error parsing certificate to verify\n");
        mbedtls_x509_crt_free(&cacert);
        return false;
    }

    // Verify the certificate
    res = mbedtls_x509_crt_verify(&clicert, &cacert, NULL, NULL, &flags, NULL, NULL);
    if (res != 0)
    {
        char error_buf[1024];
        mbedtls_strerror(res, error_buf, sizeof(error_buf));
        printf("Certificate verification failed: %s\n", error_buf);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_x509_crt_free(&clicert);
        return false;
    }

    // Extract the Common Name
    char cn_buf[256] = {0};
    const mbedtls_x509_name* name;
    for(name = &clicert.subject; name != NULL; name = name->next)
    {
        if(name->oid.len == 3 && memcmp(name->oid.p, "\x55\x04\x03", 3) == 0)
        {
            // This is the Common Name
            size_t cn_len = name->val.len < sizeof(cn_buf) - 1 ? name->val.len : sizeof(cn_buf) - 1;
            memcpy(cn_buf, name->val.p, cn_len);
            cn_buf[cn_len] = '\0';
            break;
        }
    }

    if(cn_buf[0] == '\0')
    {
        printf("Common Name not found in the certificate\n");
        mbedtls_x509_crt_free(&cacert);
        mbedtls_x509_crt_free(&clicert);
        return false;
    }

    printf("CN: %s\n", cn_buf);
    printf("expectedCN: %s\n", expectedCN);

    // Convert both strings to lowercase for case-insensitive comparison
    char cn_lower[256];
    char expected_cn_lower[256];
    size_t i;

    for (i = 0; cn_buf[i] && i < sizeof(cn_lower) - 1; i++) {
        cn_lower[i] = tolower((unsigned char)cn_buf[i]);
    }
    cn_lower[i] = '\0';

    for (i = 0; expectedCN[i] && i < sizeof(expected_cn_lower) - 1; i++) {
        expected_cn_lower[i] = tolower((unsigned char)expectedCN[i]);
    }
    expected_cn_lower[i] = '\0';

    if (strcmp(cn_lower, expected_cn_lower) != 0)
    {
        printf("Common Name mismatch\n");
        mbedtls_x509_crt_free(&cacert);
        mbedtls_x509_crt_free(&clicert);
        return false;
    }

    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&clicert);
    return true;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{
	BYTE publicKeyPemBuffer[PEM_BUFFER_SIZE_BYTES];

	mbedtls_x509_crt clicert;
	mbedtls_x509_crt_init(&clicert);

	if (mbedtls_x509_crt_parse(&clicert, certBuffer, certSizeBytes) != 0)
	{
		printf("Error parsing certificate to read\n");
		mbedtls_x509_crt_free(&clicert);
		return false;
	}
	
	KeypairContext* certPublicKeyContext = &(clicert.pk);
	// we will use a PEM buffer to create an independant copy of the public key context
	bool result = writePublicKeyToPemBuffer(certPublicKeyContext, publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES);
	mbedtls_x509_crt_free(&clicert);

	if (result)
	{
		KeypairContext* publicKeyContext = (KeypairContext*)Utils::allocateBuffer(sizeof(KeypairContext));
		if (publicKeyContext == NULL)
		{
			printf("Error during memory allocation in getPublicKeyFromCertificate()\n");
			return false;
		}

		if (loadPublicKeyFromPemBuffer(publicKeyContext, publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES))
		{
			cleanKeyContext(pPublicKeyContext);
			*pPublicKeyContext = publicKeyContext;
			return true;
		}
		else
		{
			cleanKeyContext(&publicKeyContext);
			return false;
		}
	}
	return false;
}

#endif // #ifdef MBEDTLS


/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://tls.mbed.org/api/gcm_8h.html
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* mbedtls_md_hmac
* mbedtls_hkdf
* mbedtls_gcm_setkey
* mbedtls_gcm_crypt_and_tag
* mbedtls_gcm_auth_decrypt
* mbedtls_md
* mbedtls_pk_get_type
* mbedtls_pk_rsa
* mbedtls_rsa_set_padding
* mbedtls_rsa_rsassa_pss_sign
* mbedtls_md_info_from_type
* mbedtls_rsa_rsassa_pss_verify
* mbedtls_dhm_set_group
* mbedtls_dhm_make_public
* mbedtls_dhm_read_public
* mbedtls_dhm_calc_secret
* mbedtls_x509_crt_verify
* 
* 
* 
* 
* 
* 
* 
*/