#include <string.h>
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define LOG_TAG "CryptUtil"
#define LOG_I(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

__attribute__((visibility("default")))
void my_clear_cache(void *s, void *e) {
    __builtin___clear_cache(s, e);
    LOG_I("Cache refreshed!");
}

/*__attribute__((visibility("default")))
char* bytesToHex(const unsigned char* bytes, int length) {
    static char hexString[129];
    for (int i = 0; i < length && i < 64; i++) {
        sprintf(hexString + i * 2, "%02x", bytes[i]);
    }
    hexString[128] = '\0';
    return hexString;
}*/

__attribute__((visibility("default")))
void decrypt(unsigned char* data, size_t size, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_E("Failed to create EVP_CIPHER_CTX");
        return;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        LOG_E("Failed to initialize decryption");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len;
    unsigned char* plaintext = (unsigned char*)malloc(size);
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, data, size)) {
        LOG_E("Failed to decrypt data");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return;
    }

    memcpy(data, plaintext, size);
    free(plaintext);
    EVP_CIPHER_CTX_free(ctx);
}
