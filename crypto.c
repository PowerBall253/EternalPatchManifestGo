/*
* This file is part of EternalPatchManifestLinux (https://github.com/PowerBall253/EternalPatchManifestLinux).
* Copyright (C) 2021 PowerBall253
*
* EternalPatchManifestLinux is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* EternalPatchManifestLinux is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with EternalPatchManifestLinux. If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>
#include <openssl/evp.h>

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

// Decrypt using AES GCM 128
size_t gcm_decrypt(const unsigned char *ciphertext, const size_t ciphertext_len,
                const unsigned char *aad, const size_t aad_len,
                unsigned char *tag,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        return -1;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len))
        return -1;

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len))
        return -1;

    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        return -1;

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }
    else {
        return -1;
    }
}

// Encrypt using AES GCM 128
size_t gcm_encrypt(unsigned char *plaintext, const size_t plaintext_len,
                const unsigned char *aad, const size_t aad_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        return -1;

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len))
        return -1;

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len))
        return -1;

    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;

    ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return -1;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Convert hex string to byte array
unsigned char *hex_to_bytes(const char *str)
{
    unsigned char *bytes = malloc(strlen(str) / 2);

    if (!bytes)
        return NULL;

    for (int i = 0; i < strlen(str); i += 2) {
        char byte_str[3];
        memcpy(byte_str, str + i, 2);
        byte_str[2] = '\0';

        char *endptr;
        bytes[i / 2] = strtol(byte_str, &endptr, 16);

        if (endptr == byte_str || *endptr != '\0' || errno == ERANGE) {
            free(bytes);
            return NULL;
        }
    }

    return bytes;
}

// Decrypt build manifest file into a JSON
char *decrypt_bm(const unsigned char *enc_data, const size_t enc_data_len, const char *hex_key)
{
    unsigned char iv[0xC];
    memcpy(iv, enc_data, 0xC);

    unsigned char tag[0x10];
    memcpy(tag, enc_data + enc_data_len - 0x50, 0x10);

    unsigned char *ciphertext = malloc(enc_data_len - 0xC - 0x50);

    if (!ciphertext) {
        perror("ERROR: Failed to allocate memory");
        return NULL;
    }

    memcpy(ciphertext, enc_data + 0xC, enc_data_len - 0xC - 0x50);

    unsigned char *key = hex_to_bytes(hex_key);

    if (!key) {
        eprintf("ERROR: Failed to get key bytes from provided key.\n");
        eprintf("Make sure the key provided is a valid hex string.\n");
        free(ciphertext);
        return NULL;
    }

    char *plaintext = malloc(enc_data_len - 0xC - 0x50);

    if (!plaintext) {
        perror("ERROR: Failed to allocate memory");
        free(key);
        free(ciphertext);
        return NULL;
    }

    size_t res = gcm_decrypt(ciphertext, enc_data_len - 0xC - 0x50, (unsigned char*)"build-manifest",
        strlen("build-manifest"), tag, key, iv, (unsigned char*)plaintext);

    free(key);
    free(ciphertext);

    if (res != enc_data_len - 0xC - 0x50) {
        eprintf("ERROR: Failed to decypt build manifest - corrupted file?\n");
        return NULL;
    }

    return plaintext;
}

// Re-encrypt build manifest JSON
unsigned char *encrypt_bm(const char *bm_json, const char *hex_key)
{
    unsigned char iv[0xC];

    if (getrandom(iv, 0xC, 0) != 0xC) {
        perror("ERROR: Failed to get random IV for encryption");
        return NULL;
    }
    
    unsigned char *key = hex_to_bytes(hex_key);

    if (!key) {
        eprintf("ERROR: Failed to get key bytes from provided key.\n");
        eprintf("Make sure the key provided is a valid hex string.\n");
        return NULL;
    }

    unsigned char tag[0x10];
    unsigned char *ciphertext = malloc(strlen(bm_json));

    if (!key) {
        perror("ERROR: Failed to allocate memory");
        free(key);
        return NULL;
    }

    size_t res = gcm_encrypt((unsigned char*)bm_json, strlen(bm_json), (unsigned char*)"build-manifest", 14, key, iv, ciphertext, tag);

    free(key);

    if (res != strlen(bm_json)) {
        eprintf("ERROR: Failed to encrypt new build manifest.\n");
        free(ciphertext);
        return NULL;
    }

    size_t bm_enc_len = 0xC + strlen(bm_json) + 0x10 + 0x40;

    unsigned char *bm_enc = malloc(bm_enc_len);

    if (!key) {
        perror("ERROR: Failed to allocate memory");
        free(bm_enc);
        free(ciphertext);
        return NULL;
    }

    memcpy(bm_enc, iv, 0xC);
    memcpy(bm_enc + 0xC, ciphertext, strlen(bm_json));
    memcpy(bm_enc + 0xC + strlen(bm_json), tag, 0x10);
    memset(bm_enc + 0xC + strlen(bm_json) + 0x10, 0, 0x40);

    free(ciphertext);

    return bm_enc;
}
