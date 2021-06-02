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

#include <openssl/asn1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "cJSON/cJSON.h"
#include "crypto.h"

long get_filesize(const char *path)
{
    FILE *f = fopen(path, "r");

    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);

    fclose(f);

    return filesize;
}

char *optimize_bm(char *bm_json)
{
    cJSON *files = NULL;
    cJSON *file = NULL;
    
    cJSON *json = cJSON_Parse(bm_json);

    files = cJSON_GetObjectItemCaseSensitive(json, "files");

    cJSON_ArrayForEach(file, files) {
        cJSON *filesize = cJSON_GetObjectItemCaseSensitive(file, "fileSize");
        long new_filesize = get_filesize(file->string);

        if (new_filesize == -1)
            continue;

        cJSON_SetNumberValue(filesize, new_filesize);

        printf("Found file %s, fileSize updated to: %li\n", file->string, new_filesize);

        cJSON *new_hashes = cJSON_CreateArray();
        cJSON *hash_str = cJSON_CreateString("e2df1b2aa831724ec987300f0790f04ad3f5beb8");

        int num_hashes = (new_filesize / 4294967295) + (new_filesize % 4294967295 > 0);

        for (int i = 0;  i < num_hashes; i++)
            cJSON_AddItemReferenceToArray(new_hashes, hash_str);

        cJSON_ReplaceItemInObject(file, "hashes", new_hashes);

        cJSON *chunksize = cJSON_GetObjectItemCaseSensitive(file, "chunkSize");
        cJSON_SetNumberValue(chunksize, 4294967295);
    }

    char *json_str = cJSON_PrintBuffered(json, 30720, false);

    cJSON_Delete(json);

    return json_str;
}

int main(int argc, char **argv)
{
    printf("EternalPatchManifestLinux v1.0 by PowerBall253 :)\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("%s <AES key>\n\n", argv[0]);
        printf("AES key: Hex key for AES encryption/decryption of the file.\n\n");
        printf("Example:\n");
        printf("%s 8B031F6A24C5C4F3950130C57EF660E9\n", argv[0]);
        return 1;
    }

    FILE *build_manifest = fopen("build-manifest.bin", "rb");

    if (!build_manifest) {
        fprintf(stderr, "ERROR: Failed to open build manifest for reading!\n");
        return 1;
    }

    fseek(build_manifest, 0, SEEK_END);
    long bm_len = ftell(build_manifest);
    fseek(build_manifest, 0, SEEK_SET);

    unsigned char *bm_bytes = malloc(bm_len);

    if (fread(bm_bytes, 1, bm_len, build_manifest) != bm_len) {
        fprintf(stderr, "ERROR: Failed to read from build manifest!\n");
        return 1;
    }

    fclose(build_manifest);

    char *bm_dec = decrypt_bm(bm_bytes, bm_len, argv[1]);
    free(bm_bytes);

    if (!bm_dec)
        return 1;

    char *bm_json = optimize_bm(bm_dec);
    free(bm_dec);

    if (!bm_json)
        return 1;

    unsigned char *bm_enc = encrypt_bm(bm_json, argv[1]);
    free(bm_json);

    if (!bm_enc)
        return 1;
    
    build_manifest = fopen("build-manifest.bin", "wb");

    fwrite(bm_enc, 1, 0xC + strlen(bm_json) + 0x10 + 0x40, build_manifest);
    free(bm_enc);
    
    fclose(build_manifest);

    return 0;
}
