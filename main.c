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
#include <stdbool.h>

#include "cJSON/cJSON.h"
#include "crypto.h"

// Get filesize from the given file
size_t get_filesize(const char *path)
{
    FILE *f = fopen(path, "r");

    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    size_t filesize = ftell(f);

    fclose(f);

    return filesize;
}

// Optimize the JSON by removing uneeded entries and using dummy data
char *optimize_bm(const char *bm_json)
{
    cJSON *files = NULL;
    cJSON *file = NULL;
    
    cJSON *json = cJSON_Parse(bm_json);

    files = cJSON_GetObjectItemCaseSensitive(json, "files");

    cJSON_ArrayForEach(file, files) {
        cJSON *filesize = cJSON_GetObjectItemCaseSensitive(file, "fileSize");
        size_t new_filesize = get_filesize(file->string);

        if (new_filesize == -1)
            continue;

        cJSON_SetNumberValue(filesize, new_filesize);

        printf("Found file %s, fileSize updated to: %li\n", file->string, new_filesize);

        cJSON *new_hashes = cJSON_CreateArray();
        cJSON *hash_str = cJSON_CreateString("e2df1b2aa831724ec987300f0790f04ad3f5beb8");

        int num_hashes = (int)(new_filesize / 4294967295) + (new_filesize % 4294967295 > 0 ? 1 : 0);

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
    printf("EternalPatchManifestLinux v1.3.3 by PowerBall253 :)\n\n");

    // Print usage
    if (argc < 2) {
        printf("Usage:\n");
        printf("%s <AES key>\n\n", argv[0]);
        printf("AES key: Hex key for AES encryption/decryption of the file.\n\n");
        printf("Example:\n");
        printf("%s 8B031F6A24C5C4F3950130C57EF660E9\n", argv[0]);
        return 1;
    }

    // Read the build manifest file
    FILE *build_manifest = fopen("build-manifest.bin", "rb");

    if (!build_manifest) {
        fprintf(stderr, "ERROR: Failed to open build manifest for reading!\n");
        return 1;
    }

    fseek(build_manifest, 0, SEEK_END);
    size_t bm_len = ftell(build_manifest);
    fseek(build_manifest, 0, SEEK_SET);

    unsigned char *bm_bytes = malloc(bm_len);

    if (fread(bm_bytes, 1, bm_len, build_manifest) != bm_len) {
        fprintf(stderr, "ERROR: Failed to read from build manifest!\n");
        return 1;
    }

    fclose(build_manifest);

    // Decrypt the build manifest data into a JSON
    char *bm_dec = decrypt_bm(bm_bytes, bm_len, argv[1]);
    free(bm_bytes);

    if (!bm_dec) {
        fprintf(stderr, "ERROR: Failed to decrypt build manifest!\n");
        return 1;
    }

    // Optimize the JSON file
    char *bm_json = optimize_bm(bm_dec);
    size_t bm_json_len = strlen(bm_json);
    free(bm_dec);

    if (!bm_json) {
        fprintf(stderr, "ERROR: Failed to modify the decrypted build manifest JSON!\n");
        return 1;
    }

    // Re-encrypt the build manifest JSON
    unsigned char *bm_enc = encrypt_bm(bm_json, argv[1]);
    free(bm_json);

    if (!bm_enc) {
        fprintf(stderr, "ERROR: Failed to encrypt build manifest!\n");
        return 1;
    }
    
    // Write new build manifest data to file
    build_manifest = fopen("build-manifest.bin", "wb");

    if (!build_manifest) {
        fprintf(stderr, "ERROR: Failed to open build manifest for writing!\n");
        return 1;
    }

    fwrite(bm_enc, 1, 0xC + bm_json_len + 0x10 + 0x40, build_manifest);
    free(bm_enc);
    
    fclose(build_manifest);

    return 0;
}
