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

#ifndef CRYPTO_H
#define CRYPTO_H

char *decrypt_bm(unsigned char *enc_data, int enc_data_len, char *hex_key);
unsigned char *encrypt_bm(char *bm_json, char *hex_key);

#endif