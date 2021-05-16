# EternalPatchManifestLinux
[![Build Status](https://www.travis-ci.com/PowerBall253/EternalPatchManifestLinux.svg?branch=main)](https://www.travis-ci.com/PowerBall253/EternalPatchManifestLinux)

DOOM Eternal build manifest patcher, rewritten in C for Linux.

## Usage
```
./DEternal_patchManifest <AES key>
```
Where AES key is the key used for AES encryption/decryption. The current valid key is `8B031F6A24C5C4F3950130C57EF660E9`.

## Compiling
The project uses Cmake to compile, and requires OpenSSL to be installed.

First clone the repo by running:

```
git clone https://github.com/PowerBall253/EternalPatchManifestLinux.git
```

Then, generate the makefile by running:
```
cd EternalPatchManifestLinux
mkdir build
cd build
cmake ..
```

Finally, build with:
```
make
```

