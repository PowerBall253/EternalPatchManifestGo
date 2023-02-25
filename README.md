# EternalPatchManifestGo

![Build Status](https://github.com/PowerBall253/EternalPatchManifestGo/actions/workflows/test.yml/badge.svg)


DOOM Eternal build manifest patcher, rewritten in Go.

## Usage

```
./DEternal_patchManifest <AES key>
```

Where AES key is the key used for AES encryption/decryption. The current valid key is `8B031F6A24C5C4F3950130C57EF660E9`.

## Compiling
The project requires the [go toolchain](https://go.dev/dl/) to be compiled.

To compile, run:

```
go build -o DEternal_patchManifest -ldflags="-s -w" .
```

To set a version number, build with:

```
go build -o DEternal_patchManifest -ldflags="-s -w -X 'main.Version=vX.Y.Z'" .
```

(replace vX.Y.Z with the version number you prefer).

Additionally, you may use [UPX](https://upx.github.io/) to compress the binary:

```
upx --best DEternal_patchManifest
```
