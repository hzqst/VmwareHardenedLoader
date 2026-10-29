# Build requirements and dynamic data

[Back to README](../../README.md) · [简体中文](../zh-CN/build.md)

## Requirements

- Visual Studio 2022
- Windows Driver Kit 10
- .NET SDK 9 or newer for CustomBuildTool

The maintained build configurations are Release|x64, Debug|x64, Release|ARM64, and Debug|ARM64.

## Build

Open a Visual Studio 2022 Developer Command Prompt with the WDK installed, then run:

~~~bat
msbuild VmLoader.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64
~~~

For a debug build, use:

~~~bat
msbuild VmLoader.sln /m /t:Rebuild /p:Configuration=Debug /p:Platform=x64
~~~

Use /p:Platform=ARM64 with either configuration to cross-build the ARM64 driver. The dynamic-data preparation tools still run as x64 host utilities and generate a shared data set containing both AMD64 and ARM64 records.

Before C/C++ compilation, the project automatically performs these steps:

1. Downloads the latest manifest from https://github.com/HLND2T/kphtools/releases/latest/download/kphdyn.xml, or from the URL in VMLOADER_KPHDYN_URL when that environment variable is set, into a temporary file.
2. Parses the XML with DTD processing disabled and verifies that usable firmware records exist.
3. Atomically replaces thirdparty/systeminformer/kphlib/kphdyn.xml only after validation succeeds.
4. Builds System Informer's CustomBuildTool and generates the v20 embedded source plus ksidyn.bin.
5. Signs the binary with RSA-PSS/SHA-512, verifies it again with the matching public key, and publishes it.
6. Generates the driver public-key header under the intermediate build directory.

The build intentionally does not use a cached manifest. A download, XML validation, generation, signing, or verification failure stops the build.

The manifest override is validated as an absolute HTTPS URL before download; any other value stops the build. The Nightly workflow uses it to build against the kphtools nightly manifest:

~~~bat
set VMLOADER_KPHDYN_URL=https://github.com/HLND2T/kphtools/releases/download/nightly/kphdyn.xml
msbuild VmLoader.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64
~~~

The build requires HTTPS access to GitHub and may require NuGet access when restoring CustomBuildTool packages.

## Dynamic data format

The build produces KPH dynamic configuration version 20. It extends the System Informer v19 kernel layout with these ULONG RVAs:

- `nt!ExpFirmwareTableResource`
- `nt!ExpFirmwareTableProviderListHead`

Each record is selected by an exact match on:

~~~text
Class + Machine + TimeDateStamp + SizeOfImage
~~~

A record that does not contain both firmware fields stores ULONG_MAX for the missing value and is treated as unsupported at runtime.

The driver validates both resolved RVAs before use. They must be non-zero, distinct, and located in writable, non-executable sections of the running ntoskrnl.exe image.

## Signing key

On the first successful preparation, if both key files are absent, the build creates a VmLoader-specific 4096-bit RSA key pair here:

~~~text
thirdparty\systeminformer\tools\CustomSignTool\Resources\kph.key
thirdparty\systeminformer\tools\CustomSignTool\Resources\public.key
~~~

Both files are ignored by the System Informer submodule. The private key is never copied into the parent repository, intermediate public header, or packaged output.

Back up kph.key and public.key together. If exactly one file is present, the build fails instead of silently rotating the signing identity. Losing or replacing the key pair requires rebuilding the driver and re-signing all external dynamic data.

## Build outputs

Both x64 and ARM64 builds publish these runtime files under bin:

~~~text
bin\vmloader.sys
bin\vmloader.pdb
bin\dyndata.bin
bin\dyndata.sig
~~~

The build target's driver, dynamic-data files, and PDB are copied to the same directory as the install scripts. Building another architecture or configuration locally overwrites the previous generated artifacts in bin; the CI workflow builds each target in an isolated job and packages it immediately.

`vmloader.sys` remains unsigned. Sign it with a test or production code-signing certificate before loading it.
