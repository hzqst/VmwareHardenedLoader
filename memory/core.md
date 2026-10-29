---
title: core
type: note
permalink: VmwareHardenedLoader/core
---

# Core project map

- Purpose: VMwareHardenedLoader-ng is a Windows WDM kernel driver that filters selected VMware firmware/PnP observations inside Windows guests.
- Source map:
  - `VmLoader/driver.cpp`: DriverEntry orchestration and reverse-order unload.
  - `VmLoader/kernel_symbols.cpp/.h`: running-kernel discovery, signed/embedded KPH dynamic-data lookup, PE/RVA validation.
  - `VmLoader/firmware_hook.cpp/.h`: firmware provider handler replacement for FIRM, ACPI, and RSMB.
  - `VmLoader/pnp_hook.cpp/.h`: user-mode Configuration Manager registry callback for VMware PCI/USB/HDAUDIO enumeration.
  - `shared/symbol_config.h`: service Parameters value names; currently only DynDataDirectory.
  - `VmLoader/PrepareDynData.ps1`: downloads/validates KPH XML, builds CustomBuildTool, generates/signs/verifies v20 dynamic data, emits public-key header and bin artifacts.
  - `VmLoader/VmLoader.vcxproj`, `VmLoader.sln`: maintained build entrypoints.
  - `.github/workflows/windows.yml`, `.github/workflows/nightly.yml`: pull-request/tag builds and the scheduled nightly build; the nightly sets `VMLOADER_KPHDYN_URL` to the kphtools `nightly` release manifest and publishes the `nightly` prerelease.
  - `thirdparty/systeminformer`: git submodule providing kphlib and CustomBuildTool/CustomSignTool.
- DriverEntry invariant: load kernel symbols -> install firmware hooks -> install PnP hooks; failure stops later stages and rolls back firmware hooks if PnP registration fails. Unload removes PnP then firmware hooks.
- Dynamic-data invariant: external dyndata.bin/dyndata.sig is accepted only after embedded public-key signature verification, size limits, exact kernel identity match, required firmware fields, and writable/non-executable/distinct RVA checks; embedded v20 data is fallback.
- Runtime constraints: undocumented Windows kernel globals and firmware-provider layout may change across updates; x64 and ARM64 Debug/Release are maintained build targets, but ARM64 runtime behavior still requires validation on each target Windows build.
- Read [[tech_stack]] for toolchain/dependency details.
- Read [[conventions]] for code and safety invariants.
- Read [[suggested_commands]] for Windows commands.
- Read [[task_completion]] for completion verification.
