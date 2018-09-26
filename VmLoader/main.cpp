#include <fltkernel.h>
#include "cs_driver_mm.h"
#include "kernel_stl.h"
#include <set>

extern "C"
{
	PVOID g_NtosBase = NULL;
	PVOID g_NtosEnd = NULL;
	PVOID g_ExpFirmwareTableResource = NULL;
	PVOID g_ExpFirmwareTableProviderListHead = NULL;

#define EX_FIELD_ADDRESS(Type, Base, Member) ((PUCHAR)Base + FIELD_OFFSET(Type, Member))
#define EX_FOR_EACH_IN_LIST(_Type, _Link, _Head, _Current)                                             \
    for((_Current) = CONTAINING_RECORD((_Head)->Flink, _Type, _Link);                                   \
       (_Head) != (PLIST_ENTRY)EX_FIELD_ADDRESS(_Type, _Current, _Link);                               \
       (_Current) = CONTAINING_RECORD(((PLIST_ENTRY)EX_FIELD_ADDRESS(_Type, _Current, _Link))->Flink,  \
                                     _Type,                                                          \
                                     _Link)                                                          \
       )

	typedef NTSTATUS(__cdecl *PFNFTH)(PSYSTEM_FIRMWARE_TABLE_INFORMATION);
	
	typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER_NODE {
		SYSTEM_FIRMWARE_TABLE_HANDLER SystemFWHandler;
		LIST_ENTRY FirmwareTableProviderList;
	} SYSTEM_FIRMWARE_TABLE_HANDLER_NODE, *PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;         // Not filled in
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef enum _MEMORY_INFORMATION_CLASS_EX
	{
		MemoryBasicInformationEx = 0,
		MemoryWorkingSetInformation = 1,
		MemoryMappedFilenameInformation = 2,
		MemoryRegionInformation = 3,
		MemoryWorkingSetExInformation = 4,
	} MEMORY_INFORMATION_CLASS_EX;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0x0,
		SystemProcessorInformation = 0x1,
		SystemPerformanceInformation = 0x2,
		SystemTimeOfDayInformation = 0x3,
		SystemPathInformation = 0x4,
		SystemProcessInformation = 0x5,
		SystemCallCountInformation = 0x6,
		SystemDeviceInformation = 0x7,
		SystemProcessorPerformanceInformation = 0x8,
		SystemFlagsInformation = 0x9,
		SystemCallTimeInformation = 0xa,
		SystemModuleInformation = 0xb,
		SystemLocksInformation = 0xc,
		SystemStackTraceInformation = 0xd,
		SystemPagedPoolInformation = 0xe,
		SystemNonPagedPoolInformation = 0xf,
		SystemHandleInformation = 0x10,
		SystemObjectInformation = 0x11,
		SystemPageFileInformation = 0x12,
		SystemVdmInstemulInformation = 0x13,
		SystemVdmBopInformation = 0x14,
		SystemFileCacheInformation = 0x15,
		SystemPoolTagInformation = 0x16,
		SystemInterruptInformation = 0x17,
		SystemDpcBehaviorInformation = 0x18,
		SystemFullMemoryInformation = 0x19,
		SystemLoadGdiDriverInformation = 0x1a,
		SystemUnloadGdiDriverInformation = 0x1b,
		SystemTimeAdjustmentInformation = 0x1c,
		SystemSummaryMemoryInformation = 0x1d,
		SystemMirrorMemoryInformation = 0x1e,
		SystemPerformanceTraceInformation = 0x1f,
		SystemObsolete0 = 0x20,
		SystemExceptionInformation = 0x21,
		SystemCrashDumpStateInformation = 0x22,
		SystemKernelDebuggerInformation = 0x23,
		SystemContextSwitchInformation = 0x24,
		SystemRegistryQuotaInformation = 0x25,
		SystemExtendServiceTableInformation = 0x26,
		SystemPrioritySeperation = 0x27,
		SystemVerifierAddDriverInformation = 0x28,
		SystemVerifierRemoveDriverInformation = 0x29,
		SystemProcessorIdleInformation = 0x2a,
		SystemLegacyDriverInformation = 0x2b,
		SystemCurrentTimeZoneInformation = 0x2c,
		SystemLookasideInformation = 0x2d,
		SystemTimeSlipNotification = 0x2e,
		SystemSessionCreate = 0x2f,
		SystemSessionDetach = 0x30,
		SystemSessionInformation = 0x31,
		SystemRangeStartInformation = 0x32,
		SystemVerifierInformation = 0x33,
		SystemVerifierThunkExtend = 0x34,
		SystemSessionProcessInformation = 0x35,
		SystemLoadGdiDriverInSystemSpace = 0x36,
		SystemNumaProcessorMap = 0x37,
		SystemPrefetcherInformation = 0x38,
		SystemExtendedProcessInformation = 0x39,
		SystemRecommendedSharedDataAlignment = 0x3a,
		SystemComPlusPackage = 0x3b,
		SystemNumaAvailableMemory = 0x3c,
		SystemProcessorPowerInformation = 0x3d,
		SystemEmulationBasicInformation = 0x3e,
		SystemEmulationProcessorInformation = 0x3f,
		SystemExtendedHandleInformation = 0x40,
		SystemLostDelayedWriteInformation = 0x41,
		SystemBigPoolInformation = 0x42,
		SystemSessionPoolTagInformation = 0x43,
		SystemSessionMappedViewInformation = 0x44,
		SystemHotpatchInformation = 0x45,
		SystemObjectSecurityMode = 0x46,
		SystemWatchdogTimerHandler = 0x47,
		SystemWatchdogTimerInformation = 0x48,
		SystemLogicalProcessorInformation = 0x49,
		SystemWow64SharedInformationObsolete = 0x4a,
		SystemRegisterFirmwareTableInformationHandler = 0x4b,
		SystemFirmwareTableInformation = 0x4c,
		SystemModuleInformationEx = 0x4d,
		SystemVerifierTriageInformation = 0x4e,
		SystemSuperfetchInformation = 0x4f,
		SystemMemoryListInformation = 0x50,
		SystemFileCacheInformationEx = 0x51,
		SystemThreadPriorityClientIdInformation = 0x52,
		SystemProcessorIdleCycleTimeInformation = 0x53,
		SystemVerifierCancellationInformation = 0x54,
		SystemProcessorPowerInformationEx = 0x55,
		SystemRefTraceInformation = 0x56,
		SystemSpecialPoolInformation = 0x57,
		SystemProcessIdInformation = 0x58,
		SystemErrorPortInformation = 0x59,
		SystemBootEnvironmentInformation = 0x5a,
		SystemHypervisorInformation = 0x5b,
		SystemVerifierInformationEx = 0x5c,
		SystemTimeZoneInformation = 0x5d,
		SystemImageFileExecutionOptionsInformation = 0x5e,
		SystemCoverageInformation = 0x5f,
		SystemPrefetchPatchInformation = 0x60,
		SystemVerifierFaultsInformation = 0x61,
		SystemSystemPartitionInformation = 0x62,
		SystemSystemDiskInformation = 0x63,
		SystemProcessorPerformanceDistribution = 0x64,
		SystemNumaProximityNodeInformation = 0x65,
		SystemDynamicTimeZoneInformation = 0x66,
		SystemCodeIntegrityInformation = 0x67,
		SystemProcessorMicrocodeUpdateInformation = 0x68,
		SystemProcessorBrandString = 0x69,
		SystemVirtualAddressInformation = 0x6a,
		SystemLogicalProcessorAndGroupInformation = 0x6b,
		SystemProcessorCycleTimeInformation = 0x6c,
		SystemStoreInformation = 0x6d,
		SystemRegistryAppendString = 0x6e,
		SystemAitSamplingValue = 0x6f,
		SystemVhdBootInformation = 0x70,
		SystemCpuQuotaInformation = 0x71,
		SystemNativeBasicInformation = 0x72,
		SystemErrorPortTimeouts = 0x73,
		SystemLowPriorityIoInformation = 0x74,
		SystemBootEntropyInformation = 0x75,
		SystemVerifierCountersInformation = 0x76,
		SystemPagedPoolInformationEx = 0x77,
		SystemSystemPtesInformationEx = 0x78,
		SystemNodeDistanceInformation = 0x79,
		SystemAcpiAuditInformation = 0x7a,
		SystemBasicPerformanceInformation = 0x7b,
		SystemQueryPerformanceCounterInformation = 0x7c,
		SystemSessionBigPoolInformation = 0x7d,
		SystemBootGraphicsInformation = 0x7e,
		SystemScrubPhysicalMemoryInformation = 0x7f,
		SystemBadPageInformation = 0x80,
		SystemProcessorProfileControlArea = 0x81,
		SystemCombinePhysicalMemoryInformation = 0x82,
		SystemEntropyInterruptTimingInformation = 0x83,
		SystemConsoleInformation = 0x84,
		SystemPlatformBinaryInformation = 0x85,
		SystemThrottleNotificationInformation = 0x86,
		SystemHypervisorProcessorCountInformation = 0x87,
		SystemDeviceDataInformation = 0x88,
		SystemDeviceDataEnumerationInformation = 0x89,
		SystemMemoryTopologyInformation = 0x8a,
		SystemMemoryChannelInformation = 0x8b,
		SystemBootLogoInformation = 0x8c,
		SystemProcessorPerformanceInformationEx = 0x8d,
		SystemSpare0 = 0x8e,
		SystemSecureBootPolicyInformation = 0x8f,
		SystemPageFileInformationEx = 0x90,
		SystemSecureBootInformation = 0x91,
		SystemEntropyInterruptTimingRawInformation = 0x92,
		SystemPortableWorkspaceEfiLauncherInformation = 0x93,
		SystemFullProcessInformation = 0x94,
		SystemKernelDebuggerInformationEx = 0x95,
		SystemBootMetadataInformation = 0x96,
		SystemSoftRebootInformation = 0x97,
		SystemElamCertificateInformation = 0x98,
		SystemOfflineDumpConfigInformation = 0x99,
		SystemProcessorFeaturesInformation = 0x9a,
		SystemRegistryReconciliationInformation = 0x9b,

		SystemKernelVaShadowInformation = 196,
		MaxSystemInfoClass = 0x9c,
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
		ULONG                  MaximumLength;//+0
		ULONG                  Length;//+4
		ULONG                  Flags;//+8
		ULONG                  DebugFlags;//+12
		ULONG                  ConsoleHandle;//+16
		ULONG                  ConsoleFlags;//+20
		ULONG                  StdInputHandle;//+24
		ULONG                  StdOutputHandle;//+28
		ULONG                  StdErrorHandle;//+32
		UNICODE_STRING32       CurrentDirectoryPath;// +36
		ULONG                  CurrentDirectoryHandle;//+44
		UNICODE_STRING32       DllPath;//+80, +48
		UNICODE_STRING32 ImagePathName;
		UNICODE_STRING32 CommandLine;
		//MORE
	} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define IMAGE_DOS_SIGNATURE                     0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                      0x00004550  // PE00

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC           0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC           0x20b

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16

	typedef struct _IMAGE_DOS_HEADER
	{
		USHORT e_magic;
		USHORT e_cblp;
		USHORT e_cp;
		USHORT e_crlc;
		USHORT e_cparhdr;
		USHORT e_minalloc;
		USHORT e_maxalloc;
		USHORT e_ss;
		USHORT e_sp;
		USHORT e_csum;
		USHORT e_ip;
		USHORT e_cs;
		USHORT e_lfarlc;
		USHORT e_ovno;
		USHORT e_res[4];
		USHORT e_oemid;
		USHORT e_oeminfo;
		USHORT e_res2[10];
		LONG e_lfanew;
	} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

	typedef struct _IMAGE_SECTION_HEADER
	{
		UCHAR  Name[8];
		union
		{
			ULONG PhysicalAddress;
			ULONG VirtualSize;
		} Misc;
		ULONG VirtualAddress;
		ULONG SizeOfRawData;
		ULONG PointerToRawData;
		ULONG PointerToRelocations;
		ULONG PointerToLinenumbers;
		USHORT  NumberOfRelocations;
		USHORT  NumberOfLinenumbers;
		ULONG Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

	typedef struct _IMAGE_FILE_HEADER // Size=20
	{
		USHORT Machine;
		USHORT NumberOfSections;
		ULONG TimeDateStamp;
		ULONG PointerToSymbolTable;
		ULONG NumberOfSymbols;
		USHORT SizeOfOptionalHeader;
		USHORT Characteristics;
	} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

	typedef struct _IMAGE_DATA_DIRECTORY
	{
		ULONG VirtualAddress;
		ULONG Size;
	} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

	typedef struct _IMAGE_OPTIONAL_HEADER64
	{
		USHORT Magic;
		UCHAR MajorLinkerVersion;
		UCHAR MinorLinkerVersion;
		ULONG SizeOfCode;
		ULONG SizeOfInitializedData;
		ULONG SizeOfUninitializedData;
		ULONG AddressOfEntryPoint;
		ULONG BaseOfCode;
		ULONGLONG ImageBase;
		ULONG SectionAlignment;
		ULONG FileAlignment;
		USHORT MajorOperatingSystemVersion;
		USHORT MinorOperatingSystemVersion;
		USHORT MajorImageVersion;
		USHORT MinorImageVersion;
		USHORT MajorSubsystemVersion;
		USHORT MinorSubsystemVersion;
		ULONG Win32VersionValue;
		ULONG SizeOfImage;
		ULONG SizeOfHeaders;
		ULONG CheckSum;
		USHORT Subsystem;
		USHORT DllCharacteristics;
		ULONGLONG SizeOfStackReserve;
		ULONGLONG SizeOfStackCommit;
		ULONGLONG SizeOfHeapReserve;
		ULONGLONG SizeOfHeapCommit;
		ULONG LoaderFlags;
		ULONG NumberOfRvaAndSizes;
		struct _IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

	typedef struct _IMAGE_OPTIONAL_HEADER32
	{
		//
		// Standard fields.
		//

		USHORT  Magic;
		UCHAR   MajorLinkerVersion;
		UCHAR   MinorLinkerVersion;
		ULONG   SizeOfCode;
		ULONG   SizeOfInitializedData;
		ULONG   SizeOfUninitializedData;
		ULONG   AddressOfEntryPoint;
		ULONG   BaseOfCode;
		ULONG   BaseOfData;

		//
		// NT additional fields.
		//

		ULONG   ImageBase;
		ULONG   SectionAlignment;
		ULONG   FileAlignment;
		USHORT  MajorOperatingSystemVersion;
		USHORT  MinorOperatingSystemVersion;
		USHORT  MajorImageVersion;
		USHORT  MinorImageVersion;
		USHORT  MajorSubsystemVersion;
		USHORT  MinorSubsystemVersion;
		ULONG   Win32VersionValue;
		ULONG   SizeOfImage;
		ULONG   SizeOfHeaders;
		ULONG   CheckSum;
		USHORT  Subsystem;
		USHORT  DllCharacteristics;
		ULONG   SizeOfStackReserve;
		ULONG   SizeOfStackCommit;
		ULONG   SizeOfHeapReserve;
		ULONG   SizeOfHeapCommit;
		ULONG   LoaderFlags;
		ULONG   NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

	typedef struct _IMAGE_NT_HEADERS64
	{
		ULONG Signature;
		struct _IMAGE_FILE_HEADER FileHeader;
		struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

	typedef struct _IMAGE_NT_HEADERS
	{
		ULONG Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	} IMAGE_NT_HEADERS;

	NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

	NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

	NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	typedef bool(*fnEnumSystemModuleCallback)(PRTL_PROCESS_MODULE_INFORMATION, void *);

	bool GetKernelInfo(PRTL_PROCESS_MODULE_INFORMATION pMod, PVOID checkPtr)
	{
		if (!g_NtosBase)
		{
			if (pMod->LoadOrderIndex == 0 || (checkPtr >= pMod->ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod->ImageBase + pMod->ImageSize)))
			{
				g_NtosBase = pMod->ImageBase;
				g_NtosEnd = (PUCHAR)pMod->ImageBase + pMod->ImageSize;

				return true;
			}
		}

		return false;
	}

	NTSTATUS EnumSystemModules(fnEnumSystemModuleCallback callback, PVOID Context)
	{
		ULONG cbBuffer = 0;
		PVOID pBuffer = NULL;
		NTSTATUS Status = STATUS_UNSUCCESSFUL;

		while (1)
		{
			cbBuffer += 0x40000;
			pBuffer = ExAllocatePoolWithTag(PagedPool, cbBuffer, 'nmsl');

			if (pBuffer == NULL)
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			Status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, cbBuffer, NULL);

			if (NT_SUCCESS(Status))
			{
				break;
			}

			ExFreePoolWithTag(pBuffer, 'nmsl');

			if (Status != STATUS_INFO_LENGTH_MISMATCH)
			{
				return Status;
			}
		}

		if (pBuffer == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;

		if (NT_SUCCESS(Status))
		{
			auto pMods = (PRTL_PROCESS_MODULES)pBuffer;

			for (ULONG i = 0; i < pMods->NumberOfModules; i++)
			{
				if (callback(&pMods->Modules[i], Context))
				{
					Status = STATUS_SUCCESS;
					break;
				}
			}
		}

		ExFreePoolWithTag(pBuffer, 'nmsl');

		return Status;
	}

	_Use_decl_annotations_ void *UtilGetSystemProcAddress(
		const wchar_t *proc_name) {
		PAGED_CODE();

		UNICODE_STRING proc_name_U = {};
		RtlInitUnicodeString(&proc_name_U, proc_name);
		return MmGetSystemRoutineAddress(&proc_name_U);
	}

	_Use_decl_annotations_ void *UtilMemMem(const void *search_base,
		SIZE_T search_size, const void *pattern,
		SIZE_T pattern_size) {
		if (pattern_size > search_size) {
			return nullptr;
		}
		auto base = static_cast<const char *>(search_base);
		for (SIZE_T i = 0; i <= search_size - pattern_size; i++) {
			if (RtlCompareMemory(pattern, &base[i], pattern_size) == pattern_size) {
				return const_cast<char *>(&base[i]);
			}
		}
		return nullptr;
	}

#define ULONG_TO_ULONG64(addr) ((ULONG64)addr & 0xFFFFFFFFull)
#define PVOID_TO_ULONG64(addr) (sizeof(addr) == 4 ? ULONG_TO_ULONG64(addr) : (ULONG64)addr)
	typedef BOOLEAN(*DisasmCallbackWalk)(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context, int depth);

	BOOLEAN DisasmRangesWalk(PVOID DisasmBase, SIZE_T DisasmSize, DisasmCallbackWalk callback, PVOID context, int depth)
	{
		BOOLEAN success = FALSE;

		KFLOATING_SAVE float_save = { 0 };
		auto status = KeSaveFloatingPointState(&float_save);
		if (NT_SUCCESS(status)) {

			csh handle = 0;
#ifdef _WIN64
			if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
#else
			if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
#endif
				cs_insn *insts = NULL;
				size_t count = 0;
				int instCount = 1;

				if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK)
				{
					PUCHAR pAddress = (PUCHAR)DisasmBase;

					do
					{
						const uint8_t *addr = (uint8_t *)pAddress;
						uint64_t vaddr = PVOID_TO_ULONG64(pAddress);
						size_t size = 15;

						if (insts) {
							cs_free(insts, count);
							insts = NULL;
						}
						count = cs_disasm(handle, addr, size, vaddr, 1, &insts);
						if (!count)
						{
							break;
						}
						SIZE_T instLen = insts[0].size;
						if (!instLen)
						{
							break;
						}

						if (callback(&insts[0], pAddress, instLen, instCount, context, depth))
						{
							success = TRUE;
							break;
						}

						pAddress += instLen;
						instCount++;
					} while (pAddress < (PUCHAR)DisasmBase + DisasmSize);
				}

				if (insts) {
					cs_free(insts, count);
					insts = NULL;
				}

				cs_close(&handle);
			}


			KeRestoreFloatingPointState(&float_save);
		}

		return success;
	}

	typedef struct
	{
		PVOID base;
		size_t max_insts;
		int max_depth;
		std::set<PVOID> code;
		std::set<PVOID> branches;

		PVOID lea_rcx_imm;
		PUCHAR lea_rcx_addr;
		PVOID pfn_ExAcquireResourceSharedLite;
		int call_ExAcquireResourceSharedLite_inst;
	}LocateExpFirmwareTableContext;

	BOOLEAN LocateExpFirmwareTable(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context, int depth)
	{
		LocateExpFirmwareTableContext *ctx = (LocateExpFirmwareTableContext *)context;

		if (ctx->code.size() > ctx->max_insts)
		{
			return TRUE;
		}

		if (ctx->code.find(pAddress) != ctx->code.end())
		{
			return TRUE;
		}
		else
		{
			ctx->code.emplace(pAddress);
		}

		//48 8D 0D C8 AE E6 FF                                lea     rcx, ExpFirmwareTableResource ; Resource
		if (inst->id == X86_INS_LEA && inst->detail->x86.op_count == 2
			&& inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_MEM
			&& inst->detail->x86.operands[0].reg == X86_REG_RCX && (x86_reg)inst->detail->x86.operands[1].mem.base == X86_REG_RIP)
		{
			ctx->lea_rcx_imm = (PVOID)(pAddress + instLen + (int)inst->detail->x86.operands[1].mem.disp);
			ctx->lea_rcx_addr = pAddress;
		}
		//48 8B 05 A9 AE E6 FF                                mov     rax, cs:ExpFirmwareTableProviderListHead
		//48 83 C0 E8                                         add     rax, 0FFFFFFFFFFFFFFE8h
		if (inst->id == X86_INS_MOV && inst->detail->x86.op_count == 2
			&& inst->detail->x86.operands[0].type == X86_OP_REG
			&& (inst->detail->x86.operands[0].reg == X86_REG_RCX || inst->detail->x86.operands[0].reg == X86_REG_RAX)
			&& inst->detail->x86.operands[1].type == X86_OP_MEM && inst->detail->x86.operands[1].mem.base == X86_REG_RIP)
		{
			if (ctx->call_ExAcquireResourceSharedLite_inst != -1 && instCount - ctx->call_ExAcquireResourceSharedLite_inst < 5)
			{
				g_ExpFirmwareTableProviderListHead = (PVOID)(pAddress + instLen + (int)inst->detail->x86.operands[1].mem.disp);
				return TRUE;
			}
		}
		if (instLen == 5 && pAddress[0] == 0xE8)
		{
			if (ctx->lea_rcx_addr && (int)(pAddress - ctx->lea_rcx_addr) < 20 && (int)(ctx->lea_rcx_addr - pAddress) < 20)
			{
				PVOID CallTarget = (PVOID)(pAddress + 5 + *(int *)(pAddress + 1));
				if (CallTarget == ctx->pfn_ExAcquireResourceSharedLite)
				{
					g_ExpFirmwareTableResource = ctx->lea_rcx_imm;
					ctx->call_ExAcquireResourceSharedLite_inst = instCount;
				}
			}
		}

		if ((inst->id == X86_INS_JMP || (inst->id >= X86_INS_JAE && inst->id <= X86_INS_JS)) && inst->detail->x86.op_count == 1 && inst->detail->x86.operands[0].type == X86_OP_IMM)
		{
			PVOID imm = (PVOID)inst->detail->x86.operands[0].imm;
			if (imm >= g_NtosBase && imm < g_NtosEnd)
			{
				auto foundbranch = ctx->branches.find(imm);
				if (foundbranch == ctx->branches.end())
				{
					ctx->branches.emplace(imm);
					if (depth + 1 < ctx->max_depth)
						DisasmRangesWalk(imm, 0x300, LocateExpFirmwareTable, ctx, depth + 1);
				}
			}

			if (inst->id == X86_INS_JMP)
			{
				return TRUE;
			}
		}

		if (inst->id == X86_INS_RET)
		{
			return TRUE;
		}

		if (instLen == 1 && inst->bytes[0] == 0xCC)
		{
			return TRUE;
		}

		return FALSE;
	}

	VOID RemoveSigs(PVOID FirmwareBuffer, ULONG FirmwareBufferLength, const char *Sig, size_t SigLength)
	{
		PUCHAR search_begin = (PUCHAR)FirmwareBuffer;
		SIZE_T search_size = FirmwareBufferLength;
		while (1)
		{
			auto find = UtilMemMem(search_begin, search_size, Sig, SigLength);
			if (!find)
				break;

			memset(find, '7', SigLength);
			search_begin = (PUCHAR)find + SigLength;
			search_size = (PUCHAR)FirmwareBuffer + FirmwareBufferLength - search_begin;
		}
	}

	PFNFTH g_OriginalFIRMHandler = NULL;

	NTSTATUS __cdecl MyFIRMHandler(
		_Inout_ PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo
	)
	{
		auto st = g_OriginalFIRMHandler(SystemFirmwareTableInfo);

		if (st == STATUS_SUCCESS && SystemFirmwareTableInfo->Action == 1)
		{
			RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMware", sizeof("VMware") - 1);
			RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "Virtual", sizeof("Virtual") - 1);
		}

		return st;
	}

	PFNFTH g_OriginalACPIHandler = NULL;

	NTSTATUS __cdecl MyACPIHandler(
		_Inout_ PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo
	)
	{
		auto st = g_OriginalACPIHandler(SystemFirmwareTableInfo);

		if (st == STATUS_SUCCESS && SystemFirmwareTableInfo->Action == 1)
		{
			RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMware", sizeof("VMware") - 1);
			RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMWARE", sizeof("VMWARE") - 1);
		}
		
		return st;
	}

	PFNFTH g_OriginalRSMBHandler = NULL;

	NTSTATUS __cdecl MyRSMBHandler(
		_Inout_ PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo
	)
	{
		auto st = g_OriginalRSMBHandler(SystemFirmwareTableInfo);

		if (st == STATUS_SUCCESS && SystemFirmwareTableInfo->Action == 1)
		{
			RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMware", sizeof("VMware") - 1);
			RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMWARE", sizeof("VMWARE") - 1);
		}

		return st;
	}

	_Use_decl_annotations_ static void DriverUnload(
		PDRIVER_OBJECT driver_object) {
		UNREFERENCED_PARAMETER(driver_object);
		PAGED_CODE();

		ExAcquireResourceExclusiveLite((PERESOURCE)g_ExpFirmwareTableResource, TRUE);

		PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE HandlerListCurrent = NULL;

		EX_FOR_EACH_IN_LIST(SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
			FirmwareTableProviderList,
			(PLIST_ENTRY)g_ExpFirmwareTableProviderListHead,
			HandlerListCurrent) {

			if (g_OriginalACPIHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'ACPI') {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ACPI found, node restored!\n");
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = g_OriginalACPIHandler;
			}

			if (g_OriginalRSMBHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'RSMB') {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "RSMB found, node restored!\n");
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = g_OriginalRSMBHandler;
			}

			if (g_OriginalFIRMHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'FIRM') {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "FIRM found, node restored!\n");
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = g_OriginalFIRMHandler;
			}
		}

		ExReleaseResourceLite((PERESOURCE)g_ExpFirmwareTableResource);
	}

	_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
		PUNICODE_STRING registry_path) {
		UNREFERENCED_PARAMETER(registry_path);
		PAGED_CODE();

		cs_driver_mm_init();

		PVOID checkPtr = UtilGetSystemProcAddress(L"NtOpenFile");

		EnumSystemModules(GetKernelInfo, checkPtr);

		if (!g_NtosBase) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ntos base not found!\n");
			return STATUS_UNSUCCESSFUL;
		}

		//use following code to locate ExpFirmwareTableResource & ExpFirmwareTableProviderListHead
		//PAGE
		//41 B8 41 52 46 54                                   mov     r8d, 'TFRA'     ; Tag
		auto NtHeader = RtlImageNtHeader(g_NtosBase);

		if (!NtHeader) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ntos ntheader not found!\n");
			return STATUS_UNSUCCESSFUL;
		}

		PIMAGE_SECTION_HEADER secheader = (PIMAGE_SECTION_HEADER)((PUCHAR)NtHeader + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader->FileHeader.SizeOfOptionalHeader);

		PUCHAR PAGEBase = NULL;
		SIZE_T PAGESize = 0;

		for (auto i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		{
			if (memcmp(secheader[i].Name, "PAGE\x0\x0\x0\x0", 8) == 0)
			{
				PAGEBase = (PUCHAR)g_NtosBase + secheader[i].VirtualAddress;
				PAGESize = max(secheader[i].SizeOfRawData, secheader[i].Misc.VirtualSize);
				break;
			}
		}

		if (!PAGEBase) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PAGE section not found!\n");
			return STATUS_UNSUCCESSFUL;
		}
		
		auto FindMovTag = UtilMemMem(PAGEBase, PAGESize, "\x41\xB8\x41\x52\x46\x54", sizeof("\x41\xB8\x41\x52\x46\x54") - 1);

		if (!FindMovTag) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "mov r8d, 'TFRA' sig not found!\n");
			return STATUS_UNSUCCESSFUL;
		}

		LocateExpFirmwareTableContext ctx;
		ctx.max_depth = 16;
		ctx.max_insts = 1000;
		ctx.base = (PUCHAR)FindMovTag + sizeof("\x41\xB8\x41\x52\x46\x54") - 1;
		ctx.lea_rcx_addr = NULL;
		ctx.lea_rcx_imm = NULL;
		ctx.pfn_ExAcquireResourceSharedLite = UtilGetSystemProcAddress(L"ExAcquireResourceSharedLite");
		ctx.call_ExAcquireResourceSharedLite_inst = -1;

		DisasmRangesWalk((PUCHAR)FindMovTag + sizeof("\x41\xB8\x41\x52\x46\x54") - 1, 0x300, LocateExpFirmwareTable, &ctx, 0);

		if (!g_ExpFirmwareTableResource) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExpFirmwareTableResource not found!\n");
			return STATUS_UNSUCCESSFUL;
		}

		if (!g_ExpFirmwareTableProviderListHead) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExpFirmwareTableProviderListHead not found!\n");
			return STATUS_UNSUCCESSFUL;
		}

		ExAcquireResourceExclusiveLite((PERESOURCE)g_ExpFirmwareTableResource, TRUE);

		PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE HandlerListCurrent = NULL;

		EX_FOR_EACH_IN_LIST(SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
			FirmwareTableProviderList,
			(PLIST_ENTRY)g_ExpFirmwareTableProviderListHead,
			HandlerListCurrent) {

			if (!g_OriginalACPIHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'ACPI') {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ACPI found, node manipulated!\n");
				g_OriginalACPIHandler = HandlerListCurrent->SystemFWHandler.FirmwareTableHandler;
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = MyACPIHandler;
			}

			if (!g_OriginalRSMBHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'RSMB') {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "RSMB found, node manipulated!\n");
				g_OriginalRSMBHandler = HandlerListCurrent->SystemFWHandler.FirmwareTableHandler;
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = MyRSMBHandler;
			}	
			
			if (!g_OriginalFIRMHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'FIRM') {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "FIRM found, node manipulated!\n");
				g_OriginalFIRMHandler = HandlerListCurrent->SystemFWHandler.FirmwareTableHandler;
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = MyFIRMHandler;
			}
		}

		ExReleaseResourceLite((PERESOURCE)g_ExpFirmwareTableResource);

		driver_object->DriverUnload = DriverUnload;
	
		return STATUS_SUCCESS;
	}
}