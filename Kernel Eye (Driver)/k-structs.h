#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>


#define io_mem_allocate CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_mem_free CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_mem_protect CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_mem_query CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_mem_read CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_mem_write CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_proc_base CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_proc_size CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_proc_query CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_proc_peb CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02D0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define io_proc_module CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02D1, METHOD_BUFFERED, FILE_ANY_ACCESS)


struct module_information
{
	wchar_t name[256]{};
	size_t base_address{};
	size_t size{};
};

struct mem_allocate_data
{
	unsigned long process_id{};
	size_t size{};
	void* address{};
	unsigned long allocation_type{};
	unsigned long protection{};
};


struct mem_free_data
{
	unsigned long process_id{};
	void* address{};
	size_t size{};
	unsigned long free_type{};
};


struct mem_protect_data
{
	unsigned long process_id{};
	void* address{};
	size_t size{};
	unsigned long new_protection{};
	unsigned long* old_protection{};
};


struct mem_query_data
{
	unsigned long process_id{};
	void* address{};
	size_t size{};
	MEMORY_BASIC_INFORMATION mbi{};
};


struct mem_copy_data
{
	unsigned long process_id{};
	void* address{};
	void* buffer{};
	size_t size{};
};


struct proc_base_data
{
	unsigned long process_id{};
	size_t base_address{};
};


struct proc_size_data
{
	unsigned long process_id{};
	size_t size{};
};


struct proc_query_data
{
	unsigned long process_id{};
	_PROCESSINFOCLASS process_info_class{};
	size_t size{};
	void* buffer{};
};	


struct proc_peb_data
{
	unsigned long process_id{};
	size_t peb_address{};
};


struct proc_module_data 
{
	unsigned long process_id{};
	wchar_t* module_name{};
	module_information module_info{};
};


typedef enum _SYSTEM_INFORMATION_CLASS 
	{
		SystemBasicInformation,
		SystemProcessorInformation,
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation,
		SystemProcessInformation,
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,
		SystemModuleInformation,
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation,
		SystemNonPagedPoolInformation,
		SystemHandleInformation,
		SystemObjectInformation,
		SystemPageFileInformation,
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,
		SystemFileCacheInformation,
		SystemPoolTagInformation,
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemNextEventIdInformation,
		SystemEventIdsInformation,
		SystemCrashDumpInformation,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,
		SystemPrioritySeperation,
		SystemPlugPlayBusInformation,
		SystemDockInformation,
		SystemProcessorSpeedInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation,
		SystemExtendedProcessInformation = 57
	} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
#ifdef _WIN64
	ULONG Reserved[4];
#endif
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress;
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef struct _PEB_LDR_DATA 
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _LDR_DATA_TABLE_ENTRY 
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB 
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;


typedef struct _SYSTEM_MODULE 
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;


typedef struct _SYSTEM_MODULE_INFORMATION 
{
	ULONG NumberOfModules;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;


typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


extern "C" 
{
	NTKERNELAPI
	PVOID
	PsGetProcessSectionBaseAddress(
		PEPROCESS Process
	);

	NTKERNELAPI
	PPEB
	PsGetProcessPeb(
		PEPROCESS Process
	);

	NTKERNELAPI
	NTSTATUS
	MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TarGet,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	NTSYSCALLAPI 
	NTSTATUS 
	NTAPI 
	ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID Buffer, 
		ULONG Length,
		PULONG ReturnLength
	);

	NTSYSCALLAPI
	NTSTATUS 
	ZwQueryInformationProcess(
		HANDLE ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
	);

	NTSYSCALLAPI 
	NTSTATUS 
	NTAPI 
	ZwProtectVirtualMemory(
		HANDLE ProcessHandle, 
		PVOID *BaseAddress, 
		PSIZE_T RegionSize,
		ULONG NewAccessProtection, 
		PULONG OldAccessProtection
	);

	NTKERNELAPI 
	NTSTATUS 
	IoCreateDriver(
		PUNICODE_STRING DriverName, 
		PDRIVER_INITIALIZE InitializationFunction
	);
}