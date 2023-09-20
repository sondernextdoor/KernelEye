#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <iostream>


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


namespace api
{
	void* kernel_handle{};


	class utils
	{

	public:


		/* 
			Summary: 
			Compares two wstrings and determines if they're equal.

			Param "string": 
			First wstring.

			Param "to_compare":
			Second wstring.

			Param "case_insensitive":
			Boolean value that determines whether case should be ignored. Default value is true.

			Return value:
			Returns true if the wstrings are equal, else it returns false.
		*/


		static bool equal_string( std::wstring string, std::wstring to_compare, bool case_insensitive = true )
		{
			if ( string.size() != to_compare.size() )
			{
				return false;
			}

			if ( case_insensitive = true )
			{
				for ( int i = 0; i < string.size(); i++ )
				{
					string.at( i ) = std::tolower( string.at( i ) );
					to_compare.at( i ) = std::tolower( to_compare.at( i ) );
				}
			}

			return ( !string.compare( to_compare ) );
		}


		/* 
			Summary: 
			Determines if a value is a pointer.

			Param "value": 
			The value to be evaluated.

			Return value:
			Returns true if the value is a pointer of any type, else it returns false.
		*/


		template <typename T>
		static bool is_pointer( T value )
		{
			return std::wstring( typeid( T ).name() ).find( L"ptr" ) != std::wstring::npos;
		}


		
		static void call_driver( unsigned long ioctl_code, void* in_buffer, size_t in_size, void* out_buffer, size_t out_size )
		{

			if ( kernel_handle == INVALID_HANDLE_VALUE || kernel_handle == nullptr )
			{
				kernel_handle = CreateFileW( L"\\\\.\\kerneleye", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr );

				if ( kernel_handle == INVALID_HANDLE_VALUE )
				{
					return;
				}
			}

			unsigned long bytes_returned{};
			DeviceIoControl( kernel_handle, ioctl_code, in_buffer, in_size, out_buffer, out_size, &bytes_returned, nullptr );
		}
	};


	class memory
	{

	public:


		/* 
			Summary: 
			Allocate virtual memory within the calling process.

			Param "size": 
			Specifies the amount of memory to be allocated (e.g. 0x4 would allocate 4 bytes of memory).

			Param "address": 
			If there's a specific address that would be the preferable start location of the allocated memory, it can be passed in here.
			By default, it's nullptr, which means the OS will determine where in the process to allocate the memory.

			Param "allocation_type":
			This determines the type of memory allocation to make. By default, it's MEM_COMMIT | MEM_RESERVE, which ensures that the memory allocation will be contiguous.

			Param "protection":
			This determines the protection that will be applied to the allocated memory. By default, it's PAGE_READWRITE.
			If executable memory is required, PAGE_EXECUTE_READWRITE can be specified instead.


			Return value:
			Returns a void pointer to the start of the allocated memory. Returns nullptr if it fails.
		*/


		static void* allocate( size_t size, void* address = nullptr, unsigned long allocation_type = MEM_COMMIT | MEM_RESERVE, unsigned long protection = PAGE_READWRITE )
		{
			return VirtualAlloc( address, size, allocation_type, protection );
		}


		// Same as the non-ex version, except it takes a process handle as the first param. 
		// If the handle maps to a foreign process and it contains proper access rights, memory will be allocated within the foreign process.


		static void* allocate_ex( HANDLE process_handle, size_t size, void* address = nullptr, unsigned long allocation_type = MEM_COMMIT | MEM_RESERVE, unsigned long protection = PAGE_READWRITE )
		{
			return VirtualAllocEx( process_handle, address, size, allocation_type, protection );
		}


		/* 
			Summary: 
			Free previously allocated virtual memory within the calling process.

			Param "memory": 
			Specifies the starting address of previously allocated memory that's to be freed. 
			This must be the return value from a previous call to the allocate() function if MEM_RELEASE is specified as the free_type.

			Param "size": 
			Specifies the size of memory to be released. This must be set to 0 if MEM_RELEASE is specified as the free_type. The default value is 0.

			Param "free_type":
			This determines how the memory is freed. The default value is MEM_RELEASE, which will first decommit any commited pages, then release the memory back to the OS.

			Return value:
			Returns a boolean value. True if the memory was freed without issue, false otherwise. 
		*/


		static bool free( void* memory, size_t size = 0, unsigned long free_type = MEM_RELEASE )
		{
			return VirtualFree( memory, size, free_type );
		}


		// Same as the non-ex version, except it takes a process handle as the first param. 
		// If the handle maps to a foreign process and it contains proper access rights, the specified memory will be freed within the foreign process.


		static bool free_ex( HANDLE process_handle, void* memory, size_t size = 0, unsigned long free_type = MEM_RELEASE )
		{
			return VirtualFreeEx( process_handle, memory, size, free_type );
		}


		/* 
			Summary: 
			Modify the protection of the specified memory range. 

			Param "memory": 
			Specifies the starting address of the memory that's to have its protection changed. 

			Param "size": 
			Specifies the size/range of memory that's to have its protection changed.

			Param "new_protection":
			The desired protection that's to be applied to the memory (e.g. PAGE_READONLY).

			Param "old_protection":
			The protection the memory had before any modifications were made. 

			Return value:
			Returns a boolean value. True if the memory protection was modified without issue, false otherwise. 
		*/


		static bool protect( void* memory, size_t size, unsigned long new_protection, unsigned long* old_protection )
		{
			return VirtualProtect( memory, size, new_protection, old_protection );
		}


		// Same as the non-ex version, except it takes a process handle as the first param. 
		// If the handle maps to a foreign process and it contains proper access rights, the specified memory protection will be modified within the foreign process.


		static bool protect_ex( HANDLE process_handle, void* memory, size_t size, unsigned long new_protection, unsigned long* old_protection )
		{
			return VirtualProtectEx( process_handle, memory, size, new_protection, old_protection );
		}


		/* 
			Summary: 
			Queries the specified region of memory.

			Param "address": 
			Specifies the starting address of the memory that's to be queried. 

			Param "size": 
			Specifies the size/range of memory that's to be queried.

			Return value:
			Returns a MEMORY_BASIC_INFORMATION structure containing the data obtained from querying the memory. 
		*/


		static MEMORY_BASIC_INFORMATION query( void* address )
		{
			MEMORY_BASIC_INFORMATION mbi{};
			VirtualQuery( address, &mbi, sizeof( mbi ) );
			return mbi;
		}

	
		// Same as the non-ex version, except it takes a process handle as the first param. 
		// If the handle maps to a foreign process and it contains proper access rights, the specified memory will be queried within the foreign process.


		static MEMORY_BASIC_INFORMATION query_ex( HANDLE process_handle, void* address )
		{
			MEMORY_BASIC_INFORMATION mbi{};
			VirtualQueryEx( process_handle, address, &mbi, sizeof( mbi ) );
			return mbi;
		}


		/* 
			Summary: 
			Reads the data at the specified memory address.

			Param "process_handle": 
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_VM_READ / PROCESS_ALL_ACCESS).

			Param "address": 
			Specifies the starting address of memory to be read.

			Param "buffer": 
			A pointer to a pre-allocated buffer that will hold the read data.

			Param "size": 
			Specifies the size of the memory to be read.

			Param "bytes_read": 
			An optional pointer to a size_t that will receive the number of bytes that were read. The default value is nullptr.

			Return value:
			Returns a boolean value. True if the memory was read without issue, false otherwise. 
		*/


		static bool read( HANDLE process_handle, void* address, void* buffer, size_t size, size_t* bytes_read = nullptr )
		{
			return ReadProcessMemory( process_handle, address, buffer, size, bytes_read );
		}


		// Templated version of the read function. 
		// Allows for the return value to be the read data instead of passing a buffer in.


		template <typename T>
		static T read_t( HANDLE process_handle, void* address, size_t size = sizeof( T ), size_t* bytes_read = nullptr )
		{
			T buffer{};
			ReadProcessMemory( process_handle, address, reinterpret_cast<void*>( &buffer ), size, bytes_read );
			return buffer;
		}


		/* 
			Summary: 
			Writes the specified data at the specified memory address.

			Param "process_handle": 
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_VM_WRITE | PROCESS_VM_OPERATION / PROCESS_ALL_ACCESS).

			Param "address": 
			Specifies the starting address where the data will be written.

			Param "buffer": 
			A pointer to the data that's to be written.

			Param "size": 
			Specifies the size of the data to be written.

			Param "bytes_written": 
			An optional pointer to a size_t that will receive the number of bytes that were written. The default value is nullptr.

			Return value:
			Returns a boolean value. True if the memory was written without issue, false otherwise. 
		*/


		static bool write( HANDLE process_handle, void* address, void* buffer, size_t size, size_t* bytes_written = nullptr )
		{
			return WriteProcessMemory( process_handle, address, buffer, size, bytes_written );
		}


		// Templated version of the write function. 
		// Allows for the write data to be passed in as a variable of the desired type (or as a constant) instead of passing a buffer in.


		template <typename T>
		static bool write_t( HANDLE process_handle, void* address, T buffer, size_t size = sizeof( T ), size_t* bytes_written = nullptr )
		{
			return WriteProcessMemory( process_handle, address, reinterpret_cast<void*>( &buffer ), size, bytes_written );
		}


		class kernel
		{
		public:

			static void* allocate_ex( unsigned long process_id, size_t size, void* address = nullptr, unsigned long allocation_type = MEM_COMMIT | MEM_RESERVE, unsigned long protection = PAGE_READWRITE )
			{
				struct allocate_data
				{
					unsigned long process_id;
					size_t size;
					void* address;
					unsigned long allocation_type;
					unsigned long protection;
				};

				unsigned long bytes_returned{};
				allocate_data data{ process_id, size, address, allocation_type, protection };

				utils::call_driver( io_mem_allocate, &data, sizeof( data ), &data, sizeof( data ) );
				return data.address;
			}


			static void free_ex( unsigned long process_id, void* address, size_t size = 0, unsigned long free_type = MEM_RELEASE )
			{
				struct free_data
				{
					unsigned long process_id;
					void* address;
					size_t size;
					unsigned long free_type;
				};

				unsigned long bytes_returned{};
				free_data data{ process_id, address, size, free_type };

				utils::call_driver( io_mem_free, &data, sizeof( data ), &data, sizeof( data ) );
			}


			static void protect_ex( unsigned long process_id, void* address, size_t size, unsigned long new_protection, unsigned long* old_protection = nullptr )
			{
				struct protect_data
				{
					unsigned long process_id;
					void* address;
					size_t size;
					unsigned long new_protection;
					unsigned long* old_protection;
				};

				unsigned long bytes_returned{};
				protect_data data{ process_id, address, size, new_protection, old_protection };

				utils::call_driver( io_mem_protect, &data, sizeof( data ), &data, sizeof( data ) );
			}


			static MEMORY_BASIC_INFORMATION query_ex( unsigned long process_id, void* address, size_t size )
			{
				struct query_data
				{
					unsigned long process_id;
					void* address;
					size_t size;
					MEMORY_BASIC_INFORMATION mbi;
				};

				unsigned long bytes_returned{};
				query_data data{ process_id, address, size };

				utils::call_driver( io_mem_query, &data, sizeof( data ), &data, sizeof( data ) );
				return data.mbi;
			}


			static void read( unsigned long process_id, void* address, void* buffer, size_t size )
			{
				struct read_data
				{
					unsigned long process_id;
					void* address;
					void* buffer;
					size_t size;
				};

				unsigned long bytes_returned{};
				read_data data{ process_id, address, buffer, size };

				utils::call_driver( io_mem_read, &data, sizeof( data ), &data, sizeof( data ) );
			}


			template <typename T>
			static T read_t( unsigned long process_id, void* address, size_t size = sizeof( T ) )
			{
				struct read_data
				{
					unsigned long process_id;
					void* address;
					void* buffer;
					size_t size;
				};

				T buffer{};
				unsigned long bytes_returned{};
				read_data data{ process_id, address, &buffer, size };

				utils::call_driver( io_mem_read, &data, sizeof( data ), &data, sizeof( data ) );
				return *static_cast<T*>( data.buffer );
			}


			static void write( unsigned long process_id, void* address, void* buffer, size_t size )
			{
				struct write_data
				{
					unsigned long process_id;
					void* address;
					void* buffer;
					size_t size;
				};

				unsigned long bytes_returned{};
				write_data data{ process_id, address, buffer, size };

				utils::call_driver( io_mem_write, &data, sizeof( data ), &data, sizeof( data ) );
			}


			template <typename T>
			static void write_t( unsigned long process_id, void* address, T buffer, size_t size = sizeof( T ) )
			{
				struct write_data
				{
					unsigned long process_id;
					void* address;
					void* buffer;
					size_t size;
				};

				unsigned long bytes_returned{};
				write_data data{ process_id, address, &buffer, size };

				utils::call_driver( io_mem_write, &data, sizeof( data ), &data, sizeof( data ) );
			}
		};
	};


	class process
	{

	public:


		struct module_information
		{
			wchar_t name[256]{};
			size_t base_address{};
			size_t size{};
		};


		struct process_information
		{
			wchar_t name[256]{};
			unsigned long process_id{};
			size_t base_address{};
			size_t size{};
			PEB* peb_pointer{};
			PEB peb{};
			void* handle{};
		};


		/* 
			Summary: 
			Templated function that loops all active processes. Calls the supplied callback function for each process entry.

			Param "callback": 
			A function pointer that takes a PROCESSENTRY32W structure and returns a boolean value. 
			This function pointer will be called and supplied with a PROCESSENTRY32W for each active process on the system.
			If the callback function returns false, it'll keep looping, else if it returns true, it'll break.
		*/

		template <typename T = bool(*)( PROCESSENTRY32W )>
		static void enumerate_processes( T callback )
		{
			void* process_snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) };
			PROCESSENTRY32W process_entry{ sizeof( PROCESSENTRY32W ) };

			for 
			( 
				bool b_result{ false }; 
				b_result == false && Process32NextW( process_snapshot, &process_entry ); 
				b_result = callback( process_entry ) 
			) {}

			CloseHandle( process_snapshot );
		}

	
		/* 
			Summary: 
			Templated function that loops all loaded modules within a process. Calls the supplied callback function for each module entry.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

			Param "callback": 
			A function pointer that takes a MODULEENTRY32W structure and returns a boolean value. 
			This function pointer will be called and supplied with a MODULEENTRY32W for each loaded module within the specified process.
			If the callback function returns false, it'll keep looping, else if it returns true, it'll break.
		*/


		template <typename T = bool(*)( MODULEENTRY32W )>
		static void enumerate_modules( HANDLE process_handle, T callback )
		{
			void* module_snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( process_handle ) ) };
			MODULEENTRY32W module_entry{ sizeof( MODULEENTRY32W ) };

			for( 
				bool b_result{ false }; 
				b_result == false && Module32NextW( module_snapshot, &module_entry ); 
				b_result = callback( module_entry ) 
			) {}

			CloseHandle( module_snapshot );
		}

	
		/* 
			Summary: 
			Obtains the process id for the process specified by executable name.

			Param "process_name":
			Executable name of the desired process (e.g. "notepad.exe").

			Return value:
			Returns the process id of the desired process.
		*/


		static unsigned long get_process_id( std::wstring process_name )
		{
			unsigned long process_id{};

			auto callback{ [ process_name, &process_id ] ( PROCESSENTRY32W process_entry ) -> bool 
			{
				if ( utils::equal_string( process_name, process_entry.szExeFile ) )
				{
					process_id = process_entry.th32ProcessID;
					return true;
				}
			
				return false;
			}};

			enumerate_processes( callback );
			return process_id;
		}
	

		/* 
			Summary: 
			Obtains the base address for the process specified by handle.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

			Return value:
			Returns the base address of the desired process.
		*/


		static size_t get_base_address( HANDLE process_handle )
		{
			size_t base_address{};

			auto callback{ [ process_handle, &base_address ] ( MODULEENTRY32W module_entry ) -> bool 
			{
				base_address = reinterpret_cast<size_t>( module_entry.modBaseAddr );
				return true;
			}};

			enumerate_modules( process_handle, callback );
			return base_address;
		}


		/* 
			Summary: 
			Obtains the size of the process specified by handle.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

			Return value:
			Returns the size of the desired process.
		*/


		static size_t get_size( HANDLE process_handle )
		{
			size_t size{};

			auto callback{ [ process_handle, &size ] ( MODULEENTRY32W module_entry ) -> bool 
			{
				size = module_entry.modBaseSize;
				return true;
			}};

			enumerate_modules( process_handle, callback );
			return size;
		}


		/* 
			Summary: 
			Templated function to query the desired information about the specified process.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

			Param "process_info_class":
			An enum representing the type of information to query. Default value is ProcessBasicInformation.

			Return value:
			Returns the structure corresponding to the templated type. This type should be the structure corresponding to the info class passed in.
			E.g. MEMORY_BASIC_INFORMATION for MemoryBasicInformation.
		*/


		template <typename T = PROCESS_BASIC_INFORMATION>
		static T query_process( HANDLE process_handle, _PROCESSINFOCLASS process_info_class = ProcessBasicInformation )
		{
			long ( __stdcall *NtQueryInformationProcess ) ( HANDLE, _PROCESSINFOCLASS, void*, unsigned long, unsigned long* );

			NtQueryInformationProcess = reinterpret_cast< long ( __stdcall* ) ( HANDLE, _PROCESSINFOCLASS, void*, unsigned long, unsigned long* ) >( 
				GetProcAddress( LoadLibraryW( L"ntdll.dll" ), "NtQueryInformationProcess" ) 
			);

			T buffer{};
			NtQueryInformationProcess( process_handle, process_info_class, &buffer, sizeof( T ), nullptr );
			return buffer;
		}


		/* 
			Summary: 
			Retrieves the PEB address of the specific process.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

			Return value:
			Returns the PEB address of the specified process.
		*/


		static size_t get_peb_address( HANDLE process_handle )
		{
			return reinterpret_cast<size_t>( query_process( process_handle ).PebBaseAddress );
		}


		/* 
			Summary: 
			Retrieves the PEB structure of the specific process.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION | PROCESS_WM_READ / PROCESS_ALL_ACCESS).

			Return value:
			Returns the PEB structure of the specified process.
		*/


		static PEB get_peb( HANDLE process_handle )
		{
			size_t peb_pointer{ get_peb_address( process_handle ) };

			if ( peb_pointer == 0 )
			{
				return {};
			}

			return memory::read_t<PEB>( process_handle, reinterpret_cast<PEB*>( peb_pointer ) );
		}


		/* 
			Summary: 
			Obtains a HANDLE for the process specified by process id.

			Param "process_id":
			A valid process id of a process, foreign or local.

			Param "desired_access":
			The desired access rights that the handle will possess if granted (e.g. PROCESS_ALL_ACCESS). Default value is MAXIMUM_ALLOWED.

			Param "inheritable":
			A boolean value specifying whether the handle can be inherited. Default value is false.


			Return value:
			If successful, returns a HANDLE to the process with the desired access rights (or the maximum allowed). Returns INVALID_HANDLE_VALUE if unsuccessful.
		*/


		static HANDLE get_handle( unsigned long process_id, unsigned long desired_access = MAXIMUM_ALLOWED, bool inheritable = false )
		{
			return OpenProcess( desired_access, inheritable, process_id );
		}


		/* 
			Summary: 
			Obtains a loaded module specified by name.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

			Param "module_name":
			The name of the desired module (e.g. "kernel32.dll").

			Return value:
			If successful, returns a module_information structure containing the desired module data. Returns an empty structure if unsucessful.
		*/


		static module_information get_module( HANDLE process_handle, std::wstring module_name )
		{
			module_information module_info{};

			auto callback{ [ process_handle, module_name, &module_info ] ( MODULEENTRY32W module_entry ) -> bool 
			{
				if ( utils::equal_string( module_name, module_entry.szModule ) )
				{
					module_info.base_address = reinterpret_cast<size_t>( module_entry.modBaseAddr );
					module_info.size = module_entry.modBaseSize;
					wcscpy_s( module_info.name, module_entry.szModule );

					return true;
				}

				return false;
			}};

			enumerate_modules( process_handle, callback );
			return module_info;
		}


		/* 
			Summary: 
			Obtains a module_information vector containing all loaded modules within the specified process.

			Param "process_handle":
			A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

			Return value:
			If successful, returns a module_information vector containing all loaded modules. Returns an empty vector if unsucessful.
		*/


		static std::vector <module_information> get_module_list( HANDLE process_handle )
		{
			std::vector <module_information> module_list{};

			auto callback{ [ process_handle, &module_list ] ( MODULEENTRY32W module_entry ) -> bool 
			{
				module_information module_info{};

				module_info.base_address = reinterpret_cast<size_t>( module_entry.modBaseAddr );
				module_info.size = module_entry.modBaseSize;
				wcscpy_s( module_info.name, module_entry.szModule );

				module_list.push_back( module_info );
				return false;
			}};

			enumerate_modules( process_handle, callback );
			return module_list;
		}


		/* 
			Summary: 
			Obtains a process_information list describing each active process on the system.

			Return value:
			Returns a vector containing filled process_information structures corresponding to each active process on the system.
		*/
		

		static std::vector<process_information> get_process_list()
		{
			std::vector<process_information> process_list{};

			auto callback{ [ &process_list ] ( PROCESSENTRY32 process ) -> bool 
			{
				process_information process_info{};

				std::wstring( process.szExeFile ).copy( process_info.name, 256 );
				process_info.process_id = process.th32ProcessID;
				process_info.handle = get_handle( process_info.process_id );

				process_list.push_back( process_info );
				return false;
			}};

			enumerate_processes( callback );
			return process_list;
		}


		/* 
			Summary: 
			Obtains various information about a process specified by name.

			Param "process_name":
			The name of the desired process (e.g. "notepad.exe").

			Return value:
			If successful, returns a filled process_information structure. Returns an empty structure if unsucessful.
		*/


		static process_information get_process( std::wstring process_name )
		{
			process_information process_info{};

			auto callback{ [ & ] ( PROCESSENTRY32W process_entry ) -> bool 
			{
				if ( utils::equal_string( process_name, process_entry.szExeFile ) )
				{
					std::wstring( process_entry.szExeFile ).copy( process_info.name, 256 );
					process_info.process_id = process_entry.th32ProcessID;
					process_info.handle = get_handle( process_info.process_id );

					return true;
				}
			
				return false;
			}};

			enumerate_processes( callback );
			return process_info;
		}


		class kernel
		{
		public:


			static size_t get_base_address( unsigned long process_id )
			{
				struct base_data
				{
					unsigned long process_id{};
					size_t base_address{};
				};

				unsigned long bytes_returned;
				base_data data{ process_id };

				utils::call_driver( io_proc_base, &data, sizeof( data ), &data, sizeof( data ) );
				return data.base_address;
			}


			/* 
				Summary: 
				Obtains the size of the process specified by handle.

				Param "process_handle":
				A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

				Return value:
				Returns the size of the desired process.
			*/


			static size_t get_size( unsigned long process_id )
			{
				struct size_data
				{
					unsigned long process_id{};
					size_t size{};
				};
				
				size_data data{ process_id };

				utils::call_driver( io_proc_size, &data, sizeof( data ), &data, sizeof( data ) );
				return data.size;
			}


			/* 
				Summary: 
				Templated function to query the desired information about the specified process.

				Param "process_handle":
				A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

				Param "process_info_class":
				An enum representing the type of information to query. Default value is ProcessBasicInformation.

				Return value:
				Returns the structure corresponding to the templated type. This type should be the structure corresponding to the info class passed in.
				E.g. MEMORY_BASIC_INFORMATION for MemoryBasicInformation.
			*/


			template <typename T = PROCESS_BASIC_INFORMATION>
			static T query( unsigned long process_id, _PROCESSINFOCLASS process_info_class = ProcessBasicInformation )
			{
				struct query_data
				{
					unsigned long process_id{};
					_PROCESSINFOCLASS process_info_class{};
					size_t size{};
					void* buffer{};
				};

				T buffer{};
				query_data data{ process_id, process_info_class, sizeof( T ), &buffer };

				utils::call_driver( io_proc_query, &data, sizeof( data ), &data, sizeof( data ) );
				return data.buffer;
			}


			/* 
				Summary: 
				Retrieves the PEB address of the specific process.

				Param "process_handle":
				A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION / PROCESS_ALL_ACCESS).

				Return value:
				Returns the PEB address of the specified process.
			*/


			static size_t get_peb_address( unsigned long process_id )
			{
				struct peb_data
				{
					unsigned long process_id{};
					size_t peb_address{};
				};
				
				peb_data data{ process_id };

				utils::call_driver( io_proc_peb, &data, sizeof( data ), &data, sizeof( data ) );
				return data.peb_address;
			}


			/* 
				Summary: 
				Retrieves the PEB structure of the specific process.

				Param "process_handle":
				A valid HANDLE to a process, foreign or local, that contains valid access rights (PROCESS_QUERY_INFORMATION | PROCESS_WM_READ / PROCESS_ALL_ACCESS).

				Return value:
				Returns the PEB structure of the specified process.
			*/


			static PEB get_peb( unsigned long process_id )
			{
				size_t peb_address{ get_peb_address( process_id ) };

				if ( peb_address == 0 )
				{
					return {};
				}

				return memory::kernel::read_t<PEB>( process_id, reinterpret_cast<PEB*>( peb_address ) );
			}


			static module_information get_module( unsigned long process_id, std::wstring module_name )
			{
				struct module_data 
				{
					unsigned long process_id;
					wchar_t* module_name;
					module_information module_info;
				};

				module_data data{ process_id, const_cast<wchar_t*>( module_name.c_str() ) };

				utils::call_driver( io_proc_module, &data, sizeof( data ), &data, sizeof( data ) );
				return data.module_info;
			}
		};
	};


	class thread
	{

	public:


		void* thread_handle{};
		unsigned long thread_id{};
		bool b_joinable{ true };


		thread( void* thread_routine, void* parameters = nullptr, bool b_detach = false, bool thread_ex = false, HANDLE process_handle = nullptr)
		{
			if ( thread_ex == false )
			{
				thread_handle = CreateThread( nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>( thread_routine ), parameters, 0, &thread_id );
			}
			else
			{
				thread_handle = CreateRemoteThread( process_handle, nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>( thread_routine ), parameters, 0, &thread_id );
			}


			if ( b_detach == true ) { detach(); }
		}


		static thread create( void* thread_routine, void* parameters = nullptr, bool b_detach = false )
		{
			return thread( thread_routine, parameters, b_detach );
		}


		static thread create_ex( HANDLE process_handle, void* thread_routine, void* parameters = nullptr, bool b_detach = false )
		{
			return thread( thread_routine, parameters, b_detach, true, process_handle );
		}


		void join()
		{
			if ( b_joinable == false ) { return; }

			b_joinable = false;
			WaitForSingleObject( thread_handle, INFINITE );
		}


		void detach()
		{
			if ( b_joinable == false ) { return; }

			b_joinable = false;
			thread_handle = nullptr;
			thread_id = 0;
		}


		void* native_handle()
		{
			return thread_handle;
		}
		

		unsigned long get_id()
		{
			return thread_id;
		}


		bool joinable()
		{
			return b_joinable;
		}


		~thread() 
		{ 
			if ( b_joinable == true )
			{
				throw;
			}
				
			TerminateThread( thread_handle, 0 );
			CloseHandle( thread_handle );
		}
	};
};