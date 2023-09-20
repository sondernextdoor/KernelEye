#pragma once
#include "k-structs.h"

namespace api
{
	class process
	{

	public:


		template <typename T = bool(*)( LDR_DATA_TABLE_ENTRY, wchar_t* )>
		static void enumerate_modules( PEPROCESS eprocess, T callback )
		{
			size_t return_bytes{};
			PEB peb{};
			PEB_LDR_DATA ldr{};
			LDR_DATA_TABLE_ENTRY module_entry{};

			if ( NT_SUCCESS( MmCopyVirtualMemory( eprocess, 
											      PsGetProcessPeb( eprocess ), 
											      IoGetCurrentProcess(),
											      &peb, 
											      sizeof( peb ),
											      KernelMode, 
											      &return_bytes )) && peb.Ldr )
			{
				if ( NT_SUCCESS( MmCopyVirtualMemory( eprocess, 
												      peb.Ldr, 
												      IoGetCurrentProcess(), 
												      &ldr, 
												      sizeof( PEB_LDR_DATA ), 
												      KernelMode, 
												      &return_bytes )) && ldr.InMemoryOrderModuleList.Flink )
				{ 
					auto list_head{ ldr.InMemoryOrderModuleList.Flink };
					auto next_entry{ list_head };

					do 
					{
						if ( NT_SUCCESS( MmCopyVirtualMemory( eprocess, 
														      CONTAINING_RECORD( list_head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks ), 
														      IoGetCurrentProcess(), 
														      &module_entry, 
														      sizeof( module_entry ), 
														      KernelMode, 
														      &return_bytes )) && module_entry.DllBase )
						{
							wchar_t current_module_name[256]{};

							if ( NT_SUCCESS( MmCopyVirtualMemory( eprocess, 
															      module_entry.BaseDllName.Buffer, 
															      IoGetCurrentProcess(), 
															      current_module_name, 
															      module_entry.BaseDllName.Length, 
															      KernelMode, 
															      &return_bytes )))
							{
								if ( callback( module_entry, current_module_name ) ) 
								{
									return;
								} 
							}
						}

						list_head = module_entry.InMemoryOrderLinks.Flink;

					} while ( list_head != next_entry );
				}
			}
		}


		static PEPROCESS get_eprocess( unsigned long process_id )
		{
			PEPROCESS eprocess{};
			PsLookupProcessByProcessId( reinterpret_cast<HANDLE>( process_id ), &eprocess );
			return eprocess;
		}


		static size_t get_base_address( unsigned long process_id )
		{
			size_t base_address{};
			PEPROCESS eprocess{ get_eprocess( process_id ) };

			if ( eprocess == nullptr )
			{
				return 0;
			}

			base_address = reinterpret_cast<size_t>( PsGetProcessSectionBaseAddress( eprocess ) );

			ObfDereferenceObject( eprocess );
			return base_address;
		}


		static size_t get_size( unsigned long process_id )
		{
			size_t size{};

			auto callback{ [&size] ( LDR_DATA_TABLE_ENTRY module_entry, wchar_t* module_name ) 
			{
				size = module_entry.SizeOfImage;
				return true;
			}};

			PEPROCESS eprocess{ get_eprocess( process_id ) };

			if ( eprocess == nullptr )
			{
				return 0;
			}

			enumerate_modules( eprocess, callback );
			ObfDereferenceObject( eprocess );

			return size;
		}


		static long query( unsigned long process_id, _PROCESSINFOCLASS process_info_class, void* buffer, size_t size )
		{
			long status{};
			KAPC_STATE apc{};
			PEPROCESS eprocess{ get_eprocess( process_id ) };

			if ( eprocess == nullptr )
			{
				return 0;
			}
			
			KeStackAttachProcess( eprocess, &apc );
			status = ZwQueryInformationProcess( ZwCurrentProcess(), process_info_class, buffer, size, nullptr );
			KeUnstackDetachProcess( &apc );

			ObfDereferenceObject( eprocess );
			return status;
		}


		static size_t get_peb( unsigned long process_id )
		{
			PEPROCESS eprocess{ get_eprocess( process_id ) };

			if ( eprocess == nullptr )
			{
				return 0;
			}

			return reinterpret_cast<size_t>( PsGetProcessPeb( eprocess ) );
		}


		static module_information get_module( unsigned long process_id, wchar_t* module_name )
		{
			module_information module_info{};
			PEPROCESS eprocess{ get_eprocess( process_id ) };

			if ( eprocess == nullptr )
			{
				return {};
			}

			auto callback{ [module_name, eprocess, &module_info] ( LDR_DATA_TABLE_ENTRY module_entry, wchar_t* current_module_name ) 
			{
				if ( !_wcsicmp( module_name, current_module_name ) )
				{
					size_t return_bytes{};

					module_info.base_address = reinterpret_cast<size_t>( module_entry.DllBase );
					module_info.size = module_entry.SizeOfImage;
					
					MmCopyVirtualMemory( eprocess, 
										 module_entry.BaseDllName.Buffer, 
										 IoGetCurrentProcess(), 
										 module_info.name, 
										 module_entry.BaseDllName.Length, 
										 KernelMode, 
										 &return_bytes );

					return true;
				}

				return false;
			}};

			enumerate_modules( eprocess, callback );
			return module_info;
		}
	};


	class memory
	{

	public:


		static long read( unsigned long process_id, void* address, void* buffer, size_t size ) 
		{
			size_t return_length{};
			long status{};
			PEPROCESS eprocess{ process::get_eprocess( process_id ) };

			if ( eprocess == nullptr ) 
			{
				return STATUS_UNSUCCESSFUL;
			}

			status = MmCopyVirtualMemory( eprocess, 
										  address, 
										  IoGetCurrentProcess(), 
										  buffer, 
										  size, 
										  UserMode, 
										  &return_length );
			
			ObfDereferenceObject( eprocess );
			return status;
		}


		static long write( unsigned long process_id, void* address, void* buffer, size_t size ) 
		{
			size_t return_length{};
			long status{};
			PEPROCESS eprocess{ process::get_eprocess( process_id ) };

			if ( eprocess == nullptr ) 
			{
				return STATUS_UNSUCCESSFUL;
			}

			status = MmCopyVirtualMemory( IoGetCurrentProcess(), 
										  buffer, 
										  eprocess, 
										  address, 
										  size, 
										  UserMode, 
										  &return_length );
			
			ObfDereferenceObject( eprocess );
			return status;
		}


		static long allocate( unsigned long process_id, void** address, size_t size, unsigned long allocation_type, unsigned long protection ) 
		{
			long status{};
			KAPC_STATE apc{};
			PEPROCESS eprocess{ process::get_eprocess( process_id ) };

			if ( eprocess == nullptr ) 
			{
				return STATUS_UNSUCCESSFUL;
			}

			KeStackAttachProcess( eprocess, &apc );

			status = ZwAllocateVirtualMemory( ZwCurrentProcess(), 
											  address, 
											  0, 
											  &size,
											  allocation_type,
											  protection );

			KeUnstackDetachProcess( &apc );
			ObfDereferenceObject( eprocess );

			return status;
		}


		static long free( unsigned long process_id, void** address, size_t size, unsigned long free_type ) 
		{
			long status{};
			KAPC_STATE apc{};
			PEPROCESS eprocess{ process::get_eprocess( process_id ) };

			if ( eprocess == nullptr ) 
			{
				return STATUS_UNSUCCESSFUL;
			}

			KeStackAttachProcess( eprocess, &apc );

			status = ZwFreeVirtualMemory( ZwCurrentProcess(), 
										  address, 
										  &size,
										  free_type );

			KeUnstackDetachProcess( &apc );
			ObfDereferenceObject( eprocess );

			return status;
		}


		static long protect( unsigned long process_id, void** address, size_t size, unsigned long new_protection, unsigned long* old_protection ) 
		{
			long status{};
			KAPC_STATE apc{};
			PEPROCESS eprocess{ process::get_eprocess( process_id ) };

			if ( eprocess == nullptr ) 
			{
				return STATUS_UNSUCCESSFUL;
			}

			KeStackAttachProcess( eprocess, &apc );

			status = ZwProtectVirtualMemory( ZwCurrentProcess(), 
											 address,  
											 &size,
											 new_protection,
											 old_protection );

			KeUnstackDetachProcess( &apc );
			ObfDereferenceObject( eprocess );

			return status;
		}


		static long query( unsigned long process_id, void* address, void* buffer, size_t size ) 
		{
			size_t return_length{};
			long status{};
			KAPC_STATE apc{};
			PEPROCESS eprocess{ process::get_eprocess( process_id ) };

			if ( eprocess == nullptr ) 
			{
				return STATUS_UNSUCCESSFUL;
			}

			KeStackAttachProcess( eprocess, &apc );

			status = ZwQueryVirtualMemory( ZwCurrentProcess(), 
										   address,
										   MemoryBasicInformation, 
										   buffer, 
										   size,
										   &return_length );

			KeUnstackDetachProcess( &apc );
			ObfDereferenceObject( eprocess );

			return status;
		}
	};


	class driver
	{

	public:


		static DEVICE_OBJECT* create_device( DRIVER_OBJECT* driver_object, const wchar_t* device_name, const wchar_t* symbolic_link_name, long& out_status )
		{
			DEVICE_OBJECT* device_object{};
			UNICODE_STRING us_device_name{};
			UNICODE_STRING us_symbolic_link_name{};

			RtlInitUnicodeString( &us_device_name, device_name );
			RtlInitUnicodeString( &us_symbolic_link_name, symbolic_link_name );

			if ( NT_SUCCESS( out_status = IoCreateDevice( driver_object, 
													  0, 
													  &us_device_name, 
													  FILE_DEVICE_UNKNOWN, 
													  FILE_DEVICE_SECURE_OPEN, 
													  false, 
													  &device_object )))
			{
		
				device_object->Flags |= DO_DIRECT_IO;
				device_object->Flags &= ~DO_DEVICE_INITIALIZING;

				out_status = IoCreateSymbolicLink( &us_symbolic_link_name, &us_device_name );
			}

			return device_object;
		}
	

		static long io_completion( DEVICE_OBJECT* device_object, PIRP irp )
		{
			UNREFERENCED_PARAMETER(device_object);

			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;

			IoCompleteRequest( irp, IO_NO_INCREMENT );
			return STATUS_SUCCESS;
		}


		static long io_control( DEVICE_OBJECT* device_object, IRP* irp ) 
		{
			UNREFERENCED_PARAMETER( device_object );


			long status{ STATUS_UNSUCCESSFUL };
			IO_STACK_LOCATION* stack{ IoGetCurrentIrpStackLocation( irp ) };
			void* io_buffer{ irp->AssociatedIrp.SystemBuffer };


			switch ( stack->Parameters.DeviceIoControl.IoControlCode ) 
			{
				case io_mem_allocate: 
				{
					mem_allocate_data* data{ static_cast<mem_allocate_data*>( io_buffer ) };

					if ( data != nullptr )
					{
						memory::allocate( data->process_id, &data->address, data->size, data->allocation_type, data->protection );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_mem_free: 
				{
					mem_free_data* data{ static_cast<mem_free_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						memory::free( data->process_id, &data->address, data->size, data->free_type );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_mem_protect: 
				{
					mem_protect_data* data{ static_cast<mem_protect_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						memory::protect( data->process_id, &data->address, data->size, data->new_protection, data->old_protection );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_mem_query: 
				{
					mem_query_data* data{ static_cast<mem_query_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						memory::query( data->process_id, data->address, &data->mbi, data->size );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_mem_read: 
				{
					mem_copy_data* data{ static_cast<mem_copy_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						memory::read( data->process_id, data->address, data->buffer, data->size );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_mem_write: 
				{
					mem_copy_data* data{ static_cast<mem_copy_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						memory::write( data->process_id, data->address, data->buffer, data->size );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_proc_base: 
				{
					proc_base_data* data{ static_cast<proc_base_data*>( io_buffer ) };

					if ( data != nullptr )
					{
						data->base_address = process::get_base_address( data->process_id );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_proc_size: 
				{
					proc_size_data* data{ static_cast<proc_size_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						data->size = process::get_size( data->process_id );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_proc_query: 
				{
					proc_query_data* data{ static_cast<proc_query_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						process::query( data->process_id, data->process_info_class, data->buffer, data->size );
						status = STATUS_SUCCESS;
					}

				} break;


				case io_proc_peb: 
				{
					proc_peb_data* data{ static_cast<proc_peb_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						data->peb_address = process::get_peb( data->process_id );
						status = STATUS_SUCCESS;
					}

				} break;
		

				case io_proc_module: 
				{
					proc_module_data* data{ static_cast<proc_module_data*>( irp->AssociatedIrp.SystemBuffer ) };

					if ( data != nullptr )
					{
						data->module_info = process::get_module( data->process_id, data->module_name );
						status = STATUS_SUCCESS;
					}

				} break;


				default: { status = STATUS_INVALID_PARAMETER; } break;
			}


			irp->IoStatus.Information = status == STATUS_SUCCESS ? stack->Parameters.DeviceIoControl.OutputBufferLength : 0;
			irp->IoStatus.Status = status;
			IoCompleteRequest( irp, IO_NO_INCREMENT );


			return status;
		}


		static void unload( DRIVER_OBJECT* driver_object )
		{
			UNICODE_STRING us_symbolic_link_name{};
			RtlInitUnicodeString( &us_symbolic_link_name, L"\\DosDevices\\kerneleye" );

			IoDeleteSymbolicLink( &us_symbolic_link_name );
			IoDeleteDevice( driver_object->DeviceObject );
		}
	};
}