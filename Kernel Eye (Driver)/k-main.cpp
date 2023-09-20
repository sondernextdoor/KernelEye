#include "k-api.h"

using api::driver;
bool b_map_driver{ false };

long driver_entry(DRIVER_OBJECT* driver_object, UNICODE_STRING* registry_path )
{
	long status{};

	if ( b_map_driver == true )
	{
		b_map_driver = false;
		return IoCreateDriver( nullptr, &driver_entry );
	}

	DEVICE_OBJECT* device_object{ driver::create_device( driver_object, L"\\Device\\kerneleye", L"\\DosDevices\\kerneleye", status ) };

	if ( status != STATUS_SUCCESS || device_object == nullptr )
	{
		return status;
	}

	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::io_completion;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::io_completion;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::io_control;
	driver_object->DriverUnload = driver::unload;

	device_object->Flags |= DO_BUFFERED_IO;
	device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}