#include "api.h"
#include <iostream>

using api::memory;
using api::process;
using api::thread;
using api::utils;


bool __stdcall DllMain( void* module_handle, uint32_t reason, void* reserved )
{
    return true;
}

extern "C"
{
    std::vector<process::process_information> process_list{};

    __declspec( dllexport ) void* __stdcall get_process_list( uint64_t* out_list_size )
    {
        process_list = process::get_process_list();

        if ( out_list_size != nullptr )
        {
            *out_list_size = process_list.size();
        }

        return process_list.data();
    }
}