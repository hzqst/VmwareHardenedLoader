// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Provides code to use STL in a driver project

#ifndef HYPERPLATFORM_KERNEL_STL_H_
#define HYPERPLATFORM_KERNEL_STL_H_

#include <fltKernel.h>

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

/// Disabling exception in headers included after this file
#ifdef _HAS_EXCEPTIONS
#undef _HAS_EXCEPTIONS
#endif
#define _HAS_EXCEPTIONS 0

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

/// An alternative implmentation of a C++ exception handler. Issues a bug check.
/// @param bug_check_code   A bug check code
DECLSPEC_NORETURN void KernelStlRaiseException(_In_ ULONG bug_check_code);

// Followings are definitions of functions needed to link successfully.

DECLSPEC_NORETURN void __cdecl _invalid_parameter_noinfo_noreturn();

namespace std {

DECLSPEC_NORETURN void __cdecl _Xbad_alloc();
DECLSPEC_NORETURN void __cdecl _Xinvalid_argument(_In_z_ const char *);
DECLSPEC_NORETURN void __cdecl _Xlength_error(_In_z_ const char *);
DECLSPEC_NORETURN void __cdecl _Xout_of_range(_In_z_ const char *);
DECLSPEC_NORETURN void __cdecl _Xoverflow_error(_In_z_ const char *);
DECLSPEC_NORETURN void __cdecl _Xruntime_error(_In_z_ const char *);

}  // namespace std

/// An alternative implmentation of the new operator
/// @param size   A size to allocate in bytes
/// @return An allocated pointer. The operator delete should be used to free it
void *__cdecl operator new(_In_ size_t size);

/// An alternative implmentation of the new operator
/// @param p   A pointer to delete
void __cdecl operator delete(_In_ void *p);

/// An alternative implmentation of the new operator
/// @param p   A pointer to delete
/// @param size   Ignored
void __cdecl operator delete(_In_ void *p, _In_ size_t size);

/// An alternative implmentation of __stdio_common_vsprintf_s
/// @param _Options   Ignored
/// @param _Buffer  Storage location for output
/// @param _BufferCount   Maximum number of characters to write
/// @param _Format  Format specification
/// @param _Locale  Ignored
/// @param _ArgList   Pointer to list of arguments
/// @return The number of characters written, not including the terminating null
///         character, or a negative value if an output error occurs
_Success_(return >= 0) EXTERN_C inline int __cdecl __stdio_common_vsprintf_s(
    _In_ unsigned __int64 _Options, _Out_writes_z_(_BufferCount) char *_Buffer,
    _In_ size_t _BufferCount,
    _In_z_ _Printf_format_string_params_(2) char const *_Format,
    _In_opt_ _locale_t _Locale, va_list _ArgList);

/// An alternative implmentation of __stdio_common_vswprintf_s
/// @param _Options   Ignored
/// @param _Buffer  Storage location for output
/// @param _BufferCount   Maximum number of characters to write
/// @param _Format  Format specification
/// @param _Locale  Ignored
/// @param _ArgList   Pointer to list of arguments
/// @return The number of characters written, not including the terminating null
///         character, or a negative value if an output error occurs
_Success_(return >= 0) _Check_return_opt_ EXTERN_C
    inline int __cdecl __stdio_common_vswprintf_s(
        _In_ unsigned __int64 _Options,
        _Out_writes_z_(_BufferCount) wchar_t *_Buffer, _In_ size_t _BufferCount,
        _In_z_ _Printf_format_string_params_(2) wchar_t const *_Format,
        _In_opt_ _locale_t _Locale, va_list _ArgList);

#endif  // HYPERPLATFORM_KERNEL_STL_H_
