#ifndef BASEDEFS_H
#define BASEDEFS_H

#ifdef __cplusplus
#define IW_EXTERN_C_START extern "C" {
#define IW_EXTERN_C_END }
#else
#define IW_EXTERN_C_START
#define IW_EXTERN_C_END
#endif

#if (defined(_WIN32) || defined(_WIN64))
#	if (defined(IW_NODLL) || defined(IW_STATIC))
#		define IW_EXPORT
#	else
#		ifdef IW_API_EXPORTS
#			define IW_EXPORT __declspec(dllexport)
#		else
#			define IW_EXPORT __declspec(dllimport)
#		endif
#	endif
#else
#   if __GNUC__ >= 4
#       define IW_EXPORT __attribute__ ((visibility("default")))
#   else
#       define IW_EXPORT
#   endif
#endif

#define IW_ARR_STATIC static
#define IW_ARR_CONST const

#ifdef _WIN32
#include <windows.h>
#define INVALIDHANDLE(_HNDL) (((_HNDL) == INVALID_HANDLE_VALUE) || (_HNDL) == NULL)
#else
typedef int HANDLE;
#define INVALID_HANDLE_VALUE (-1)
#define INVALIDHANDLE(_HNDL) ((_HNDL) < 0 || (_HNDL) == UINT16_MAX)
#endif

#define IW_ERROR_START 70000

#include<stdint.h>

typedef uint64_t iwrc; 


#endif
