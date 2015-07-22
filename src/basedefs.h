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





#endif
