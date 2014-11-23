#ifndef _SnP_Interface_h_

// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define ENV64BIT
#else
#define ENV32BIT
#endif
#endif

// Check GCC
#if __GNUC__
#ifdef USE_KECCAK64
#define ENV64BIT
#else
#define ENV32BIT
#endif
#endif

#ifdef ENV32BIT
#include "KeccakF-1600/Inplace32BI/SnP-interface.h"
#endif

#ifdef ENV64BIT
#include "KeccakF-1600/Optimized64/SnP-interface.h"
#endif


#endif