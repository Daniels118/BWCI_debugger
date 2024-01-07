#ifndef LL_NONE
#	define LL_NONE 0
#	define LL_ERROR 1
#	define LL_WARNING 2
#	define LL_NOTICE 3
#	define LL_INFO 4
#	define LL_DEBUG 5
#	define LL_TRACE 6
#	define LL_DEEP_TRACE 7
#	define PAUSE (void)getchar();
#endif

#ifdef LOG_LEVEL
#	undef _LOG_LEVEL
#	define _LOG_LEVEL LOG_LEVEL
#else
#	define _LOG_LEVEL LL_INFO
#endif

#ifdef PAUSE_ON
#	undef _PAUSE_ON
#	define _PAUSE_ON PAUSE_ON
#else
#	define _PAUSE_ON 0
#endif

#undef ERR
#undef WARN
#undef NOTICE
#undef INFO
#undef DEBUG
#undef TRACE

#if _LOG_LEVEL >= LL_ERR
#	if _PAUSE_ON >= LL_ERR
#		define ERR(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__); PAUSE;
#	else
#		define ERR(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__);
#	endif
#else
#	define ERR(format, ...)
#endif

#if _LOG_LEVEL >= LL_WARN
#	if _PAUSE_ON >= LL_WARN
#		define WARNING(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__); PAUSE;
#	else
#		define WARNING(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__);
#	endif
#else
#	define WARNING(format, ...)
#endif

#if _LOG_LEVEL >= LL_NOTICE
#	if _PAUSE_ON >= LL_NOTICE
#		define NOTICE(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__); PAUSE;
#	else
#		define NOTICE(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__);
#	endif
#else
#	define NOTICE(format, ...)
#endif

#if _LOG_LEVEL >= LL_INFO
#	if _PAUSE_ON >= LL_INFO
#		define INFO(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__); PAUSE;
#	else
#		define INFO(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__);
#	endif
#else
#	define INFO(format, ...)
#endif

#if _LOG_LEVEL >= LL_DEBUG
#	if _PAUSE_ON >= LL_DEBUG
#		define DEBUG(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__); PAUSE;
#	else
#		define DEBUG(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__);
#	endif
#else
#	define DEBUG(format, ...)
#endif

#if _LOG_LEVEL >= LL_TRACE
#	if _PAUSE_ON >= LL_TRACE
#		define TRACE(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__); PAUSE;
#	else
#		define TRACE(format, ...) printf("debugger:%i: " format "\n", __LINE__, ##__VA_ARGS__);
#	endif
#else
#	define TRACE(format, ...)
#endif

#undef _LOG_LEVEL
