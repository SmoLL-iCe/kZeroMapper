#pragma once
#include <cstdarg>
#include <cstdio>
#include <Windows.h>
#define WITH_LOGS

namespace kZeroMapper {
	void InternalLog(const char* fmt, ...);
}

#if defined(TEST_ACTION) || defined(CONSOLE) || defined(WITH_LOGS) || defined(_DEBUG) || defined(DEBUG)
#define LOG_FILE(fmt, ...) ::kZeroMapper::InternalLog(fmt, ##__VA_ARGS__)
#define LOG_SEC(fmt, ...)  ::kZeroMapper::InternalLog(fmt, ##__VA_ARGS__)
#define LOGS(fmt, ...)     ::kZeroMapper::InternalLog(fmt, ##__VA_ARGS__)
#else
#define LOG_FILE(fmt, ...) ((void)0)
#define LOG_SEC(fmt, ...)  ((void)0)
#define LOGS(fmt, ...)     ((void)0)
#endif
