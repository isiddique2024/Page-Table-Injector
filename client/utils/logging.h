#pragma once
#include <cstdio>
#include <cstring>

#define DISABLE_DEBUG_PRINT 0
#if DISABLE_DEBUG_PRINT
  #define debug_log(level, format, ...) ((void)0)
#else
  #define debug_log(level, format, ...)                                   \
    do {                                                                  \
      const char* prefix;                                                 \
      if (strcmp(level, "SUCCESS") == 0)                                  \
        prefix = "[+]";                                                   \
      else if (strcmp(level, "ERROR") == 0)                               \
        prefix = "[!]";                                                   \
      else if (strcmp(level, "WARNING") == 0)                             \
        prefix = "[-]";                                                   \
      else                                                                \
        prefix = "[*]";                                                   \
      printf("%s %s: " format "\n", prefix, __FUNCTION__, ##__VA_ARGS__); \
    } while (0)
#endif