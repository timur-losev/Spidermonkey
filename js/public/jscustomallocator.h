#pragma once

#ifdef ANDROID
#include <android/log.h>
static void
_my_malloc_message(size_t b)
{
  __android_log_print(ANDROID_LOG_INFO, "GeckoJemalloc", "%d", b);
}
#else
static void
_my_malloc_message(size_t b)
{
}
#endif

#  define JS_OOM_POSSIBLY_FAIL() do {} while(0)

static inline void* js_malloc(size_t bytes)
{
    _my_malloc_message(bytes);
    return malloc(bytes);
}

static inline void* js_calloc(size_t bytes)
{
    _my_malloc_message(bytes);
    return calloc(bytes, 1);
}

static inline void* js_calloc(size_t nmemb, size_t size)
{
    _my_malloc_message(size);
    return calloc(nmemb, size);
}

static inline void* js_realloc(void* p, size_t bytes)
{
    _my_malloc_message(bytes);
    return realloc(p, bytes);
}

static inline void js_free(void* p)
{
    free(p);
}