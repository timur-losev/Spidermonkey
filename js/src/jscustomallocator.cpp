#include "jsapi.h"
//#include "jscustomallocator.h"

#if defined(XP_WIN)
    #include "jswin.h"
#elif defined(XP_UNIX)
    #include <errno.h>
    #include <sys/mman.h>
    #include <sys/resource.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <unistd.h>
#endif

#if ENABLE_POOL_ALLOCATOR

extern JS_PUBLIC_API(FMallocBinned*) CreateFMallocBinnedInstance() {
#ifdef _MSC_VER
        MEMORYSTATUSEX MemoryStatusEx;
        ZeroMemory(&MemoryStatusEx, sizeof(MemoryStatusEx));
        MemoryStatusEx.dwLength = sizeof(MemoryStatusEx);
        ::GlobalMemoryStatusEx(&MemoryStatusEx);

        SYSTEM_INFO SystemInfo;
        ZeroMemory(&SystemInfo, sizeof(SystemInfo));
        ::GetSystemInfo(&SystemInfo);

        size_t TotalPhysical = MemoryStatusEx.ullTotalPhys;
        size_t TotalVirtual = MemoryStatusEx.ullTotalVirtual;
        size_t BinnedPageSize = SystemInfo.dwAllocationGranularity;	// Use this so we get larger 64KiB pages, instead of 4KiB
        size_t OsAllocationGranularity = SystemInfo.dwAllocationGranularity;	// VirtualAlloc cannot allocate memory less than that
        size_t PageSize = SystemInfo.dwPageSize;

        size_t TotalPhysicalGB = (TotalPhysical + 1024 * 1024 * 1024 - 1) / 1024 / 1024 / 1024;

        return new FMallocBinned(BinnedPageSize & std::numeric_limits<uint32_t>::max(), ((uint64_t)std::numeric_limits<uint32_t>::max()) + 1);
#elif defined ANDROID
#endif
}

#ifdef ANDROID
     void* PlatformMemory::BinnedAllocFromOS(size_t Size)
    {
        return mmap(nullptr, Size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    }

     void PlatformMemory::BinnedFreeToOS(void* Ptr, size_t Size)
    {
        if (munmap(Ptr, Size) != 0)
        {
            const int ErrNo = errno;
        }
    }
#elif defined(_MSC_VER)
     void* PlatformMemory::BinnedAllocFromOS(size_t Size)
    {
        void* Ptr = VirtualAlloc(NULL, Size, MEM_COMMIT, PAGE_READWRITE);

        return Ptr;
    }

     void PlatformMemory::BinnedFreeToOS(void* Ptr, size_t Size)
    {
            // Windows maintains the size of allocation internally, so Size is unused
        assert(VirtualFree(Ptr, 0, MEM_RELEASE) != 0);
    }
#endif

#endif