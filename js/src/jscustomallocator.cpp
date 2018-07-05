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
    #include <sys/sysinfo.h>
#endif


#ifdef ANDROID
#include <android/log.h>
#endif

#if ENABLE_POOL_ALLOCATOR
#define ARRAY_COUNT(arr) sizeof(arr)/sizeof(arr[0])

    struct MemStats {
        size_t AvailablePhysical = 0;
        size_t AvailableVirtual = 0;
        size_t PeakUsedVirtual  = 0;
        size_t UsedVirtual = 0;
        size_t PeakUsedPhysical = 0;
        size_t UsedPhysical = 0;
        size_t TotalPhysical = 0;
    };

    struct PlatformMemoryConstants {
        size_t TotalPhysical = 0;
        size_t TotalVirtual = 0;
        size_t TotalPhysicalGB = 0;
        size_t PageSize = 0;
        size_t BinnedPageSize = 0;
        size_t OsAllocationGranularity = 0;
    };

#ifdef ANDROID
    static uint64_t GetBytesFromStatusLine(char * Line)
    {
        assert(Line);
        int Len = strlen(Line);

        // Len should be long enough to hold at least " kB\n"
        const int kSuffixLength = 4;	// " kB\n"
        if (Len <= kSuffixLength)
        {
            return 0;
        }

        // let's check that this is indeed "kB"
        char * Suffix = &Line[Len - kSuffixLength];
        if (strcmp(Suffix, " kB\n") != 0)
        {
            // Linux the kernel changed the format, huh?
            return 0;
        }

        // kill the kB
        *Suffix = 0;

        // find the beginning of the number
        for (const char * NumberBegin = Suffix; NumberBegin >= Line; --NumberBegin)
        {
            if (*NumberBegin == ' ')
            {
                return static_cast< uint64_t >(atol(NumberBegin + 1)) * 1024ULL;
            }
        }

        // we were unable to find whitespace in front of the number
        return 0;
    }

    static MemStats GetStats()
    {
        MemStats MemoryStats;

        if (FILE* FileGlobalMemStats = fopen("/proc/meminfo", "r"))
            {
                int FieldsSetSuccessfully = 0;
                uint64_t MemFree = 0, Cached = 0;
                do
                {
                    char LineBuffer[256] = { 0 };
                    char *Line = fgets(LineBuffer, 256, FileGlobalMemStats);
                    if (Line == nullptr)
                    {
                        break;	// eof or an error
                    }

                    // if we have MemAvailable, favor that (see http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773)
                    if (strstr(Line, "MemAvailable:") == Line)
                    {
                        MemoryStats.AvailablePhysical = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                    else if (strstr(Line, "SwapFree:") == Line)
                    {
                        MemoryStats.AvailableVirtual = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                    else if (strstr(Line, "MemFree:") == Line)
                    {
                        MemFree = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                    else if (strstr(Line, "Cached:") == Line)
                    {
                        Cached = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                } while (FieldsSetSuccessfully < 4);

                // if we didn't have MemAvailable (kernels < 3.14 or CentOS 6.x), use free + cached as a (bad) approximation
                if (MemoryStats.AvailablePhysical == 0)
                {
                    //MemoryStats.AvailablePhysical = std::min(MemFree + Cached, MemoryStats.TotalPhysical);
                }

                fclose(FileGlobalMemStats);
            }

            // again /proc "API" :/
            if (FILE* ProcMemStats = fopen("/proc/self/status", "r"))
            {
                int FieldsSetSuccessfully = 0;
                do
                {
                    char LineBuffer[256] = { 0 };
                    char *Line = fgets(LineBuffer, ARRAY_COUNT(LineBuffer), ProcMemStats);
                    if (Line == nullptr)
                    {
                        break;	// eof or an error
                    }

                    if (strstr(Line, "VmPeak:") == Line)
                    {
                        MemoryStats.PeakUsedVirtual = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                    else if (strstr(Line, "VmSize:") == Line)
                    {
                        MemoryStats.UsedVirtual = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                    else if (strstr(Line, "VmHWM:") == Line)
                    {
                        MemoryStats.PeakUsedPhysical = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                    else if (strstr(Line, "VmRSS:") == Line)
                    {
                        MemoryStats.UsedPhysical = GetBytesFromStatusLine(Line);
                        ++FieldsSetSuccessfully;
                    }
                } while (FieldsSetSuccessfully < 4);

                fclose(ProcMemStats);
            }

            // sanitize stats as sometimes peak < used for some reason
            MemoryStats.PeakUsedVirtual = std::max(MemoryStats.PeakUsedVirtual, MemoryStats.UsedVirtual);
            MemoryStats.PeakUsedPhysical = std::max(MemoryStats.PeakUsedPhysical, MemoryStats.UsedPhysical);

        return MemoryStats;
    }

   PlatformMemoryConstants GetConstants()
   {
        static PlatformMemoryConstants MemoryConstants;

        if (MemoryConstants.TotalPhysical == 0)
        {
            // Gather platform memory stats.
            struct sysinfo SysInfo;
            unsigned long long MaxPhysicalRAMBytes = 0;
            unsigned long long MaxVirtualRAMBytes = 0;

            if (0 == sysinfo(&SysInfo))
            {
                MaxPhysicalRAMBytes = static_cast< unsigned long long >(SysInfo.mem_unit) * static_cast< unsigned long long >(SysInfo.totalram);
                MaxVirtualRAMBytes = static_cast< unsigned long long >(SysInfo.mem_unit) * static_cast< unsigned long long >(SysInfo.totalswap);
            }

            MemoryConstants.TotalPhysical = MaxPhysicalRAMBytes;
            MemoryConstants.TotalVirtual = MaxVirtualRAMBytes;
            MemoryConstants.TotalPhysicalGB = (MemoryConstants.TotalPhysical + 1024 * 1024 * 1024 - 1) / 1024 / 1024 / 1024;
            MemoryConstants.PageSize = sysconf(_SC_PAGESIZE);
            MemoryConstants.BinnedPageSize = std::max((size_t)65536, MemoryConstants.PageSize);
            MemoryConstants.OsAllocationGranularity = MemoryConstants.PageSize;
        }

        return MemoryConstants;
    }
#endif

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

	const PlatformMemoryConstants& MemoryConstants = GetConstants();
	MemStats memoryStats = GetStats();

    __android_log_print(ANDROID_LOG_INFO, "Binned allocator", "Memory total: Physical=%.2fMB (%dGB approx) Available=%.2fMB PageSize=%.1fKB",
		float(MemoryConstants.TotalPhysical/1024.0/1024.0),
		MemoryConstants.TotalPhysicalGB, 
		float(memoryStats.AvailablePhysical/1024.0/1024.0),
		float(MemoryConstants.PageSize/1024.0));

        uint64_t MemoryLimit = std::min<uint64_t>(uint64_t(1) << details::CeilLogTwo(MemoryConstants.TotalPhysical), 0x100000000);

        return new FMallocBinned(MemoryConstants.PageSize, MemoryLimit);
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
