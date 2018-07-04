#pragma once

#define ENABLE_POOL_ALLOCATOR 1

#if ENABLE_POOL_ALLOCATOR
#include <stdint.h>
#include <type_traits>
#include <assert.h>
#include <algorithm>
#include <limits>

#endif

#if !defined(__LP64__) && !defined(_WIN64)
#define PLATFORM_32BITS 1
#else
#define PLATFORM_64BITS 1
#endif



#if ENABLE_POOL_ALLOCATOR
#define MEM_TIME(st)

//#define USE_LOCKFREE_DELETE
#define CACHE_FREED_OS_ALLOCS


#if defined CACHE_FREED_OS_ALLOCS
#define MAX_CACHED_OS_FREES (64)
#if PLATFORM_64BITS
#define MAX_CACHED_OS_FREES_BYTE_LIMIT (64*1024*1024)
#else
#define MAX_CACHED_OS_FREES_BYTE_LIMIT (16*1024*1024)
#endif
#endif

#define STAT(x)

enum {
    DEFAULT_ALIGNMENT = 16
};

typedef int64_t PTRINT;

namespace details {
    template <typename T>
    T Align(T Val, uint64_t Alignment)
    {
        static_assert(std::is_integral<T>::value || std::is_pointer<T>::value, "Align expects an integer or pointer type");

        return (T)(((uint64_t)Val + Alignment - 1) & ~(Alignment - 1));
    }

    inline uint32_t CeilLogTwo(uint32_t Arg)
    {
        auto FloorLog2 = [](uint32_t Value) -> uint32_t {
            uint32_t pos = 0;
            if (Value >= 1 << 16) { Value >>= 16; pos += 16; }
            if (Value >= 1 << 8) { Value >>= 8; pos += 8; }
            if (Value >= 1 << 4) { Value >>= 4; pos += 4; }
            if (Value >= 1 << 2) { Value >>= 2; pos += 2; }
            if (Value >= 1 << 1) { pos += 1; }
            return (Value == 0) ? 0 : pos;
        };

        auto CountLeadingZeros = [FloorLog2](uint32_t Value) -> uint32_t {
            if (Value == 0) return 32;
            return 31 - FloorLog2(Value);
        };

        int32_t Bitmask = ((int32_t)(CountLeadingZeros(Arg) << 26)) >> 31;
        return (32 - CountLeadingZeros(Arg - 1)) & (~Bitmask);
    }
}

class JS_PUBLIC_API(PlatformMemory) {

public:

#ifdef ANDROID
    static void* BinnedAllocFromOS(size_t Size);

    static void BinnedFreeToOS(void* Ptr, size_t Size);
#elif defined(_MSC_VER)
    static void* BinnedAllocFromOS(size_t Size);

    static void BinnedFreeToOS(void* Ptr, size_t Size);
#endif
};

//
// Optimized virtual memory allocator.
//
class FMallocBinned;

extern JS_PUBLIC_API(FMallocBinned*) CreateFMallocBinnedInstance();

class FMallocBinned
{
public:
    static FMallocBinned* getInstance() {
        static FMallocBinned* instance = CreateFMallocBinnedInstance();

        return instance;
    }
private:

    // Counts.
    enum { POOL_COUNT = 42 };

    /** Maximum allocation for the pooled allocator */
    enum { EXTENED_PAGE_POOL_ALLOCATION_COUNT = 2 };
    enum { MAX_POOLED_ALLOCATION_SIZE = 32768 + 1 };
    enum { PAGE_SIZE_LIMIT = 65536 };
    // BINNED_ALLOC_POOL_SIZE can be increased beyond 64k to cause binned malloc to allocate
    // the small size bins in bigger chunks. If OS Allocation is slow, increasing
    // this number *may* help performance but YMMV.
    enum { BINNED_ALLOC_POOL_SIZE = 65536 };

    // Forward declares.
    struct FFreeMem;
    struct FPoolTable;

    // Memory pool info. 32 bytes.
    struct FPoolInfo
    {
        /** Number of allocated elements in this pool, when counts down to zero can free the entire pool. */
        uint16_t			Taken;		// 2
                                    /** Index of pool. Index into MemSizeToPoolTable[]. Valid when < MAX_POOLED_ALLOCATION_SIZE, MAX_POOLED_ALLOCATION_SIZE is OsTable.
                                    When AllocSize is 0, this is the number of pages to step back to find the base address of an allocation. See FindPoolInfoInternal()
                                    */
        uint16_t			TableIndex; // 4		
                                    /** Number of bytes allocated */
        uint32_t			AllocSize;	// 8
                                    /** Pointer to first free memory in this pool or the OS Allocation Size in bytes if this allocation is not binned*/
        FFreeMem*		FirstMem;   // 12/16
        FPoolInfo*		Next;		// 16/24
        FPoolInfo**		PrevLink;	// 20/32
#if PLATFORM_32BITS
                                    /** Explicit padding for 32 bit builds */
        uint8_t Padding[12]; // 32
#endif

        void SetAllocationSizes(uint32_t InBytes, size_t InOsBytes, uint32_t InTableIndex, uint32_t SmallAllocLimt)
        {
            TableIndex = InTableIndex;
            AllocSize = InBytes;
            if (TableIndex == SmallAllocLimt)
            {
                FirstMem = (FFreeMem*)InOsBytes;
            }
        }

        uint32_t GetBytes() const
        {
            return AllocSize;
        }

        size_t GetOsBytes(uint32_t InPageSize, uint32_t SmallAllocLimt) const
        {
            if (TableIndex == SmallAllocLimt)
            {
                return (size_t)FirstMem;
            }
            else
            {
                return details::Align(AllocSize, InPageSize);
            }
        }

        void Link(FPoolInfo*& Before)
        {
            if (Before)
            {
                Before->PrevLink = &Next;
            }
            Next = Before;
            PrevLink = &Before;
            Before = this;
        }

        void Unlink()
        {
            if (Next)
            {
                Next->PrevLink = PrevLink;
            }
            *PrevLink = Next;
        }
    };

    /** Information about a piece of free memory. 8 bytes */
    struct FFreeMem
    {
        /** Next or MemLastPool[], always in order by pool. */
        FFreeMem*	Next;
        /** Number of consecutive free blocks here, at least 1. */
        uint32_t		NumFreeBlocks;
    };

    /** Default alignment for binned allocator */
    enum { DEFAULT_BINNED_ALLOCATOR_ALIGNMENT = sizeof(FFreeMem) };

#ifdef CACHE_FREED_OS_ALLOCS
    /**  */
    struct FFreePageBlock
    {
        void*				Ptr;
        size_t				ByteSize;

        FFreePageBlock()
        {
            Ptr = nullptr;
            ByteSize = 0;
        }
    };
#endif

    /** Pool table. */
    struct FPoolTable
    {
        FPoolInfo*			FirstPool;
        FPoolInfo*			ExhaustedPool;
        uint32_t				BlockSize;

#if STATS
        /** Number of currently active pools */
        uint32_t				NumActivePools;

        /** Largest number of pools simultaneously active */
        uint32_t				MaxActivePools;

        /** Number of requests currently active */
        uint32_t				ActiveRequests;

        /** High watermark of requests simultaneously active */
        uint32_t				MaxActiveRequests;

        /** Minimum request size (in bytes) */
        uint32_t				MinRequest;

        /** Maximum request size (in bytes) */
        uint32_t				MaxRequest;

        /** Total number of requests ever */
        uint64_t				TotalRequests;

        /** Total waste from all allocs in this table */
        uint64_t				TotalWaste;
#endif
        FPoolTable()
            : FirstPool(nullptr)
            , ExhaustedPool(nullptr)
            , BlockSize(0)
#if STATS
            , NumActivePools(0)
            , MaxActivePools(0)
            , ActiveRequests(0)
            , MaxActiveRequests(0)
            , MinRequest(0)
            , MaxRequest(0)
            , TotalRequests(0)
            , TotalWaste(0)
#endif
        {

        }
    };

    /** Hash table struct for retrieving allocation book keeping information */
    struct PoolHashBucket
    {
        size_t			Key;
        FPoolInfo*		FirstPool;
        PoolHashBucket* Prev;
        PoolHashBucket* Next;

        PoolHashBucket()
        {
            Key = 0;
            FirstPool = nullptr;
            Prev = this;
            Next = this;
        }

        void Link(PoolHashBucket* After)
        {
            Link(After, Prev, this);
        }

        static void Link(PoolHashBucket* Node, PoolHashBucket* Before, PoolHashBucket* After)
        {
            Node->Prev = Before;
            Node->Next = After;
            Before->Next = Node;
            After->Prev = Node;
        }

        void Unlink()
        {
            Next->Prev = Prev;
            Prev->Next = Next;
            Prev = this;
            Next = this;
        }
    };

    uint64_t TableAddressLimit;


    // PageSize dependent constants
    uint64_t MaxHashBuckets;
    uint64_t MaxHashBucketBits;
    uint64_t MaxHashBucketWaste;
    uint64_t MaxBookKeepingOverhead;
    /** Shift to get the reference from the indirect tables */
    uint64_t PoolBitShift;
    uint64_t IndirectPoolBitShift;
    uint64_t IndirectPoolBlockSize;
    /** Shift required to get required hash table key. */
    uint64_t HashKeyShift;
    /** Used to mask off the bits that have been used to lookup the indirect table */
    uint64_t PoolMask;
    uint64_t BinnedSizeLimit;
    uint64_t BinnedOSTableIndex;

    // Variables.
    FPoolTable  PoolTable[POOL_COUNT];
    FPoolTable	OsTable;
    FPoolTable	PagePoolTable[EXTENED_PAGE_POOL_ALLOCATION_COUNT];
    FPoolTable* MemSizeToPoolTable[MAX_POOLED_ALLOCATION_SIZE + EXTENED_PAGE_POOL_ALLOCATION_COUNT];

    PoolHashBucket* HashBuckets;
    PoolHashBucket* HashBucketFreeList;

    uint32_t		PageSize;

#ifdef CACHE_FREED_OS_ALLOCS
    FFreePageBlock	FreedPageBlocks[MAX_CACHED_OS_FREES];
    uint32_t			FreedPageBlocksNum;
    uint32_t			CachedTotal;
#endif

#if STATS
    size_t		OsCurrent;
    size_t		OsPeak;
    size_t		WasteCurrent;
    size_t		WastePeak;
    size_t		UsedCurrent;
    size_t		UsedPeak;
    size_t		CurrentAllocs;
    size_t		TotalAllocs;
    /** OsCurrent - WasteCurrent - UsedCurrent. */
    size_t		SlackCurrent;
    double		MemTime;
#endif

    // Implementation. 
    void OutOfMemory(uint64_t Size, uint32_t Alignment = 0)
    {
        // this is expected not to return
        
    }

    inline void TrackStats(FPoolTable* Table, size_t Size)
    {
#if STATS
        // keep track of memory lost to padding
        Table->TotalWaste += Table->BlockSize - Size;
        Table->TotalRequests++;
        Table->ActiveRequests++;
        Table->MaxActiveRequests = std::max(Table->MaxActiveRequests, Table->ActiveRequests);
        Table->MaxRequest = Size > Table->MaxRequest ? Size : Table->MaxRequest;
        Table->MinRequest = Size < Table->MinRequest ? Size : Table->MinRequest;
#endif
    }

    /**
    * Create a 64k page of FPoolInfo structures for tracking allocations
    */
    FPoolInfo* CreateIndirect()
    {
        assert(IndirectPoolBlockSize * sizeof(FPoolInfo) <= PageSize);
        FPoolInfo* Indirect = (FPoolInfo*)PlatformMemory::BinnedAllocFromOS(IndirectPoolBlockSize * sizeof(FPoolInfo));
        if (!Indirect)
        {
            OutOfMemory(IndirectPoolBlockSize * sizeof(FPoolInfo));
        }
        memset(Indirect, 0, IndirectPoolBlockSize * sizeof(FPoolInfo));
        //STAT(OsPeak = std::max(OsPeak, OsCurrent += Align(IndirectPoolBlockSize * sizeof(FPoolInfo), PageSize)));
        //STAT(WastePeak = std::max(WastePeak, WasteCurrent += Align(IndirectPoolBlockSize * sizeof(FPoolInfo), PageSize)));
        return Indirect;
    }

    /**
    * Gets the FPoolInfo for a memory address. If no valid info exists one is created.
    * NOTE: This function requires a mutex across threads, but its is the callers responsibility to
    * acquire the mutex before calling
    */
    inline FPoolInfo* GetPoolInfo(size_t Ptr)
    {
        if (!HashBuckets)
        {
            // Init tables.
            HashBuckets = (PoolHashBucket*)PlatformMemory::BinnedAllocFromOS(details::Align(MaxHashBuckets * sizeof(PoolHashBucket), PageSize));

            for (uint32_t i = 0; i<MaxHashBuckets; ++i)
            {
                new (HashBuckets + i) PoolHashBucket();
            }
        }

        size_t Key = Ptr >> HashKeyShift;
        size_t Hash = Key & (MaxHashBuckets - 1);
        size_t PoolIndex = ((size_t)Ptr >> PoolBitShift) & PoolMask;

        PoolHashBucket* collision = &HashBuckets[Hash];
        do
        {
            if (collision->Key == Key || !collision->FirstPool)
            {
                if (!collision->FirstPool)
                {
                    collision->Key = Key;
                    InitializeHashBucket(collision);
                    assert(!!collision->FirstPool);
                }
                return &collision->FirstPool[PoolIndex];
            }
            collision = collision->Next;
        } while (collision != &HashBuckets[Hash]);
        //Create a new hash bucket entry
        PoolHashBucket* NewBucket = CreateHashBucket();
        NewBucket->Key = Key;
        HashBuckets[Hash].Link(NewBucket);
        return &NewBucket->FirstPool[PoolIndex];
    }

    inline FPoolInfo* FindPoolInfo(size_t Ptr1, size_t& AllocationBase)
    {
        uint16_t NextStep = 0;
        size_t Ptr = Ptr1 & ~((size_t)PageSize - 1);
        for (uint32_t i = 0, n = (BINNED_ALLOC_POOL_SIZE / PageSize) + 1; i<n; ++i)
        {
            FPoolInfo* Pool = FindPoolInfoInternal(Ptr, NextStep);
            if (Pool)
            {
                AllocationBase = Ptr;
                //assert(Ptr1 >= AllocationBase && Ptr1 < AllocationBase+Pool->GetBytes());
                return Pool;
            }
            Ptr = ((Ptr - (PageSize*NextStep)) - 1)&~((size_t)PageSize - 1);
        }
        AllocationBase = 0;
        return nullptr;
    }

    inline FPoolInfo* FindPoolInfoInternal(size_t Ptr, uint16_t& JumpOffset)
    {
        assert(HashBuckets);

        uint32_t Key = Ptr >> HashKeyShift;
        uint32_t Hash = Key & (MaxHashBuckets - 1);
        uint32_t PoolIndex = ((size_t)Ptr >> PoolBitShift) & PoolMask;
        JumpOffset = 0;

        PoolHashBucket* collision = &HashBuckets[Hash];
        do
        {
            if (collision->Key == Key)
            {
                if (!collision->FirstPool[PoolIndex].AllocSize)
                {
                    JumpOffset = collision->FirstPool[PoolIndex].TableIndex;
                    return nullptr;
                }
                return &collision->FirstPool[PoolIndex];
            }
            collision = collision->Next;
        } while (collision != &HashBuckets[Hash]);

        return nullptr;
    }

    /**
    *	Returns a newly created and initialized PoolHashBucket for use.
    */
    inline PoolHashBucket* CreateHashBucket()
    {
        PoolHashBucket* bucket = AllocateHashBucket();
        InitializeHashBucket(bucket);
        return bucket;
    }

    /**
    *	Initializes bucket with valid parameters
    *	@param bucket pointer to be initialized
    */
    inline void InitializeHashBucket(PoolHashBucket* bucket)
    {
        if (!bucket->FirstPool)
        {
            bucket->FirstPool = CreateIndirect();
        }
    }

    /**
    * Allocates a hash bucket from the free list of hash buckets
    */
    PoolHashBucket* AllocateHashBucket()
    {
        if (!HashBucketFreeList)
        {
            HashBucketFreeList = (PoolHashBucket*)PlatformMemory::BinnedAllocFromOS(PageSize);
            //STAT(OsPeak = std::max(OsPeak, OsCurrent += PageSize));
            //STAT(WastePeak = std::max(WastePeak, WasteCurrent += PageSize));
            for (size_t i = 0, n = (PageSize / sizeof(PoolHashBucket)); i<n; ++i)
            {
                HashBucketFreeList->Link(new (HashBucketFreeList + i) PoolHashBucket());
            }
        }
        PoolHashBucket* NextFree = HashBucketFreeList->Next;
        PoolHashBucket* Free = HashBucketFreeList;
        Free->Unlink();
        if (NextFree == Free)
        {
            NextFree = nullptr;
        }
        HashBucketFreeList = NextFree;
        return Free;
    }

    FPoolInfo* AllocatePoolMemory(FPoolTable* Table, uint32_t PoolSize, uint16_t TableIndex)
    {
        // Must create a new pool.
        uint32_t Blocks = PoolSize / Table->BlockSize;
        uint32_t Bytes = Blocks * Table->BlockSize;
        size_t OsBytes = details::Align(Bytes, PageSize);
        assert(Blocks >= 1);
        assert(Blocks * Table->BlockSize <= Bytes && PoolSize >= Bytes);

        // Allocate memory.
        FFreeMem* Free = nullptr;
        size_t ActualPoolSize; //TODO: use this to reduce waste?
        Free = (FFreeMem*)OSAlloc(OsBytes, ActualPoolSize);

        assert(!((size_t)Free & (PageSize - 1)));
        if (!Free)
        {
            OutOfMemory(OsBytes);
        }

        // Create pool in the indirect table.
        FPoolInfo* Pool;
        {
            Pool = GetPoolInfo((size_t)Free);
            for (size_t i = (size_t)PageSize, Offset = 0; i<OsBytes; i += PageSize, ++Offset)
            {
                FPoolInfo* TrailingPool = GetPoolInfo(((size_t)Free) + i);
                assert(!!TrailingPool);
                //Set trailing pools to point back to first pool
                TrailingPool->SetAllocationSizes(0, 0, Offset, BinnedOSTableIndex);
            }
        }

        // Init pool.
        Pool->Link(Table->FirstPool);
        Pool->SetAllocationSizes(Bytes, OsBytes, TableIndex, BinnedOSTableIndex);
        //STAT(OsPeak = std::max(OsPeak, OsCurrent += OsBytes));
        //STAT(WastePeak = std::max(WastePeak, WasteCurrent += OsBytes - Bytes));
        Pool->Taken = 0;
        Pool->FirstMem = Free;

#if STATS
        Table->NumActivePools++;
        Table->MaxActivePools = std::max(Table->MaxActivePools, Table->NumActivePools);
#endif
        // Create first free item.
        Free->NumFreeBlocks = Blocks;
        Free->Next = nullptr;

        return Pool;
    }

    inline FFreeMem* AllocateBlockFromPool(FPoolTable* Table, FPoolInfo* Pool, uint32_t Alignment)
    {
        // Pick first available block and unlink it.
        Pool->Taken++;
        assert(Pool->TableIndex < BinnedOSTableIndex); // if this is false, FirstMem is actually a size not a pointer
        assert(Pool->FirstMem);
        assert(Pool->FirstMem->NumFreeBlocks > 0);
        assert(Pool->FirstMem->NumFreeBlocks < PAGE_SIZE_LIMIT);
        FFreeMem* Free = (FFreeMem*)((uint8_t*)Pool->FirstMem + --Pool->FirstMem->NumFreeBlocks * Table->BlockSize);
        if (!Pool->FirstMem->NumFreeBlocks)
        {
            Pool->FirstMem = Pool->FirstMem->Next;
            if (!Pool->FirstMem)
            {
                // Move to exhausted list.
                Pool->Unlink();
                Pool->Link(Table->ExhaustedPool);
            }
        }
        STAT(UsedPeak = std::max(UsedPeak, UsedCurrent += Table->BlockSize));
        return details::Align(Free, Alignment);
    }

    /**
    * Releases memory back to the system. This is not protected from multi-threaded access and it's
    * the callers responsibility to Lock AccessGuard before calling this.
    */
    void FreeInternal(void* Ptr)
    {
        MEM_TIME(MemTime -= FPlatformTime::Seconds());
        STAT(CurrentAllocs--);

        size_t BasePtr;
        FPoolInfo* Pool = FindPoolInfo((size_t)Ptr, BasePtr);
#if PLATFORM_IOS
        if (Pool == NULL)
        {
            UE_LOG(LogMemory, Warning, TEXT("Attempting to free a pointer we didn't allocate!"));
            return;
        }
#endif
        assert(Pool);
        assert(Pool->GetBytes() != 0);
        if (Pool->TableIndex < BinnedOSTableIndex)
        {
            FPoolTable* Table = MemSizeToPoolTable[Pool->TableIndex];
#ifdef USE_FINE_GRAIN_LOCKS
            FScopeLock TableLock(&Table->CriticalSection);
#endif
#if STATS
            Table->ActiveRequests--;
#endif
            // If this pool was exhausted, move to available list.
            if (!Pool->FirstMem)
            {
                Pool->Unlink();
                Pool->Link(Table->FirstPool);
            }

            void* BaseAddress = (void*)BasePtr;
            uint32_t BlockSize = Table->BlockSize;
            PTRINT OffsetFromBase = (PTRINT)Ptr - (PTRINT)BaseAddress;
            assert(OffsetFromBase >= 0);
            uint32_t AlignOffset = OffsetFromBase % BlockSize;

            // Patch pointer to include previously applied alignment.
            Ptr = (void*)((PTRINT)Ptr - (PTRINT)AlignOffset);

            // Free a pooled allocation.
            FFreeMem* Free = (FFreeMem*)Ptr;
            Free->NumFreeBlocks = 1;
            Free->Next = Pool->FirstMem;
            Pool->FirstMem = Free;
            STAT(UsedCurrent -= Table->BlockSize);

            // Free this pool.
            assert(Pool->Taken >= 1);
            if (--Pool->Taken == 0)
            {
#if STATS
                Table->NumActivePools--;
#endif
                // Free the OS memory.
                size_t OsBytes = Pool->GetOsBytes(PageSize, BinnedOSTableIndex);
                STAT(OsCurrent -= OsBytes);
                STAT(WasteCurrent -= OsBytes - Pool->GetBytes());
                Pool->Unlink();
                Pool->SetAllocationSizes(0, 0, 0, BinnedOSTableIndex);
                OSFree((void*)BasePtr, OsBytes);
            }
        }
        else
        {
            // Free an OS allocation.
            assert(!((size_t)Ptr & (PageSize - 1)));
            size_t OsBytes = Pool->GetOsBytes(PageSize, BinnedOSTableIndex);
            STAT(UsedCurrent -= Pool->GetBytes());
            STAT(OsCurrent -= OsBytes);
            STAT(WasteCurrent -= OsBytes - Pool->GetBytes());
            OSFree((void*)BasePtr, OsBytes);
        }

        MEM_TIME(MemTime += FPlatformTime::Seconds());
    }

    void PushFreeLockless(void* Ptr)
    {
        FreeInternal(Ptr);
    }

    /**
    * Clear and Process the list of frees to be deallocated. It's the callers
    * responsibility to Lock AccessGuard before calling this
    */
    void FlushPendingFrees()
    {
#ifdef USE_LOCKFREE_DELETE
        if (!PendingFreeList && !bDoneFreeListInit)
        {
            bDoneFreeListInit = true;
            PendingFreeList = new ((void*)PendingFreeListMemory) TLockFreePointerList<void>();
        }
        // Because a lockless list and TArray calls new/malloc internally, need to guard against re-entry
        if (bFlushingFrees || !PendingFreeList)
        {
            return;
        }
        bFlushingFrees = true;
        PendingFreeList->PopAll(FlushedFrees);
        for (uint32_t i = 0, n = FlushedFrees.Num(); i<n; ++i)
        {
            FreeInternal(FlushedFrees[i]);
        }
        FlushedFrees.Reset();
        bFlushingFrees = false;
#endif
    }

    inline void OSFree(void* Ptr, size_t Size)
    {
#ifdef CACHE_FREED_OS_ALLOCS
#ifdef USE_FINE_GRAIN_LOCKS
        FScopeLock MainLock(&AccessGuard);
#endif
        if (Size > MAX_CACHED_OS_FREES_BYTE_LIMIT / 4)
        {
            PlatformMemory::BinnedFreeToOS(Ptr, Size);
            return;
        }
        while (FreedPageBlocksNum && (FreedPageBlocksNum >= MAX_CACHED_OS_FREES || CachedTotal + Size > MAX_CACHED_OS_FREES_BYTE_LIMIT))
        {
            //Remove the oldest one
            void* FreePtr = FreedPageBlocks[0].Ptr;
            CachedTotal -= FreedPageBlocks[0].ByteSize;
            FreedPageBlocksNum--;
            if (FreedPageBlocksNum)
            {
                ::memmove(&FreedPageBlocks[0], &FreedPageBlocks[1], sizeof(FFreePageBlock) * FreedPageBlocksNum);
            }
            PlatformMemory::BinnedFreeToOS(FreePtr, Size);
        }
        FreedPageBlocks[FreedPageBlocksNum].Ptr = Ptr;
        FreedPageBlocks[FreedPageBlocksNum].ByteSize = Size;
        CachedTotal += Size;
        ++FreedPageBlocksNum;
#else
        (void)Size;
        PlatformMemory::BinnedFreeToOS(Ptr);
#endif
    }

    inline void* OSAlloc(size_t NewSize, size_t& OutActualSize)
    {
#ifdef CACHE_FREED_OS_ALLOCS
        {
#ifdef USE_FINE_GRAIN_LOCKS
            // We want to hold the lock a little as possible so release it
            // before the big call to the OS
            FScopeLock MainLock(&AccessGuard);
#endif
            for (uint32_t i = 0; i < FreedPageBlocksNum; ++i)
            {
                // look for exact matches first, these are aligned to the page size, so it should be quite common to hit these on small pages sizes
                if (FreedPageBlocks[i].ByteSize == NewSize)
                {
                    void* Ret = FreedPageBlocks[i].Ptr;
                    OutActualSize = FreedPageBlocks[i].ByteSize;
                    CachedTotal -= FreedPageBlocks[i].ByteSize;
                    if (i < FreedPageBlocksNum - 1)
                    {
                        ::memmove(&FreedPageBlocks[i], &FreedPageBlocks[i + 1], sizeof(FFreePageBlock) * (FreedPageBlocksNum - i - 1));
                    }
                    FreedPageBlocksNum--;
                    return Ret;
                }
            };
            for (uint32_t i = 0; i < FreedPageBlocksNum; ++i)
            {
                // is it possible (and worth i.e. <25% overhead) to use this block
                if (FreedPageBlocks[i].ByteSize >= NewSize && FreedPageBlocks[i].ByteSize * 3 <= NewSize * 4)
                {
                    void* Ret = FreedPageBlocks[i].Ptr;
                    OutActualSize = FreedPageBlocks[i].ByteSize;
                    CachedTotal -= FreedPageBlocks[i].ByteSize;
                    if (i < FreedPageBlocksNum - 1)
                    {
                        ::memmove(&FreedPageBlocks[i], &FreedPageBlocks[i + 1], sizeof(FFreePageBlock) * (FreedPageBlocksNum - i - 1));
                    }
                    FreedPageBlocksNum--;
                    return Ret;
                }
            };
        }
        OutActualSize = NewSize;
        void* Ptr = PlatformMemory::BinnedAllocFromOS(NewSize);
        if (!Ptr)
        {
            //Are we holding on to much mem? Release it all.
            FlushAllocCache();
            Ptr = PlatformMemory::BinnedAllocFromOS(NewSize);
        }
        return Ptr;
#else
        (void)OutActualSize;
        return PlatformMemory::BinnedAllocFromOS(NewSize);
#endif
    }

#ifdef CACHE_FREED_OS_ALLOCS
    void FlushAllocCache()
    {
#ifdef USE_FINE_GRAIN_LOCKS
        FScopeLock MainLock(&AccessGuard);
#endif
        for (int i = 0, n = FreedPageBlocksNum; i<n; ++i)
        {
            //Remove allocs
            PlatformMemory::BinnedFreeToOS(FreedPageBlocks[i].Ptr, FreedPageBlocks[i].ByteSize);
            FreedPageBlocks[i].Ptr = nullptr;
            FreedPageBlocks[i].ByteSize = 0;
        }
        FreedPageBlocksNum = 0;
        CachedTotal = 0;
    }
#endif

public:

    // FMalloc interface.
    // InPageSize - First parameter is page size, all allocs from BinnedAllocFromOS() MUST be aligned to this size
    // AddressLimit - Second parameter is estimate of the range of addresses expected to be returns by BinnedAllocFromOS(). Binned
    // Malloc will adjust it's internal structures to make look ups for memory allocations O(1) for this range. 
    // It's is ok to go outside this range, look ups will just be a little slower
    FMallocBinned(uint32_t InPageSize, uint64_t AddressLimit)
        : TableAddressLimit(AddressLimit)
#ifdef USE_LOCKFREE_DELETE
        , PendingFreeList(nullptr)
        , bFlushingFrees(false)
        , bDoneFreeListInit(false)
#endif
        , HashBuckets(nullptr)
        , HashBucketFreeList(nullptr)
        , PageSize(InPageSize)
#ifdef CACHE_FREED_OS_ALLOCS
        , FreedPageBlocksNum(0)
        , CachedTotal(0)
#endif
#if STATS
        , OsCurrent(0)
        , OsPeak(0)
        , WasteCurrent(0)
        , WastePeak(0)
        , UsedCurrent(0)
        , UsedPeak(0)
        , CurrentAllocs(0)
        , TotalAllocs(0)
        , SlackCurrent(0)
        , MemTime(0.0)
#endif
    {
        assert(!(PageSize & (PageSize - 1)));
        assert(!(AddressLimit & (AddressLimit - 1)));
        assert(PageSize <= 65536); // There is internal limit on page size of 64k
        assert(AddressLimit > PageSize); // Check to catch 32 bit overflow in AddressLimit

                                        /** Shift to get the reference from the indirect tables */
        PoolBitShift = details::CeilLogTwo(PageSize);
        IndirectPoolBitShift = details::CeilLogTwo(PageSize / sizeof(FPoolInfo));
        IndirectPoolBlockSize = PageSize / sizeof(FPoolInfo);

        MaxHashBuckets = AddressLimit >> (IndirectPoolBitShift + PoolBitShift);
        MaxHashBucketBits = details::CeilLogTwo(MaxHashBuckets);
        MaxHashBucketWaste = (MaxHashBuckets * sizeof(PoolHashBucket)) / 1024;
        MaxBookKeepingOverhead = ((AddressLimit / PageSize) * sizeof(PoolHashBucket)) / (1024 * 1024);
        /**
        * Shift required to get required hash table key.
        */
        HashKeyShift = PoolBitShift + IndirectPoolBitShift;
        /** Used to mask off the bits that have been used to lookup the indirect table */
        PoolMask = ((1ull << (HashKeyShift - PoolBitShift)) - 1);
        BinnedSizeLimit = PAGE_SIZE_LIMIT / 2;
        BinnedOSTableIndex = BinnedSizeLimit + EXTENED_PAGE_POOL_ALLOCATION_COUNT;

        assert((BinnedSizeLimit & (BinnedSizeLimit - 1)) == 0);


        // Init tables.
        OsTable.FirstPool = nullptr;
        OsTable.ExhaustedPool = nullptr;
        OsTable.BlockSize = 0;

        /** The following options are not valid for page sizes less than 64k. They are here to reduce waste*/
        PagePoolTable[0].FirstPool = nullptr;
        PagePoolTable[0].ExhaustedPool = nullptr;
        PagePoolTable[0].BlockSize = PageSize == PAGE_SIZE_LIMIT ? BinnedSizeLimit + (BinnedSizeLimit / 2) : 0;

        PagePoolTable[1].FirstPool = nullptr;
        PagePoolTable[1].ExhaustedPool = nullptr;
        PagePoolTable[1].BlockSize = PageSize == PAGE_SIZE_LIMIT ? PageSize + BinnedSizeLimit : 0;

        // Block sizes are based around getting the maximum amount of allocations per pool, with as little alignment waste as possible.
        // Block sizes should be close to even divisors of the POOL_SIZE, and well distributed. They must be 16-byte aligned as well.
        static const uint32_t BlockSizes[POOL_COUNT] =
        {
            8,		16,		32,		48,		64,		80,		96,		112,
            128,	160,	192,	224,	256,	288,	320,	384,
            448,	512,	576,	640,	704,	768,	896,	1024,
            1168,	1360,	1632,	2048,	2336,	2720,	3264,	4096,
            4672,	5456,	6544,	8192,	9360,	10912,	13104,	16384,
            21840,	32768
        };

        for (uint32_t i = 0; i < POOL_COUNT; i++)
        {
            PoolTable[i].FirstPool = nullptr;
            PoolTable[i].ExhaustedPool = nullptr;
            PoolTable[i].BlockSize = BlockSizes[i];
#if STATS
            PoolTable[i].MinRequest = PoolTable[i].BlockSize;
#endif
        }

        for (uint32_t i = 0; i<MAX_POOLED_ALLOCATION_SIZE; i++)
        {
            uint32_t Index = 0;
            while (PoolTable[Index].BlockSize < i)
            {
                ++Index;
            }
            assert(Index < POOL_COUNT);
            MemSizeToPoolTable[i] = &PoolTable[Index];
        }

        MemSizeToPoolTable[BinnedSizeLimit] = &PagePoolTable[0];
        MemSizeToPoolTable[BinnedSizeLimit + 1] = &PagePoolTable[1];

        assert(MAX_POOLED_ALLOCATION_SIZE - 1 == PoolTable[POOL_COUNT - 1].BlockSize);
    }


    virtual ~FMallocBinned()
    {}


    /**
    * Malloc
    */
    void* Malloc(size_t Size, uint32_t Alignment)
    {
#ifdef USE_COARSE_GRAIN_LOCKS
        FScopeLock ScopedLock(&AccessGuard);
#endif

        FlushPendingFrees();

        // Handle DEFAULT_ALIGNMENT for binned allocator.
        if (Alignment == DEFAULT_ALIGNMENT)
        {
            Alignment = DEFAULT_BINNED_ALLOCATOR_ALIGNMENT;
        }

        Alignment = std::max<uint32_t>(Alignment, DEFAULT_BINNED_ALLOCATOR_ALIGNMENT);
        size_t SpareBytesCount = std::min<size_t>(DEFAULT_BINNED_ALLOCATOR_ALIGNMENT, Size);
        Size = std::max<size_t>(PoolTable[0].BlockSize, Size + (Alignment - SpareBytesCount));
        MEM_TIME(MemTime -= FPlatformTime::Seconds());
        STAT(CurrentAllocs++);
        STAT(TotalAllocs++);
        FFreeMem* Free;
        if (Size < BinnedSizeLimit)
        {
            // Allocate from pool.
            FPoolTable* Table = MemSizeToPoolTable[Size];

            assert(Size <= Table->BlockSize);

            TrackStats(Table, Size);

            FPoolInfo* Pool = Table->FirstPool;
            if (!Pool)
            {
                Pool = AllocatePoolMemory(Table, BINNED_ALLOC_POOL_SIZE/*PageSize*/, Size);
            }

            Free = AllocateBlockFromPool(Table, Pool, Alignment);
        }
        else if (((Size >= BinnedSizeLimit && Size <= PagePoolTable[0].BlockSize) ||
            (Size > PageSize && Size <= PagePoolTable[1].BlockSize)))
        {
            // Bucket in a pool of 3*PageSize or 6*PageSize
            uint32_t BinType = Size < PageSize ? 0 : 1;
            uint32_t PageCount = 3 * BinType + 3;
            FPoolTable* Table = &PagePoolTable[BinType];

            assert(Size <= Table->BlockSize);

            TrackStats(Table, Size);

            FPoolInfo* Pool = Table->FirstPool;
            if (!Pool)
            {
                Pool = AllocatePoolMemory(Table, PageCount*PageSize, BinnedSizeLimit + BinType);
            }

            Free = AllocateBlockFromPool(Table, Pool, Alignment);
        }
        else
        {
            // Use OS for large allocations.
            size_t AlignedSize = details::Align(Size, PageSize);
            size_t ActualPoolSize; //TODO: use this to reduce waste?
            Free = (FFreeMem*)OSAlloc(AlignedSize, ActualPoolSize);
            if (!Free)
            {
                OutOfMemory(AlignedSize);
            }

            void* AlignedFree = details::Align(Free, Alignment);

            // Create indirect.
            FPoolInfo* Pool;
            {
                Pool = GetPoolInfo((size_t)Free);

                if ((size_t)Free != ((size_t)AlignedFree & ~(PageSize - 1)))
                {
                    // Mark the FPoolInfo for AlignedFree to jump back to the FPoolInfo for ptr.
                    for (size_t i = (size_t)PageSize, Offset = 0; i < AlignedSize; i += PageSize, ++Offset)
                    {
                        FPoolInfo* TrailingPool = GetPoolInfo(((size_t)Free) + i);
                        assert(TrailingPool);
                        //Set trailing pools to point back to first pool
                        TrailingPool->SetAllocationSizes(0, 0, Offset, BinnedOSTableIndex);
                    }
                }
            }
            Free = (FFreeMem*)AlignedFree;
            Pool->SetAllocationSizes(Size, AlignedSize, BinnedOSTableIndex, BinnedOSTableIndex);
            STAT(OsPeak = std::max(OsPeak, OsCurrent += AlignedSize));
            STAT(UsedPeak = std::max(UsedPeak, UsedCurrent += Size));
            STAT(WastePeak = std::max(WastePeak, WasteCurrent += AlignedSize - Size));
        }

        MEM_TIME(MemTime += FPlatformTime::Seconds());
        return Free;
    }

    /**
    * Realloc
    */
    void* Realloc(void* Ptr, size_t NewSize, uint32_t Alignment)
    {
        // Handle DEFAULT_ALIGNMENT for binned allocator.
        if (Alignment == DEFAULT_ALIGNMENT)
        {
            Alignment = DEFAULT_BINNED_ALLOCATOR_ALIGNMENT;
        }

        Alignment = std::max<uint32_t>(Alignment, DEFAULT_BINNED_ALLOCATOR_ALIGNMENT);
        const uint32_t NewSizeUnmodified = NewSize;
        size_t SpareBytesCount = std::min<size_t>(DEFAULT_BINNED_ALLOCATOR_ALIGNMENT, NewSize);
        if (NewSize)
        {
            NewSize = std::max<size_t>(PoolTable[0].BlockSize, NewSize + (Alignment - SpareBytesCount));
        }
        MEM_TIME(MemTime -= FPlatformTime::Seconds());
        size_t BasePtr;
        void* NewPtr = Ptr;
        if (Ptr && NewSize)
        {
            FPoolInfo* Pool = FindPoolInfo((size_t)Ptr, BasePtr);

            if (Pool->TableIndex < BinnedOSTableIndex)
            {
                // Allocated from pool, so grow or shrink if necessary.
                assert(Pool->TableIndex > 0); // it isn't possible to allocate a size of 0, Malloc will increase the size to DEFAULT_BINNED_ALLOCATOR_ALIGNMENT
                if (NewSizeUnmodified > MemSizeToPoolTable[Pool->TableIndex]->BlockSize || NewSizeUnmodified <= MemSizeToPoolTable[Pool->TableIndex - 1]->BlockSize)
                {
                    NewPtr = Malloc(NewSizeUnmodified, Alignment);
                    memcpy(NewPtr, Ptr, std::min<size_t>(NewSizeUnmodified, MemSizeToPoolTable[Pool->TableIndex]->BlockSize - (Alignment - SpareBytesCount)));
                    Free(Ptr);
                }
                else if (((size_t)Ptr & (size_t)(Alignment - 1)) != 0)
                {
                    NewPtr = details::Align(Ptr, Alignment);
                    memmove(NewPtr, Ptr, NewSize);
                }
            }
            else
            {
                // Allocated from OS.
                if (NewSize > Pool->GetOsBytes(PageSize, BinnedOSTableIndex) || NewSize * 3 < Pool->GetOsBytes(PageSize, BinnedOSTableIndex) * 2)
                {
                    // Grow or shrink.
                    NewPtr = Malloc(NewSizeUnmodified, Alignment);
                    memcpy(NewPtr, Ptr, std::min<size_t>(NewSizeUnmodified, Pool->GetBytes()));
                    Free(Ptr);
                }
                else
                {
                    // Keep as-is, reallocation isn't worth the overhead.
                    STAT(UsedCurrent += NewSize - Pool->GetBytes());
                    STAT(UsedPeak = std::max(UsedPeak, UsedCurrent));
                    STAT(WasteCurrent += Pool->GetBytes() - NewSize);
                    Pool->SetAllocationSizes(NewSizeUnmodified, Pool->GetOsBytes(PageSize, BinnedOSTableIndex), BinnedOSTableIndex, BinnedOSTableIndex);
                }
            }
        }
        else if (Ptr == nullptr)
        {
            NewPtr = Malloc(NewSizeUnmodified, Alignment);
        }
        else
        {
            Free(Ptr);
            NewPtr = nullptr;
        }

        MEM_TIME(MemTime += FPlatformTime::Seconds());
        return NewPtr;
    }

    /**
    * Free
    */
    void Free(void* Ptr)
    {
        if (!Ptr)
        {
            return;
        }

        PushFreeLockless(Ptr);
    }

    /**
    * If possible determine the size of the memory allocated at the given address
    *
    * @param Original - Pointer to memory we are checking the size of
    * @param SizeOut - If possible, this value is set to the size of the passed in pointer
    * @return true if succeeded
    */
    bool GetAllocationSize(void *Original, size_t &SizeOut)
    {
        if (!Original)
        {
            return false;
        }
        size_t BasePtr;
        FPoolInfo* Pool = FindPoolInfo((size_t)Original, BasePtr);
        SizeOut = Pool->TableIndex < BinnedOSTableIndex ? MemSizeToPoolTable[Pool->TableIndex]->BlockSize : Pool->GetBytes();
        return true;
    }

    /**
    * Validates the allocator's heap
    */
    bool ValidateHeap()
    {
#ifdef USE_COARSE_GRAIN_LOCKS
        FScopeLock ScopedLock(&AccessGuard);
#endif
        for (int32_t i = 0; i < POOL_COUNT; i++)
        {
            FPoolTable* Table = &PoolTable[i];
#ifdef USE_FINE_GRAIN_LOCKS
            FScopeLock TableLock(&Table->CriticalSection);
#endif
            for (FPoolInfo** PoolPtr = &Table->FirstPool; *PoolPtr; PoolPtr = &(*PoolPtr)->Next)
            {
                FPoolInfo* Pool = *PoolPtr;
                assert(Pool->PrevLink == PoolPtr);
                assert(Pool->FirstMem);
                for (FFreeMem* Free = Pool->FirstMem; Free; Free = Free->Next)
                {
                    assert(Free->NumFreeBlocks > 0);
                }
            }
            for (FPoolInfo** PoolPtr = &Table->ExhaustedPool; *PoolPtr; PoolPtr = &(*PoolPtr)->Next)
            {
                FPoolInfo* Pool = *PoolPtr;
                assert(Pool->PrevLink == PoolPtr);
                assert(!Pool->FirstMem);
                (void)Pool;
            }
        }

        return(true);
    }


    /** Called once per frame, gathers and sets all memory allocator statistics into the corresponding stats. MUST BE THREAD SAFE. */
    void UpdateStats()
    {
#if STATS
        size_t	LocalOsCurrent = 0;
        size_t	LocalOsPeak = 0;
        size_t	LocalWasteCurrent = 0;
        size_t	LocalWastePeak = 0;
        size_t	LocalUsedCurrent = 0;
        size_t	LocalUsedPeak = 0;
        size_t	LocalCurrentAllocs = 0;
        size_t	LocalTotalAllocs = 0;
        size_t	LocalSlackCurrent = 0;

        {
#ifdef USE_INTERNAL_LOCKS
            FScopeLock ScopedLock(&AccessGuard);
#endif
            UpdateSlackStat();

            // Copy memory stats.
            LocalOsCurrent = OsCurrent;
            LocalOsPeak = OsPeak;
            LocalWasteCurrent = WasteCurrent;
            LocalWastePeak = WastePeak;
            LocalUsedCurrent = UsedCurrent;
            LocalUsedPeak = UsedPeak;
            LocalCurrentAllocs = CurrentAllocs;
            LocalTotalAllocs = TotalAllocs;
            LocalSlackCurrent = SlackCurrent;
        }

        SET_MEMORY_STAT(STAT_Binned_OsCurrent, LocalOsCurrent);
        SET_MEMORY_STAT(STAT_Binned_OsPeak, LocalOsPeak);
        SET_MEMORY_STAT(STAT_Binned_WasteCurrent, LocalWasteCurrent);
        SET_MEMORY_STAT(STAT_Binned_WastePeak, LocalWastePeak);
        SET_MEMORY_STAT(STAT_Binned_UsedCurrent, LocalUsedCurrent);
        SET_MEMORY_STAT(STAT_Binned_UsedPeak, LocalUsedPeak);
        SET_DWORD_STAT(STAT_Binned_CurrentAllocs, LocalCurrentAllocs);
        SET_DWORD_STAT(STAT_Binned_TotalAllocs, LocalTotalAllocs);
        SET_MEMORY_STAT(STAT_Binned_SlackCurrent, LocalSlackCurrent);
#endif
    }

    /** Writes allocator stats from the last update into the specified destination. */
    //void GetAllocatorStats(FGenericMemoryStats& out_Stats) override;

    /**
    * Dumps allocator stats to an output device. Subclasses should override to add additional info
    *
    * @param Ar	[in] Output device
    */
    void DumpAllocatorStats(class FOutputDevice& Ar)
    {
       
        {
#ifdef USE_COARSE_GRAIN_LOCKS
            FScopeLock ScopedLock(&AccessGuard);
#endif
            ValidateHeap();
#if STATS
            UpdateSlackStat();
#if !NO_LOGGING
            // This is all of the memory including stuff too big for the pools
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Allocator Stats for %s:"), GetDescriptiveName());
            // Waste is the total overhead of the memory system
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Current Memory %.2f MB used, plus %.2f MB waste"), UsedCurrent / (1024.0f * 1024.0f), (OsCurrent - UsedCurrent) / (1024.0f * 1024.0f));
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Peak Memory %.2f MB used, plus %.2f MB waste"), UsedPeak / (1024.0f * 1024.0f), (OsPeak - UsedPeak) / (1024.0f * 1024.0f));

            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Current OS Memory %.2f MB, peak %.2f MB"), OsCurrent / (1024.0f * 1024.0f), OsPeak / (1024.0f * 1024.0f));
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Current Waste %.2f MB, peak %.2f MB"), WasteCurrent / (1024.0f * 1024.0f), WastePeak / (1024.0f * 1024.0f));
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Current Used %.2f MB, peak %.2f MB"), UsedCurrent / (1024.0f * 1024.0f), UsedPeak / (1024.0f * 1024.0f));
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Current Slack %.2f MB"), SlackCurrent / (1024.0f * 1024.0f));

            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Allocs      % 6i Current / % 6i Total"), CurrentAllocs, TotalAllocs);
            MEM_TIME(BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Seconds     % 5.3f"), MemTime));
            MEM_TIME(BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("MSec/Allc   % 5.5f"), 1000.0 * MemTime / MemAllocs));

            // This is the memory tracked inside individual allocation pools
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT(""));
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Block Size Num Pools Max Pools Cur Allocs Total Allocs Min Req Max Req Mem Used Mem Slack Mem Waste Efficiency"));
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("---------- --------- --------- ---------- ------------ ------- ------- -------- --------- --------- ----------"));

            uint32_t TotalMemory = 0;
            uint32_t TotalWaste = 0;
            uint32_t TotalActiveRequests = 0;
            uint32_t TotalTotalRequests = 0;
            uint32_t TotalPools = 0;
            uint32_t TotalSlack = 0;

            FPoolTable* Table = nullptr;
            for (int32_t i = 0; i < BinnedSizeLimit + EXTENED_PAGE_POOL_ALLOCATION_COUNT; i++)
            {
                if (Table == MemSizeToPoolTable[i] || MemSizeToPoolTable[i]->BlockSize == 0)
                    continue;

                Table = MemSizeToPoolTable[i];

#ifdef USE_FINE_GRAIN_LOCKS
                FScopeLock TableLock(&Table->CriticalSection);
#endif

                uint32_t TableAllocSize = (Table->BlockSize > BinnedSizeLimit ? (((3 * (i - BinnedSizeLimit)) + 3)*BINNED_ALLOC_POOL_SIZE) : BINNED_ALLOC_POOL_SIZE);
                // The amount of memory allocated from the OS
                uint32_t MemAllocated = (Table->NumActivePools * TableAllocSize) / 1024;
                // Amount of memory actually in use by allocations
                uint32_t MemUsed = (Table->BlockSize * Table->ActiveRequests) / 1024;
                // Wasted memory due to pool size alignment
                uint32_t PoolMemWaste = Table->NumActivePools * (TableAllocSize - ((TableAllocSize / Table->BlockSize) * Table->BlockSize)) / 1024;
                // Wasted memory due to individual allocation alignment. This is an estimate.
                uint32_t MemWaste = (uint32_t)(((double)Table->TotalWaste / (double)Table->TotalRequests) * (double)Table->ActiveRequests) / 1024 + PoolMemWaste;
                // Memory that is reserved in active pools and ready for future use
                uint32_t MemSlack = MemAllocated - MemUsed - PoolMemWaste;

                BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("% 10i % 9i % 9i % 10i % 12i % 7i % 7i % 7iK % 8iK % 8iK % 9.2f%%"),
                    Table->BlockSize,
                    Table->NumActivePools,
                    Table->MaxActivePools,
                    Table->ActiveRequests,
                    (uint32_t)Table->TotalRequests,
                    Table->MinRequest,
                    Table->MaxRequest,
                    MemUsed,
                    MemSlack,
                    MemWaste,
                    MemAllocated ? 100.0f * (MemAllocated - MemWaste) / MemAllocated : 100.0f);

                TotalMemory += MemAllocated;
                TotalWaste += MemWaste;
                TotalSlack += MemSlack;
                TotalActiveRequests += Table->ActiveRequests;
                TotalTotalRequests += Table->TotalRequests;
                TotalPools += Table->NumActivePools;
            }

            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT(""));
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("%iK allocated in pools (with %iK slack and %iK waste). Efficiency %.2f%%"), TotalMemory, TotalSlack, TotalWaste, TotalMemory ? 100.0f * (TotalMemory - TotalWaste) / TotalMemory : 100.0f);
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT("Allocations %i Current / %i Total (in %i pools)"), TotalActiveRequests, TotalTotalRequests, TotalPools);
            BufferedOutput.CategorizedLogf(LogMemory.GetCategoryName(), ELogVerbosity::Log, TEXT(""));
#endif
#endif
        }

    }


protected:

    void UpdateSlackStat()
    {
#if	STATS
        size_t LocalWaste = WasteCurrent;
        double Waste = 0.0;
        for (int32_t PoolIndex = 0; PoolIndex < POOL_COUNT; PoolIndex++)
        {
            Waste += ((double)PoolTable[PoolIndex].TotalWaste / (double)PoolTable[PoolIndex].TotalRequests) * (double)PoolTable[PoolIndex].ActiveRequests;
            Waste += PoolTable[PoolIndex].NumActivePools * (BINNED_ALLOC_POOL_SIZE - ((BINNED_ALLOC_POOL_SIZE / PoolTable[PoolIndex].BlockSize) * PoolTable[PoolIndex].BlockSize));
        }
        LocalWaste += (uint32_t)Waste;
        SlackCurrent = OsCurrent - LocalWaste - UsedCurrent;
#endif // STATS
    }

};

#endif //ENABLE_POOL_ALLOCATOR

# if defined(DEBUG) || defined(JS_OOM_BREAKPOINT)
/*
 * In order to test OOM conditions, when the testing function
 * oomAfterAllocations COUNT is passed, we fail continuously after the NUM'th
 * allocation from now.
 */
extern JS_PUBLIC_DATA(uint32_t) OOM_maxAllocations; /* set in builtin/TestingFunctions.cpp */
extern JS_PUBLIC_DATA(uint32_t) OOM_counter; /* data race, who cares. */

#ifdef JS_OOM_BREAKPOINT
static MOZ_NEVER_INLINE void js_failedAllocBreakpoint() { asm(""); }
#define JS_OOM_CALL_BP_FUNC() js_failedAllocBreakpoint()
#else
#define JS_OOM_CALL_BP_FUNC() do {} while(0)
#endif

#  define JS_OOM_POSSIBLY_FAIL() \
    do \
    { \
        if (++OOM_counter > OOM_maxAllocations) { \
            JS_OOM_CALL_BP_FUNC();\
            return nullptr; \
        } \
    } while (0)

# else
#  define JS_OOM_POSSIBLY_FAIL() do {} while(0)
# endif /* DEBUG || JS_OOM_BREAKPOINT */

static inline void* js_malloc(size_t bytes)
{
    JS_OOM_POSSIBLY_FAIL();

    #if !ENABLE_POOL_ALLOCATOR
        return malloc(bytes);
    #else
        return FMallocBinned::getInstance()->Malloc(bytes, DEFAULT_ALIGNMENT);
    #endif
}

static inline void* js_calloc(size_t bytes)
{
    JS_OOM_POSSIBLY_FAIL();

    #if !ENABLE_POOL_ALLOCATOR
        return calloc(bytes, 1);
    #else
        void* data = FMallocBinned::getInstance()->Malloc(bytes, DEFAULT_ALIGNMENT);
        ::memset(data, 0, bytes);

        return data;
    #endif
}

static inline void* js_calloc(size_t nmemb, size_t size)
{
   JS_OOM_POSSIBLY_FAIL();
    #if !ENABLE_POOL_ALLOCATOR
        return calloc(nmemb, size);
    #else
        void* data = FMallocBinned::getInstance()->Malloc(nmemb * size, DEFAULT_ALIGNMENT);
        ::memset(data, 0, nmemb * size);

        return data;
    #endif
}

static inline void* js_realloc(void* p, size_t bytes)
{
    JS_OOM_POSSIBLY_FAIL();

    #if !ENABLE_POOL_ALLOCATOR
        return realloc(p, bytes);
    #else
        return FMallocBinned::getInstance()->Realloc(p, bytes, DEFAULT_ALIGNMENT);
    #endif
}

static inline void js_free(void* p)
{
    #if !ENABLE_POOL_ALLOCATOR
        free(p);
    #else
        return FMallocBinned::getInstance()->Free(p);
    #endif
}
