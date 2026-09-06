#pragma once
#include "MapperBackend.h"
#include <type_traits>

enum class KernelCallGate
{
	TableSwap,       // NtUserSetGestureConfig (vtable / dispatch table pointer swap, no RX modification required)
	NtQueryAtom      // NtQueryInformationAtom (jump stub patch in ntoskrnl, requires RX modification)
};

class KernelRwCallBackend : public IMapperBackend
{
public:
	NTSTATUS Load( ) override;
	NTSTATUS Unload( ) override;
	bool Clean( ) override;
	NTSTATUS Execute( uint8_t* shellCode, uint32_t codeSize ) override;
	void SetAllocationMode( KernelAllocationMode mode );

	void SetCallGate( KernelCallGate gate );
	KernelCallGate GetCallGate( ) const;

	uint64_t ResolveNtUserSetGestureConfigRef( );
	uint64_t ResolveNtUserSetGestureConfigRefFromSessionState( uint64_t win32k, uint64_t ntUserSetGestureConfigFull );
	uint64_t GetNtUserSetGestureConfigRef( ) const { return m_NtUserSetGestureConfigRef; }

	bool PrepareKernelCallGestureConfig( uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize );
	bool RestoreKernelCallGestureConfig( uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize );

	bool PrepareKernelCallAtom( uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize );
	bool RestoreKernelCallAtom( uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize );

	virtual bool PrepareKernelCall( uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize );
	virtual bool RestoreKernelCall( uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize );

	friend class KernelClean;
	friend class KernelCleanImpl;
protected:
	virtual NTSTATUS LoadDevice( ) = 0;
	virtual NTSTATUS UnloadDevice( ) = 0;
	virtual bool ReadMemory( uint64_t address, void* buffer, size_t size ) = 0;
	virtual bool WriteMemory( uint64_t address, const void* buffer, size_t size ) = 0;

	virtual bool WriteToReadOnlyMemory( uint64_t address, const void* buffer, size_t size );

	uint64_t GetKernelModuleExport( uint64_t kernelModuleBase, const char* functionName );
	uint64_t AllocatePool( POOL_TYPE poolType, uint64_t size );
	bool FreePool( uint64_t address );
	uint64_t AllocIndependentPages( uint32_t size );
	bool FreeIndependentPages( uint64_t address, uint32_t size );
	bool MmSetPageProtection( uint64_t address, uint32_t size, ULONG protect );
	uint64_t MmAllocateIndependentPagesEx( uint32_t size );
	uint64_t ResolveRelativeAddress( uint64_t instruction, ULONG offsetOffset, ULONG instructionSize );
	uint64_t FindSection( const char* sectionName, uint64_t moduleBase, ULONG* sectionSize );
	uint64_t FindPattern( uint64_t address, size_t size, const char* pattern, const char* mask );
	uint64_t FindPatternInSection( const char* sectionName, uint64_t moduleBase, const char* pattern, const char* mask );
	bool FindPatternInSectionAll( const char* sectionName, uint64_t moduleBase, const char* pattern, const char* mask, uint64_t* results, size_t maxResults, size_t* resultCount );
	uint64_t FindCallInRange( uint64_t address, size_t size );

	template<typename T, typename ...A>
	bool CallKernelFunction( T* outResult, uint64_t kernelFunctionAddress, const A... arguments )
	{
		constexpr auto callVoid = std::is_same_v<T, void>;

		if constexpr ( !callVoid )
		{
			if ( !outResult )
				return false;
		}
		else
		{
			UNREFERENCED_PARAMETER( outResult );
		}

		if ( !kernelFunctionAddress || !m_Ntoskrnl )
			return false;

		void* userFunction = nullptr;
		uint64_t restoreAddress = 0;
		uint8_t originalBytes[ 16 ] {};
		size_t originalSize = 0;

		if ( !PrepareKernelCall( kernelFunctionAddress, &userFunction, &restoreAddress, originalBytes, &originalSize ) )
			return false;

		if constexpr ( !callVoid )
		{
			using FunctionFn = T( __stdcall* )( A... );
			const auto function = r_cast<FunctionFn>( userFunction );
			*outResult = function( arguments... );
		}
		else
		{
			using FunctionFn = void( __stdcall* )( A... );
			const auto function = r_cast<FunctionFn>( userFunction );
			function( arguments... );
		}

		if ( !RestoreKernelCall( restoreAddress, originalBytes, originalSize ) )
			return false;

		return true;
	}

	HANDLE m_Device = INVALID_HANDLE_VALUE;
	uint64_t m_Ntoskrnl = 0;
	uint64_t m_NtUserSetGestureConfigRef = 0;
	KernelCallGate m_CallGate = KernelCallGate::TableSwap;
	KernelAllocationMode m_AllocationMode = KernelAllocationMode::Pool;
	uint64_t m_MmAllocateIndependentPagesEx = 0;
	uint64_t m_MmFreeIndependentPages = 0;
	uint64_t m_MmSetPageProtection = 0;
};

namespace kZeroMapper
{
	inline uint64_t ResolveNtUserSetGestureConfigRef( KernelRwCallBackend& backend )
	{
		return backend.ResolveNtUserSetGestureConfigRef( );
	}

	inline bool PrepareKernelCallGestureConfig( KernelRwCallBackend& backend, uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize )
	{
		return backend.PrepareKernelCallGestureConfig( kernelFunctionAddress, userFunction, restoreAddress, originalBytes, originalSize );
	}

	inline bool RestoreKernelCallGestureConfig( KernelRwCallBackend& backend, uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize )
	{
		return backend.RestoreKernelCallGestureConfig( restoreAddress, originalBytes, originalSize );
	}

	inline bool PrepareKernelCallAtom( KernelRwCallBackend& backend, uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize )
	{
		return backend.PrepareKernelCallAtom( kernelFunctionAddress, userFunction, restoreAddress, originalBytes, originalSize );
	}

	inline bool RestoreKernelCallAtom( KernelRwCallBackend& backend, uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize )
	{
		return backend.RestoreKernelCallAtom( restoreAddress, originalBytes, originalSize );
	}

	inline bool PrepareKernelCall( KernelRwCallBackend& backend, uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize )
	{
		return backend.PrepareKernelCall( kernelFunctionAddress, userFunction, restoreAddress, originalBytes, originalSize );
	}

	inline bool RestoreKernelCall( KernelRwCallBackend& backend, uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize )
	{
		return backend.RestoreKernelCall( restoreAddress, originalBytes, originalSize );
	}
}

