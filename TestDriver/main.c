#include <ntddk.h>
#include <ntstrsafe.h>

static VOID LogToFile(const char* message)
{
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;

    RtlInitUnicodeString(&filePath, L"\\??\\C:\\TestDriver.log");

    InitializeObjectAttributes(
        &objAttr,
        &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    NTSTATUS status = ZwCreateFile(
        &fileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[kZeroMapper] TestDriver: Failed to open/create log file. Status: 0x%08X\n", status);
        return;
    }

    size_t length = 0;
    status = RtlStringCbLengthA(message, 1024, &length);
    if (NT_SUCCESS(status) && length > 0)
    {
        status = ZwWriteFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            (PVOID)message,
            (ULONG)length,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[kZeroMapper] TestDriver: Failed to write to log file. Status: 0x%08X\n", status);
        }
    }

    ZwClose(fileHandle);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    LARGE_INTEGER systemTime;
    LARGE_INTEGER localTime;
    TIME_FIELDS timeFields;

    KeQuerySystemTime(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    RtlTimeToTimeFields(&localTime, &timeFields);

    char logBuffer[512];
    RtlStringCbPrintfA(
        logBuffer,
        sizeof(logBuffer),
        "[%04hd-%02hd-%02hd %02hd:%02hd:%02hd.%03hd] [kZeroMapper] Hello World from TestDriver! DriverEntry executed successfully.\r\n",
        timeFields.Year,
        timeFields.Month,
        timeFields.Day,
        timeFields.Hour,
        timeFields.Minute,
        timeFields.Second,
        timeFields.Milliseconds
    );

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", logBuffer);

    LogToFile(logBuffer);

    return STATUS_SUCCESS;
}

