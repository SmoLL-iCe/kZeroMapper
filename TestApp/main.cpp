#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <Windows.h>

#include <kZeroMapper/kZeroMapper.h>

namespace fs = std::filesystem;

void LogCallback(const char* message)
{
    std::cout << "[kZeroMapper] " << message << std::endl;
}

std::vector<uint8_t> ReadFileBuffer(const fs::path& filePath)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        return {};

    const auto fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    return buffer;
}

int main(int argc, char* argv[])
{
    std::cout << "=================================================" << std::endl;
    std::cout << "       kZeroMapper - Test Harness App" << std::endl;
    std::cout << "=================================================" << std::endl;

    kZeroMapper::SetLogCallback(LogCallback);

    fs::path driverPath;
    if (argc > 1)
    {
        driverPath = argv[1];
    }
    else
    {
        // Search default paths for TestDriver.sys
        char exePathBuf[MAX_PATH];
        GetModuleFileNameA(NULL, exePathBuf, MAX_PATH);
        fs::path exeDir = fs::path(exePathBuf).parent_path();

        std::vector<fs::path> candidatePaths = {
            exeDir / "TestDriver.sys",
            fs::current_path() / "TestDriver.sys",
            exeDir / ".." / "Release" / "TestDriver.sys",
            exeDir / ".." / "Debug" / "TestDriver.sys"
        };

        for (const auto& candidate : candidatePaths)
        {
            if (fs::exists(candidate))
            {
                driverPath = candidate;
                break;
            }
        }
    }

    if (driverPath.empty() || !fs::exists(driverPath))
    {
        std::cerr << "[-] Driver file not found!" << std::endl;
        std::cout << "[*] Usage: TestApp.exe [path_to_driver.sys]" << std::endl;
        std::cout << "[*] Please build TestDriver first or specify a valid .sys file." << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] Found test driver: " << driverPath.string() << std::endl;
    auto driverBuffer = ReadFileBuffer(driverPath);
    if (driverBuffer.empty())
    {
        std::cerr << "[-] Failed to read driver file into buffer!" << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] Read " << driverBuffer.size() << " bytes from driver file." << std::endl;
    std::cout << "[*] Mapping driver using kZeroMapper..." << std::endl;

    const NTSTATUS status = kZeroMapper::MapDriver( 
        kZeroMapper::MapperProvider::RTCore64, 
        driverBuffer.data( ),
        driverBuffer.size( ), 
        kZeroMapper::KernelAllocationMode::Pool, 
        false );

    //const NTSTATUS status = kZeroMapper::MapDriver(
    //    driverBuffer.data(),
    //    driverBuffer.size(),
    //    false // bClean
    //);

    std::cout << "-------------------------------------------------" << std::endl;
    if (status == 0) // STATUS_SUCCESS
    {
        std::cout << "[+] Driver mapped successfully! Status: 0x0 (STATUS_SUCCESS)" << std::endl;
    }
    else
    {
        std::cout << "[-] Driver mapping failed! Status: 0x" << std::hex << status << std::dec << std::endl;
        std::cout << "[-] Last status: 0x" << std::hex << kZeroMapper::GetLastStatus() << std::dec << std::endl;
        std::cout << "[-] Status2: 0x" << std::hex << kZeroMapper::GetStatus2() << std::dec << std::endl;
    }
    std::cout << "-------------------------------------------------" << std::endl;

    system("pause");
    return (status == 0) ? 0 : 1;
}
