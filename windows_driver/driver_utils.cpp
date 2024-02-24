#include "driver_utils.h"

// Windows versions
#define WIN_1507 10240
#define WIN_1511 10586
#define WIN_1607 14393
#define WIN_1703 15063
#define WIN_1709 16299
#define WIN_1803 17134
#define WIN_1809 17763
#define WIN_1903 18362
#define WIN_1909 18363
#define WIN_2004 19041
#define WIN_20H2 19042
#define WIN_21H1 19043
#define WIN_21H2 19044
#define WIN_22H2 19045
#define WIN_1121H2 22000
#define WIN_1122H2 22621

ULONG get_token_offset_eprocess()
{
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	RtlGetVersion(&osVersion);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Running on %i", osVersion.dwBuildNumber);

	ULONG tokenOffset = 0;

	switch (osVersion.dwBuildNumber)
	{
	case WIN_1903:
	case WIN_1909:
	{
		tokenOffset = 0x360;
		break;
	}
	case WIN_1507:
	case WIN_1511:
	case WIN_1607:
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
	{
		tokenOffset = 0x358;
		break;
	}
	default:
	{
		tokenOffset = 0x4b8;
		break;
	}
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Token offset: %i", tokenOffset);
	return tokenOffset;
}
