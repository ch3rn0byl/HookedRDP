#pragma once
#include <Windows.h>
#include <bcrypt.h>

#include <vector>

#include "nthelpers.h"

#pragma comment(lib, "Bcrypt.lib")

static const BYTE rgbIV[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const BYTE rgbAES128Key[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

class AES
{
private:
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL; 
protected:
	DWORD cbKeyObject = 0;
	DWORD cbData = 0;
	DWORD cbBlockLen = 0;
	DWORD cbBlob = 0;
	DWORD cbPlainText = 0;
	DWORD cbCipherText = 0;

	PBYTE pbKeyObject = NULL;
	PBYTE pbIV = NULL;
	PBYTE pbBlob = NULL;
	PBYTE pbPlainText = NULL;
	PBYTE pbCipherText = NULL;

	std::string sCipherText;
public:
	AES(){}
	~AES()
	{
		if (hKey != NULL)
		{
			BCryptDestroyKey(hKey);
		}
		if (hAlgorithm != NULL)
		{
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		}
		if (pbKeyObject != NULL)
		{
			delete[] pbKeyObject;
		}
		if (pbIV != NULL)
		{
			delete[] pbIV;
		}
		if (pbBlob != NULL)
		{
			delete[] pbBlob;
		}
		if (pbPlainText != NULL)
		{
			delete[] pbPlainText;
		}
	}

	BOOL initialize()
	{
		// Opens the algorithm handle
		status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Calculates the size of the buffer to hold the KeyObject
		status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&cbKeyObject), sizeof(DWORD), &cbData, 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Allocate the keyobject
		pbKeyObject = new BYTE[cbKeyObject];

		// Get the block length for the IV
		status = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, reinterpret_cast<PBYTE>(&cbBlockLen), sizeof(DWORD), &cbData, 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Determine whether the cbBlockLen is not longer than the IV length
		if (cbBlockLen > sizeof(rgbIV))
		{
			status = STATUS_INVALID_BUFFER_SIZE; 
			return false;
		}

		// Allocates the buffer for the IV. It is needed for the encrypt/decrypt process
		pbIV = new BYTE[cbBlockLen];

		RtlCopyMemory(pbIV, rgbIV, cbBlockLen);

		status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Generate the key from supplied input key bytes
		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pbKeyObject, cbKeyObject, (PBYTE)rgbAES128Key, sizeof(rgbAES128Key), 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Save the copy because its going to get nuked
		status = BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &cbBlob, 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Allocate the buffer to hold the blob
		pbBlob = new BYTE[cbBlob];

		status = BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, pbBlob, cbBlob, &cbBlob, 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}
		return true;
	}

	BOOL CNGEncrypt(std::string EncryptMe)
	{
		cbPlainText = static_cast<DWORD>(EncryptMe.size());
		pbPlainText = new BYTE[cbPlainText];

		RtlCopyMemory(pbPlainText, EncryptMe.c_str(), EncryptMe.size());

		// Get the output buffer size to encrypt
		status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		pbCipherText = new BYTE[cbCipherText];
		status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Destroy the key
		status = BCryptDestroyKey(hKey);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		hKey = NULL;
		return true;
	}

	BOOL CNGDecrypt()
	{
		if (pbPlainText)
		{
			delete[] pbPlainText;
		}

		ZeroMemory(pbKeyObject, cbKeyObject);

		RtlCopyMemory(pbIV, rgbIV, cbBlockLen);

		status = BCryptImportKey(hAlgorithm, NULL, BCRYPT_OPAQUE_KEY_BLOB, &hKey, pbKeyObject, cbKeyObject, pbBlob, cbBlob, 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		// Get the output buffer size
		status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		pbPlainText = new BYTE[cbPlainText];

		status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, pbPlainText, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(status))
		{
			return false;
		}
		return true;
	}

	DWORD GetNTLastError()
	{
		return status;
	}

	PUCHAR GetEncryptedString()
	{
		return pbCipherText;
	}

	std::string GetEncodedString()
	{
		std::string result(reinterpret_cast<const char*>(pbCipherText));

		std::vector<base64::byte> data(std::begin(result), std::end(result));
		auto sCipherText = base64::encode(data);
		return sCipherText;
	}

	PUCHAR GetDecryptedString()
	{
		return pbPlainText;
	}
};

