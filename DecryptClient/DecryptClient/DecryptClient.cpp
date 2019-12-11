#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include "Base64.h"
#include "AES.h"

int main(int argc, char* argv[])
{
	std::string lpFileName;
	std::string EncryptedString;

	std::vector<std::string> Treasure;

	std::cout << "\n\t--==[[ Fancy Name Decrypter Thingy ]]==--\n" << std::endl;
	if (argc != 2)
	{
		std::cerr << "[!] Usage: " << argv[0] << " EncryptedFile" << std::endl;
		return EXIT_FAILURE;
	}
	else
	{
		lpFileName = argv[1];
	}

	std::ifstream L00T(lpFileName, std::ios::binary);
	if (L00T.is_open())
	{
		while (std::getline(L00T, EncryptedString))
		{
			Treasure.push_back(EncryptedString);
		}
	}
	else
	{
		std::cerr << "[!] Unable to open " << lpFileName << "!" << std::endl;
		return EXIT_FAILURE;
	}

	// Start initializing AES and what not
	AES* DecryptMe = new AES();
	if (!DecryptMe->initialize())
	{
		std::cerr << "[!] Unable to be initialized!" << std::endl;
		return EXIT_FAILURE;
	}

	std::cout << "[+] Reading " << lpFileName << "..." << std::endl;
	for (auto i : Treasure)
	{
		auto decoded = base64::decode(i);

		DecryptMe->CNGDecrypt(i);
		std::cout << "[+] Loot: " << DecryptMe->GetDecryptedString() << std::endl;
	}
	std::cout << "[+] Done!" << std::endl;

	return EXIT_SUCCESS;
}