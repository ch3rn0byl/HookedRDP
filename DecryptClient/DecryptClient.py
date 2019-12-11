import argparse
import binascii
import base64
import sys
try:
    from Crypto.Cipher import AES
    import Crypto.Cipher.AES
except ModuleNotFoundError as e:
    print('[!] {}'.format(e))
    sys.exit(-1)

key = binascii.unhexlify(b'000102030405060708090a0b0c0d0e0f')
IV = binascii.unhexlify(b'000102030405060708090a0b0c0d0e0f')

if not sys.version_info.major == 3:
    print('[!] This was written in Python3!')
    sys.exit(0)

def main(arguments):
    lpFileName = arguments.f

    print('\n\t--==[[ Fancy Name Decrypter Thingy ]]==--\n')
    print('[+] Reading {}...'.format(lpFileName))
    with open(lpFileName) as file:
        loot = file.readlines()

    decipher = AES.new(key, AES.MODE_CBC, IV)

    for item in loot:
        if item.endswith('\n'):
            item = item.strip()
        item = base64.b64decode(item)
        print('[+] Loot: {}'.format(decipher.decrypt(item)))
    print('[+] Done!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='This decrypts the file given for clear text credentials',
        epilog='Please use responsibly for evil, hehehe'
    )
    parser.add_argument('-f', metavar='file', help='The file with encrypted content', required=True)
    args = parser.parse_args()
    main(args)