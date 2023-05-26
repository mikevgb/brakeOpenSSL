import time
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

encryptAlgos = [
    'AES-128-CBC', 'AES-128-CFB', 'AES-128-CFB1', 'AES-128-CFB8', 'AES-128-CTR',
    'AES-128-ECB', 'AES-128-GCM', 'AES-128-OFB', 'AES-128-XTS',
    'AES-192-CBC', 'AES-192-CFB', 'AES-192-CFB1', 'AES-192-CFB8', 'AES-192-CTR',
    'AES-192-ECB', 'AES-192-GCM', 'AES-192-OFB',
    'AES-256-CBC', 'AES-256-CFB', 'AES-256-CFB1', 'AES-256-CFB8', 'AES-256-CTR',
    'AES-256-ECB', 'AES-256-GCM', 'AES-256-OFB', 'AES-256-XTS',
    'BF', 'BF-CBC', 'BF-CFB', 'BF-ECB', 'BF-OFB', 'BLOWFISH',
    'CAMELLIA-128-CBC', 'CAMELLIA-128-CFB', 'CAMELLIA-128-CFB1',
    'CAMELLIA-128-CFB8', 'CAMELLIA-128-ECB', 'CAMELLIA-128-OFB',
    'CAMELLIA-192-CBC', 'CAMELLIA-192-CFB', 'CAMELLIA-192-CFB1',
    'CAMELLIA-192-CFB8', 'CAMELLIA-192-ECB', 'CAMELLIA-192-OFB',
    'CAMELLIA-256-CBC', 'CAMELLIA-256-CFB', 'CAMELLIA-256-CFB1',
    'CAMELLIA-256-CFB8', 'CAMELLIA-256-ECB', 'CAMELLIA-256-OFB',
    'CAST', 'CAST-CBC', 'CAST5-CBC', 'CAST5-CFB', 'CAST5-ECB', 'CAST5-OFB',
    'DES', 'DES-CBC', 'DES-CFB', 'DES-CFB1', 'DES-CFB8', 'DES-ECB', 'DES-EDE',
    'DES-EDE-CBC', 'DES-EDE-CFB', 'DES-EDE-OFB', 'DES-EDE3', 'DES-EDE3-CBC',
    'DES-EDE3-CFB', 'DES-EDE3-CFB1', 'DES-EDE3-CFB8', 'DES-EDE3-OFB',
    'DES-OFB', 'DES3', 'DESX', 'DESX-CBC',
    'ID-AES128-GCM', 'ID-AES192-GCM', 'ID-AES256-GCM',
    'RC2', 'RC2-40-CBC', 'RC2-64-CBC', 'RC2-CBC', 'RC2-CFB', 'RC2-ECB', 'RC2-OFB',
    'RC4', 'RC4-40', 'RC4-HMAC-MD5',
    'SEED', 'SEED-CBC', 'SEED-CFB', 'SEED-ECB', 'SEED-OFB'
]

digestAlgos = [
    'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'blake2b', 'blake2s', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
    'shake_128', 'shake_256', 'sha512_224', 'sha512_256', 'sm3'
]

def readPassFromDir(passDir):
    passwords = []
    for root, _, files in os.walk(passDir):
        for file in files:
            fPath = os.path.join(root, file)
            with open(fPath, 'r', encoding='utf-8', errors='ignore') as f:
                passwords.extend(line.strip() for line in f.readlines())
    print("Passwords loaded!")
    return passwords

def extractSalt(encryptedData):
    salt = encryptedData[:8]
    data = encryptedData[8:]
    return salt, data

def decryptFile(fPath, passwords):
    with open(fPath, 'rb') as file:
        encryptedData = file.read()

    salt, encryptedData = extractSalt(encryptedData)

    for algoName in encryptAlgos:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Encryption: {algoName}")
        for digestName in digestAlgos:
            try:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] Digest: {digestName}")
                passFound = False
                for password in passwords:
                    try:
                        key = password.encode() + digestName.encode()
                        cipher = AES.new(key, AES.MODE_CBC, salt)
                        decryptedData = Padding.unpad(cipher.decrypt(encryptedData), 16)
                        print(f"Decryption successful with algorithm: {algoName} and digest: {digestName}")
                        passFound = True
                        if passFound == True:
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            print(f"[{timestamp}] Password found! {password} Encryption: {algoName} Digest: {digestName}")
                        break
                    except ValueError:
                        pass

                if passFound:
                    return decryptedData

            except Exception as e:
                print(f"Error decrypting with {algoName} and {digestName}: {str(e)}")

    print("Decryption unsuccessful with all algorithms and digests.")
    return None

if __name__ == "__main__":
    fPath = './test.enc'
    passDir = './dicc_s'

    passwords = readPassFromDir(passDir)

    decryptedData = decryptFile(fPath, passwords)
    if decryptedData:
        outFile = os.path.splitext(fPath)[0] + "_decrypted.txt"
        with open(outFile, 'wb') as file:
            file.write(decryptedData)
        print(f"Decrypted data saved to {outFile}")

