#ifndef _XIT_H_
#define _XIT_H_

// 注意：对 PE 结构没有做 严格的合法性 检查。
// 注意：请在加上编译选项： /EHa ，以使 Windows 异常能被 c++ 异常捕获。
// 为保持兼容性，特意不使用类，为记。

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static_assert(sizeof(size_t) == sizeof(void*), "size_t != void*");

namespace xit
  {
////////////////////////////////////////////////////////////////
enum ERROR_ENUM
  {
  XSuccess,
  XOpenProcessToken,
  XLookupPrivilegeValue,
  XAdjustTokenPrivileges,
  XCreateToolhelp32Snapshot,
  XProcess32First,
  XGetPID,
  XGetModule,
  XCreateFile,
  XGetFileSizeEx,
  XLoadFile,
  XLoadFileLocalAlloc,
  XLoadFileLocalLock,
  XReadFile,
  XLocalAlloc,
  XLocalLock,
  XDecode,
  XFindResource,
  XLoadResource,
  XLockResource,
  XSizeofResource,
  XVirtualAllocEx,
  XMappingLock,
  XMappingHeader,
  XMappingSection,
  XMapping,
  XOpenProcess,
  XCreateRemoteThread,
  XWaitForSingleObject_timeout,
  XWaitForSingleObject_fail,
  XGetExitCodeThread,
  XRemoteThread,
  XDoShellcodeNew,
  XWriteProcessMemory,
  XReadProcessMemory,
  XImportDLL,
  XSetImageBase,
  XNoExport,
  XIndex,
  XNoFind,
  XNoMod,
  XGetModuleHandleA,
  XGetProcAddress,
  XLocalDllProcAddr,
  };

typedef unsigned long long Result;

static_assert(8 == sizeof(Result),      "8 != ull");
static_assert(4 == sizeof(ERROR_ENUM),  "4 != enum");
static_assert(4 == sizeof(DWORD),       "4 != dword");

/// 获得 XIT_ERROR_ENUM 错误码。
ERROR_ENUM Error(const Result res);
/// 获得 GetLastError 错误码。
DWORD ErrorEx(const Result res);
/// 检测是否存在错误码。
bool IsOK(const Result res);

/// 进程提权。
Result UpperToken(HANDLE hProcess = GetCurrentProcess());

/// 指定 PID 或 进程名，获取 PID 。成功则返回 DWORD 。
Result GetPID(LPCTSTR pid);

/// 指定 HMOUDLE 。成功则返回 HMOUDLE 。
Result GetModule(LPCTSTR hmod);

/// 不加密，仅仅是简单 COPY 。
bool NoDecode(LPVOID BIN, LPVOID SRC, const size_t size);

/// 解密函数。
using Decode_Function = bool(*)(LPVOID BIN, LPVOID SRC, const size_t size);

/// 指定加载文件。成功则返回 HLOCAL。
Result LoadFile(LPCTSTR lpFileName, Decode_Function Decode = &NoDecode);

/// 指定加载资源。成功则返回 HLOCAL。
Result LoadRes(HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode = &NoDecode);

/// 平铺 DLL 。成功则返回 LPVOID 。
Result Mapping(HANDLE hProcess, LPVOID BIN);

/// 打开进程。成功则返回 HANDLE 。
Result OpenProcess(const DWORD PID);
Result OpenProcess(LPCTSTR pid);

// 注意：以下函数，传入的句柄，都不主动释放。

/// 执行远程线程。成功则返回 线程 DWORD 。
Result RemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, LPVOID lpParam);

/// 指定加载 DLL 。成功则返回 PE 。注意：PE 需已 Mapping 。
Result LoadDll(HANDLE hProcess, LPVOID PE);

/// 指定加载文件为 DLL 。成功则返回 LPVOID 。
Result LoadDll(HANDLE hProcess, LPCTSTR lpFileName, Decode_Function Decode = &NoDecode);
Result LoadDll(LPCTSTR pid, LPCTSTR lpFileName, Decode_Function Decode = &NoDecode);

/// 指定加载资源为 DLL 。成功则返回 LPVOID 。
Result LoadDll(HANDLE           hProcess,
               HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode = &NoDecode);
Result LoadDll(LPCTSTR          pid,
               HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode = &NoDecode);

struct UnloadDllST
  {
  Result tls;
  Result main;
  Result import;
  Result ex;
  };

/// 指定卸载 DLL 。
UnloadDllST UnloadDll(HANDLE hProcess, LPVOID PE, const bool release_pe = true);
/// 指定卸载 DLL 。
UnloadDllST UnloadDll(LPCTSTR pid, LPVOID PE);

/// 本地查找指定模块的导出函数。
Result LocalDllProcAddr(LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false);

/// 远程查找指定模块的导出函数。
Result RemoteDllProcAddr(HANDLE hProcess, LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false);
////////////////////////////////////////////////////////////////
  }

#endif  //_XIT_H_