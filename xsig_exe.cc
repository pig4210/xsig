#include <conio.h>

#include <iostream>
#include <string>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef NOMINMAX
#undef WIN32_LEAN_AND_MEAN

#include <xit/xit.h>

#include <xlib/xcrc.h>
#include <xlib/xlog.h>

//////////////////////////////////////////////////////////////// xxlog
class xxlog : public xlib::xlog {
 public:
  virtual ~xxlog() {
    do_out();
  }
  virtual void raw_out(const xlib::xmsg& msg) {
    std::cout << msg.toas() << std::endl;
  }
};

#define xslog xxlog()
#define xsig_need_debug

#include <xlib/xsig.h>

static bool CheckOK(const xit::Result& res) {
  if (xit::IsOK(res)) return true;
  std::cout << "There is Error :" << std::endl;
  std::cout << "    " << (void*)xit::Error(res) << '(' << xit::Error(res) << ')'
            << std::endl;
  std::cout << "    " << (void*)(size_t)xit::ErrorEx(res) << '('
            << xit::ErrorEx(res) << ')' << std::endl;
  return false;
}

int wmain(int argc, LPCTSTR argv[]) {
  if (argc <= 1 || argc > 3) {
    std::cout << " Usage : xsig   process   sig_file";
    std::cout << " Usage : xsig   sig_file";
    return 0;
  }

  // 只是提供 sig_file ，就生成 sig_bin 。
  if (argc == 2) {
    std::cout << "xsig dll read..." << std::endl;
    // 特征码文件读取、分段。
    const auto sigs = xlib::xsig::read_sig_file(std::wstring(argv[1]));
    if (sigs.empty()) {
      std::cout << "xsig dll read fail !" << std::endl;
      return 0;
    }

    xlib::vbin bins;
    for (const auto& v : sigs) {
      xlib::xsig sig;
      if (!sig.make_lexs(v.data())) {
        std::cout << "xsig make_lexs fail !" << std::endl;
        std::cout << v << std::endl;
        return 0;
      }
      
      bins.append(sig.to_bin());
    }
    
    const auto bin = std::wstring(argv[1]) + L".bin";
    std::wcout << L"write : " << bin << L" ..." << std::endl;
    std::ofstream file;
    file.open(bin, std::ios_base::out | std::ios_base::binary);
    file.write((const char*)bins.data(), bins.size());
    file.close();
    std::wcout << L"write : " << bin << L" done." << std::endl;
    return 0;
  }
  xit::UpperToken();  // 无论是否提权成功，都尝试继续。

  auto res = xit::OpenProcess(argv[1]);
  if (!CheckOK(res)) return 0;
  auto hProcess = (HANDLE)res;

  size_t size = 0;
  while (TEXT('\0') != argv[2][size]) ++size;
  ++size;
  size *= sizeof(TCHAR);
  auto shellcode =
      VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
  if (nullptr == shellcode) {
    std::cout << "create sig_file error : " << GetLastError();
    CloseHandle(hProcess);
    return 0;
  }
  if (FALSE ==
      WriteProcessMemory(hProcess, shellcode, &argv[2][0], size, nullptr)) {
    std::cout << "create sig_file error : " << GetLastError();
    VirtualFreeEx(hProcess, shellcode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
  }

  res = xit::LoadFile(TEXT("xsig.dll"));

  if (!CheckOK(res)) {
    VirtualFreeEx(hProcess, shellcode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
  }
  auto hMem = (HLOCAL)res;
  res = xit::Mapping(hProcess, hMem);
  if (!CheckOK(res)) {
    LocalFree(hMem);
    VirtualFreeEx(hProcess, shellcode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
  }

  LocalFree(hMem);
  auto PE = (LPVOID)res;

  res = xit::LoadDll(hProcess, PE);
  if (!CheckOK(res)) {
    VirtualFreeEx(hProcess, shellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
  }

  res = xit::RemoteDllProcAddr(hProcess, PE, "match", false);
  std::cout << (void*)res << std::endl;
  if (CheckOK(res)) {
    auto ps = (LPTHREAD_START_ROUTINE)res;
    res = xit::RemoteThread(hProcess, ps, shellcode);
    if (xit::IsOK(res)) CloseHandle((HANDLE)res);
  }

  std::cout << "Press any key to free dll..." << std::endl;
  _getch();

  VirtualFreeEx(hProcess, shellcode, 0, MEM_RELEASE);
  const auto st = xit::UnloadDll(hProcess, PE, true);

  CloseHandle(hProcess);

  CheckOK(st.tls);
  CheckOK(st.main);
  CheckOK(st.import);
  CheckOK(st.ex);

  std::cout << "Done." << std::endl;
  _getch();
  return 0;
}