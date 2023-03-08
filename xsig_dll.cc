#include <map>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef NOMINMAX
#undef WIN32_LEAN_AND_MEAN

#include <xlib/xcrc.h>
#include <xlib/xlog.h>

//////////////////////////////////////////////////////////////// xxlog
class xxlog : public xlib::xlog {
 public:
  virtual ~xxlog() {
    if (gout)
      do_out();
    else
      clear();
  }
  virtual void raw_out(const xlib::xmsg& msg) {
    OutputDebugStringA(msg.toas().c_str());
  }

 public:
  static inline bool gout = true;
};

#define xslog xxlog()
#define xsig_need_debug

#include <xlib/xsig.h>

////////////////////////////////////////////////////////////////
using config_routine = void (*)();

static bool g_make_h = false;
static bool g_make_bin = true;

static const std::map<std::string, config_routine> gk_config_routines = {
    std::pair<std::string, config_routine>(
        ":none", [] {
          xxlog::gout = false;
          xlib::xsig::dbglog = false;
        }),
    std::pair<std::string, config_routine>(
        ":nodbg", [] {
          xxlog::gout = true;
          xlib::xsig::dbglog = false;
        }),
    std::pair<std::string, config_routine>(
        ":dbg", [] {
          xxlog::gout = true;
          xlib::xsig::dbglog = true;
        }),
    std::pair<std::string, config_routine>(
        ":simple", [] {
          xlib::xsig::exmatch = false;
        }),
    std::pair<std::string, config_routine>(
        ":advance", [] {
          xlib::xsig::exmatch = true;
        }),
    std::pair<std::string, config_routine>(
        ":makeh", [] {
          g_make_h = true;
        }),
};

static xlib::xsig::Blks GetPEImage(const wchar_t* const mod_name) {
  xdbg << "get pe image : " << mod_name;
  const auto hMod = GetModuleHandleW(mod_name);
  xdbg << "             : " << hMod;
  if (nullptr == hMod) return xlib::xsig::Blks();

  const auto& dos = *(const IMAGE_DOS_HEADER*)hMod;
  const auto& pe  = *(const IMAGE_NT_HEADERS*)((size_t)&dos + (size_t)dos.e_lfanew);
  return xlib::xsig::check_blk(xlib::xblk((const void*)hMod, (intptr_t)pe.OptionalHeader.SizeOfImage));
}

static xlib::xsig::Blks dosets(
    const std::shared_ptr<xlib::xsig::Lexical::Sets>& sets) {
  xlib::xsig::Blks main_blks;
  for (const auto& v : sets->_cfgs) {
    auto it = gk_config_routines.find(v);
    if (gk_config_routines.end() == it) {
      xerr << "unknown config " << v;
      continue;
    }
    (it->second)();
    continue;
  }

  for (const auto& v : sets->_blks) {
    const auto blks = xlib::xsig::check_blk(v);
    for (const auto& vv : blks) {
      main_blks.push_back(vv);
    }
  }

  for (const auto& v : sets->_mods) {
    const auto blks = GetPEImage(xlib::u82ws(*(const std::u8string*)&v).data());
    for (const auto& vv : blks) {
      main_blks.push_back(vv);
    }
  }
  return main_blks;
}

extern "C" {
__declspec(dllexport) int match(const wchar_t* const sig_file);
}

class sig_value_array {
 public:
  static inline constexpr uint64_t values[] = {
    0, 0
  };
};

int match(const wchar_t* const sig_file) {
  try {
    g_make_h = false;

    xdbg << "xsig dll match...";
    if (nullptr == sig_file) return __LINE__;

    xdbg << "xsig dll read...";
    // 特征码文件读取、分段。
    const auto sigs = xlib::xsig::read_sig_file(std::wstring(sig_file));
    if (sigs.empty()) return __LINE__;

    xdbg << "xsig dll main pe...";
    // 默认匹配范围是主模块的 Image 。
    xlib::xsig::Blks main_blks = GetPEImage(nullptr);
    if (main_blks.empty()) return __LINE__;

    xdbg << "xsig dll main pe :";
    for (const auto& blk : main_blks) {
      xdbg << "  " << blk.begin() << " ~ " << blk.end();
    }

    xlib::xsig::Reports main_reps;

    for (const auto& v : sigs) {
      xdbg << "================================";
      // 特征码转换成 xsig 。
      xlib::xsig sig;
      if (!sig.make_lexs(v.data())) {
        xerr << XTEXT("xsig make_lexs fail !");
        xerr << v;
        continue;
      }

      const auto sets = sig.get_sets();
      if (sets) {
        const auto blks = dosets(sets);
        if (!blks.empty()) {
          main_blks.clear();
          xdbg << "xsig dll change :";
          for (const auto& blk : blks) {
            xdbg << "  " << blk.begin() << " ~ " << blk.end();
            main_blks.push_back(blk);
          }
        }
        continue;
      }

      bool matched = false;
      for(const auto& blk : main_blks) {
        if(!sig.match({blk})) continue;
        matched = true;
        break;
      }

      if (!matched) {
        xerr << XTEXT("xsig match fail !");
        xerr << v;
        continue;
      }

      const auto reps = sig.report(main_blks.at(0).begin());
      for (const auto& vv : reps) {
        auto it = main_reps.find(vv.first);
        if (main_reps.end() == it) {
          xdbg << "   " << vv.second.q << " : " << vv.first;
          main_reps.insert(vv);
          continue;
        }
        if (it->second.q == vv.second.q) {
          xdbg << " - " << vv.second.q << " : " << vv.first;
          continue;
        }
        xdbg << " x " << vv.second.q << " " << it->second.q << " : " << vv.first;
      }
    }

    if (main_reps.empty()) return 0;

    if (!g_make_h) return 0;
    
    const auto hfile = std::wstring(sig_file) + L".h";
    xdbg << "write : " << hfile << " ...";
    std::ofstream file;
    file.open(hfile, std::ios_base::out | std::ios_base::binary);


    xlib::xmsg m;
    m << "#ifndef _sig_value_array_H_\n"
         "#define _sig_value_array_H_\n\n"
         "class sig_value_array {\n"
         " public:\n"
         "  static inline constexpr uint64_t values[] = {\n";
    
    file.write((const char*)m.data(), m.size());
    for (const auto& v : main_reps) {
      m.clear();
      const auto h = xlib::crc64(v.first) + xlib::crc32(v.first);
      m << "    0x" << h << ", 0x" << v.second.q << ", // " << v.first << "\n";
      file.write((const char*)m.data(), m.size());
    }

    m.clear();
    m << "  };\n};";
    file.write((const char*)m.data(), m.size());

    file.close();
    xdbg << "write : " << hfile << " done.";
    return 0;
  } catch (...) {
    xerr << XTEXT("match exception !");
    return -1;
  }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  UNREFERENCED_PARAMETER(hModule);
  UNREFERENCED_PARAMETER(lpReserved);
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      OutputDebugStringA("xsig load.");
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      OutputDebugStringA("xsig free.");
      break;
  }
  return TRUE;
}