#include "utils.hpp"
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>
#include <vector>
#include <sys/sysctl.h>
#include <cstdint>
#include <cstdio>
uint64_t g_eboot_address = 0;  // 定义或改为extern如果在其他地方定义
extern "C"     int sceKernelGetProcessName(int pid, char *out);
void write_log(const char* text)
{
	int text_len = printf("%s", text);
	int fd = open("/data/etaHEN/disabler_plugin.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
	if (fd < 0)
	{
		return;
	}
	write(fd, text, text_len);
	close(fd);
}

void plugin_log(const char* fmt, ...)
{
	char msg[0x1000]{};
	va_list args;
	va_start(args, fmt);
	int msg_len = vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	// Append newline at the end
	if (msg[msg_len-1] == '\n')
	{
		write_log(msg);
	}
	else
	{
	     strcat(msg, "\n");
	     write_log(msg);
	}
}


char backupShellCoreBytes[5] = {0};
uint64_t shellcore_offset_patch = 0;

static uint32_t pattern_to_byte(const char *pattern, uint8_t *bytes) {
  uint32_t count = 0;
  const char *start = pattern;
  const char *end = pattern + strlen(pattern);

  for (const char *current = start; current < end; ++current) {
    if (*current == '?') {
      ++current;
      if (*current == '?') {
        ++current;
      }
      bytes[count++] = -1;
    } else {
      bytes[count++] = strtoul(current, (char **)&current, 16);
    }
  }
  return count;
}
void write_bytes32(pid_t pid, uint64_t addr, const uint32_t val) {
  plugin_log("addr: 0x%lx", addr);
  plugin_log("val: 0x%08x", val);
  dbg::write(pid, addr, (void *)&val, sizeof(uint32_t));
}

// valid hex look up table.
const uint8_t hex_lut[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

__attribute__((noinline)) static uint8_t *hexstrtochar2(const char *hexstr,
                                                        size_t *size) {
  if (!hexstr || *hexstr == '\0' || !size || *size < 0) {
    return nullptr;
  }
  uint32_t str_len = strlen(hexstr);
  size_t data_len = ((str_len + 1) / 2) * sizeof(uint8_t);
  *size = (str_len) * sizeof(uint8_t);
  uint8_t *data = (uint8_t *)malloc(*size);
  if (!data) {
    return nullptr;
  }
  uint32_t j = 0; // hexstr position
  uint32_t i = 0; // data position

  if (str_len % 2 == 1) {
    data[i] = (uint8_t)(hex_lut[0] << 4) | hex_lut[(uint8_t)hexstr[j]];
    j = ++i;
  }

  for (; j < str_len; j += 2, i++) {
    data[i] = (uint8_t)(hex_lut[(uint8_t)hexstr[j]] << 4) |
              hex_lut[(uint8_t)hexstr[j + 1]];
  }

  *size = data_len;
  return data;
}
void write_bytes(pid_t pid, uint64_t addr, const char *hexString) {
  uint8_t *byteArray = nullptr;
  size_t bytesize = 0;
  byteArray = hexstrtochar2(hexString, &bytesize);
  if (!byteArray) {
    return;
  }
  plugin_log("addr: 0x%lx", addr);
  dbg::write(pid, addr, byteArray, bytesize);

  dbg::read(pid, addr, byteArray, bytesize);
  if (byteArray) {
    plugin_log("freeing byteArray at 0x%p", byteArray);
    free(byteArray);
  }
}
uint8_t *PatternScan(const uint64_t module_base, const uint64_t module_size,
                     const char *signature) {
  plugin_log("module_base: 0x%lx module_size: 0x%lx", module_base, module_size);
  if (!module_base || !module_size) {
    return nullptr;
  }

  uint8_t patternBytes[256];
  (void)memset(patternBytes, 0, 256);
  int32_t patternLength = pattern_to_byte(signature, patternBytes);
  if (patternLength <= 0 || patternLength >= 256) {
    plugin_log("Pattern length too large or invalid! %i (0x%08x)",
               patternLength, patternLength);
    plugin_log("Input Pattern %s", signature);
    return nullptr;
  }
  uint8_t *scanBytes = (uint8_t *)module_base;
  for (uint64_t i = 0; i < module_size; ++i) {
    bool found = true;
    for (int32_t j = 0; j < patternLength; ++j) {
      if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != 0xff) {
        found = false;
        break;
      }
    }
    if (found) {
      plugin_log("found pattern at 0x%p", &scanBytes[i]);
      return &scanBytes[i];
    }
  }
  return nullptr;
}

static std::vector<int32_t> PatternToByte(const std::string& pattern) {
    std::vector<int32_t> bytes;
    const char* start = pattern.data();
    const char* end = start + pattern.size();

    for (const char* current = start; current < end; ++current) {
        if (*current == '?') {
            ++current;
            if (*current == '?')
                ++current;
            bytes.push_back(-1);
        } else {
            bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
        }
    }

    return bytes;
}

uint8_t* PatternScanNew(const std::string& signature, const uint64_t g_eboot_image_size) {
    plugin_log(" module_size: 0x%lx", g_eboot_image_size);
    
    std::vector<int32_t> patternBytes = PatternToByte(signature);
    const uint8_t* scanBytes = reinterpret_cast<const uint8_t*>(g_eboot_address);
    
    const int32_t* sigPtr = patternBytes.data();
    const size_t sigSize = patternBytes.size();

    for (size_t i = 0; i < g_eboot_image_size - sigSize; ++i) {
        bool found = true;
        
        for (size_t j = 0; j < sigSize; ++j) {
            if (sigPtr[j] != -1 && scanBytes[i + j] != static_cast<uint8_t>(sigPtr[j])) {
                found = false;
                break;
            }
        }

        if (found) {
            return const_cast<uint8_t*>(&scanBytes[i]);
        }
    }

    return nullptr;
}

pid_t g_ShellCorePid = 0;

static pid_t find_pid(const char *name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if (sysctl(mib, 4, 0, &buf_size, 0, 0)) {
      perror("sysctl");
      return -1;
  }

  if (!(buf = (uint8_t *)malloc(buf_size))) {
      perror("malloc");
      return -1;
  }

  if (sysctl(mib, 4, buf, &buf_size, 0, 0)) {
      perror("sysctl");
      free(buf);
      return -1;
  }

  for (uint8_t *ptr = buf; ptr < (buf + buf_size);) {
      int ki_structsize = *(int *)ptr;
      pid_t ki_pid = *(pid_t *)&ptr[72];
      char *ki_tdname = (char *)&ptr[447];

      ptr += ki_structsize;
      if (strcmp(ki_tdname, name) == 0) {
          printf("[MATCH] ki_pid: %d, ki_tdname: %s\n", ki_pid, ki_tdname);
          pid = ki_pid;
          break;
      }
  }

  free(buf);
  return pid;
}

int get_shellcore_pid() {
  int pid = -1;
  size_t NumbOfProcs = 9999;

  for (int j = 0; j <= NumbOfProcs; j++) {
      char tmp_buf[500];
      memset(tmp_buf, 0, sizeof(tmp_buf));
      sceKernelGetProcessName(j, tmp_buf);
      if (strcmp("SceShellCore", tmp_buf) == 0) {
          pid = j;
          break;
      }
  }

  return pid == -1 ? find_pid("SceShellCore") : pid;
}

bool patchShellCore() {

  const UniquePtr<Hijacker> executable = Hijacker::getHijacker(get_shellcore_pid());
  uintptr_t shellcore_base = 0;
  uint64_t shellcore_size = 0;
  if (executable) {
    shellcore_base = executable->getEboot()->getTextSection()->start();
    shellcore_size = executable->getEboot()->getTextSection()->sectionLength();
    g_ShellCorePid = executable->getPid();
  } else {
    plugin_log("SceShellCore not found");
  }
  bool status = false;
  (void)memset(backupShellCoreBytes, 0, sizeof(backupShellCoreBytes));
  shellcore_offset_patch = 0;
  if (!shellcore_base || !shellcore_size) {
    return false;
  }

  plugin_log("allocating 0x%lx bytes", shellcore_size);
  char *shellcore_copy = (char *)malloc(shellcore_size);
  plugin_log("shellcore_copy: 0x%p", shellcore_copy);
  if (!shellcore_copy) {
    plugin_log("shellcore_copy is nullptr");
    return false;
  }
  if (dbg::read(g_ShellCorePid, shellcore_base, shellcore_copy,
                shellcore_size)) {
   
    int offset = -1;

    switch (getSystemSwVersion() & VERSION_MASK) {
    case V200:
      offset = 0x7B7F96;
      break;
    case V220:
      offset = 0x7B82E6;
      break;
    case V225:
      offset = 0x7B8836;
      break;
    case V226:
      offset = 0x7B9FE6;
      break;
    case V230:
      offset = 0x7BAB76;
      break;
    case V250:
    case V270:
      offset = 0x7BBF26;
      break;
    case V300:
    case V310:
      offset = 0x899166;
      break;
    case V320:
    case V321:
      offset = 0x899456;
      break;
    case V400:
    case V402:
    case V403:
      offset = 0x81CA56;
      break;
    case V450:
      offset = 0x81D3C6;
      break;
    case V451:
      offset = 0x81D3D6;
      break;
    case V500:
      offset = 0x8CEAC6;
      break;
    case V502:
      offset = 0x8CEAB6;
      break;
    case V510:
      offset = 0x8D1486;
      break;
    case V550:
      offset = 0x8D1E96;
      break;
    case V600:        
      offset = 0x91B466;
      break;
    case V602:
      offset = 0x91B406;
      break;
    case V650:
      offset = 0x91BC36;
      break;
    case V700:
    case V701:
      offset = 0x9CAD26;
      break;
    case V720:
      offset = 0x9CB606;
      break;
    case V740:
      offset = 0x9D6CF6;
      break;
    case V760:
    case V761:
      offset = 0x9DA2D6;
      break;
    default:
#if 0
      uint64_t addr = shellcore_base +  (uint64_t)0x070FEFC;
      write_bytes(g_ShellCorePid, addr, "9090909090");

      addr = shellcore_base +  (uint64_t)0x070EB02;
      write_bytes(g_ShellCorePid, addr, "9090909090");

      plugin_log("patched addr: 0x%lx", addr);
#endif
      printf_notification("Unknown firmware: 0x%08x", getSystemSwVersion());
      break;
    }

    plugin_log("offset: 0x%llx | ver 0x%X", offset, getSystemSwVersion() & VERSION_MASK);
    if (offset != -1) {
      write_bytes(g_ShellCorePid, (shellcore_base + offset), "9090909090");
      plugin_log("setting status to true");
      status = true;
    }
  }
  if (shellcore_copy) {
    plugin_log("freeing shellcore_copy from 0x%p", shellcore_copy);
    free(shellcore_copy), shellcore_copy = nullptr;
  }
  return status;
}
