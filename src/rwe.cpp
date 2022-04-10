#include "../include/rwe.hpp"

namespace llmo {
namespace rwe {

ScopedProtectionRemover::ScopedProtectionRemover(
  const std::uintptr_t address, const std::size_t size) :
  m_address(address), m_size(size)
{
  if (0u == address) {
    throw Exception{address, Code::kAddressIsNull};
  }
  else if (0u == size) {
    throw Exception{address, Code::kSizeIsZero};
  }
  else if (!isRegionAvailable(address)) {
    throw Exception{address, Code::kRegionIsNotAvailable};
  }

  if (!setProtectionLevel(m_address, m_size,
    MemoryProtection::kPageExecuteReadWrite,
    m_protectionLevel))
  {
    throw Exception{address, Code::kVirtualProtectFailed};
  }
}

ScopedProtectionRemover::~ScopedProtectionRemover()
{
  setProtectionLevel(
    m_address, m_size,
    m_protectionLevel,
    m_protectionLevel);
}

void flushInstructionCache(
  const std::uintptr_t address, 
  const std::size_t size)
{
  ::FlushInstructionCache(
    ::GetCurrentProcess(), 
    reinterpret_cast<::LPCVOID>(address), 
    size);
}

bool isRegionAvailable(const std::uintptr_t address)
{
  ::MEMORY_BASIC_INFORMATION mbi{};
  void* pointer{reinterpret_cast<void*>(address)};

  if (0u != ::VirtualQuery(pointer, &mbi, sizeof(mbi)))
  {
    if (mbi.State == MEM_COMMIT) {
      return true;
    }
  }

  return false;
}

bool setProtectionLevel(
  const std::uintptr_t address,
  const std::size_t size,
  const MemoryProtection next,
  MemoryProtection& previous)
{
  return TRUE == ::VirtualProtect(
    reinterpret_cast<::LPVOID>(address),
    size, static_cast<::DWORD>(next),
    reinterpret_cast<::PDWORD>(&previous));
}

void Set(
  const std::uintptr_t address, 
  const std::int32_t value, 
  const std::size_t size)
{
  ScopedProtectionRemover instance{address, size};
  std::memset(reinterpret_cast<void*>(address), value, size);
  flushInstructionCache(address, size);
}

void Nop(
  const std::uintptr_t address, 
  const std::size_t size)
{
  Set(address, 0x90, size);
}

void Set(
  const void* pointer, 
  const std::int32_t value, 
  const std::size_t size)
{
  Set(reinterpret_cast<std::uintptr_t>(pointer), value, size);
}

void Nop(
  const void* pointer, 
  const std::size_t size)
{
  Nop(reinterpret_cast<std::uintptr_t>(pointer), size);
}

} // namespace rwe
} // namepace llmo
