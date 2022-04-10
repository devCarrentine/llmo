#ifndef LLMO_RWE_HPP
#define LLMO_RWE_HPP

#if !_WIN32
#error Compatible only with Win32
#endif

#include <utility> // std::forward

#include <cstddef> // std::size_t
#include <cstdint> // std::uintptr_t
#include <cstring> // std::memcpy, std::memset

#include <windows.h> // VirtualProtect

#include "detail.hpp" // return_type

namespace llmo
{
  // Read, write, execute.
  namespace rwe
  {
    // Memory protection constants.
    enum class MemoryProtection
    {
      kPageExecute            = PAGE_EXECUTE,
      kPageExecuteRead        = PAGE_EXECUTE_READ,
      kPageExecuteReadWrite   = PAGE_EXECUTE_READWRITE,
      kPageExecuteWriteCopy   = PAGE_EXECUTE_WRITECOPY,
      kPageNoAccess           = PAGE_NOACCESS,
      kPageReadOnly           = PAGE_READONLY,
      kPageReadWrite          = PAGE_READWRITE,
      kPageWriteCopy          = PAGE_WRITECOPY,
      kPageGuard              = PAGE_GUARD,
      kPageNoCache            = PAGE_NOCACHE,
      kPageWriteCombine       = PAGE_WRITECOMBINE
    };

    // Unprotects in constructor, restores protection in destructor.
    class ScopedProtectionRemover
    {
    public:
      enum class Exception
      {
        kAddressIsNull,
        kRegionIsNotAvailable,
        kSizeIsZero,
        kVirtualProtectFailed,
      };

      ScopedProtectionRemover(
        const std::uintptr_t address,
        const std::size_t size = 4096);

      ~ScopedProtectionRemover();

    private:
      std::uintptr_t m_address{};
      std::size_t m_size{};

      MemoryProtection m_protectionLevel{
        MemoryProtection::kPageExecuteReadWrite};
    };

    using Exception = ScopedProtectionRemover::Exception;

    void flushInstructionCache(
      const std::uintptr_t address, 
      const std::size_t size);

    // Calls VirtualQuery and returns true if mbi.State is MEM_COMMIT.
    // It's necessary to call always when you're going to work with the memory.
    bool isRegionAvailable(const std::uintptr_t address);

    // Calls VirtualProtect, gets previous memory protection flag,
    // writes it to [ MemoryProtection& previous ] and sets new.
    // It's necessary to do if you're going to work with the memory.
    bool setProtectionLevel(
      const std::uintptr_t address,
      const std::size_t size,
      const MemoryProtection next,
      MemoryProtection& previous);

    // Reads value from the address and returns it.
    // Absolutely safe, but be accurate to typename T.
    template <typename T>
    T Read(const std::uintptr_t address)
    {
      T out{};

      ScopedProtectionRemover instance{address, sizeof(out)};
      std::memcpy(&out, reinterpret_cast<void*>(address), sizeof(out));

      flushInstructionCache(address, sizeof(out));

      return out;
    }

    // Writes some value to address.
    // Absolutely safe, but be accurate to typename T.
    template <typename T>
    void Write(const std::uintptr_t address, const T in)
    {
      ScopedProtectionRemover instance{address, sizeof(in)};
      std::memcpy(reinterpret_cast<void*>(address), &in, sizeof(in));
      flushInstructionCache(address, sizeof(in));
    }

    // Absolutely safe alternative for std::memset.
    void Set(
      const std::uintptr_t address,
      const std::int32_t value,
      const std::size_t size);

    // Absolutely safe alternative for std::memset with nop opcode [ 0x90 ].
    void Nop(
      const std::uintptr_t address,
      const std::size_t size);

    // Absolutely safe alternative for std::memcpy.
    template <typename T>
    void Copy(
      const std::uintptr_t address,
      const T source,
      const std::size_t size)
    {
      ScopedProtectionRemover instance{address, size};
      std::memcpy(reinterpret_cast<void*>(address), source, size);
      flushInstructionCache(address, size);
    }

    // Calls some function, but unprotects the region where it is.
    template <class T, typename ... Args, class R = detail::return_type_T<T>>
    R Call(const std::uintptr_t address, Args ... args)
    {
      ScopedProtectionRemover instance{address};
      return reinterpret_cast<T>(address)(std::forward<Args>(args) ...);
    }

    // overloads with void* instead of std::uintptr_t as address

    template <typename T>
    T Read(const void* pointer) {
      return Read<T>(reinterpret_cast<std::uintptr_t>(pointer));
    }

    template <typename T>
    void Write(const void* pointer, const T in) {
      Write(reinterpret_cast<std::uintptr_t>(pointer), in);
    }

    void Set(
      const void* pointer,
      const std::int32_t value,
      const std::size_t size);

    void Nop(const void* pointer, const std::size_t size);

    template <typename T>
    void Copy(const void* address, const T source, const std::size_t size) {
      Copy(reinterpret_cast<std::uintptr_t>(address), source, size);
    }

    template <class T, typename... Args, class R = detail::return_type_T<T>>
    R Call(const void* pointer, Args ... args) {
      return Call<T>(reinterpret_cast<std::uintptr_t>(pointer), args ...);
    }
  } // namespace rwe
} // namespace llmo

#endif // LLMO_RWE_HPP
