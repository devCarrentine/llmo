#ifndef LLMO_HOOK_HPP
#define LLMO_HOOK_HPP

#include <cstdint> // std::uintptr_t
#include <stdexcept> // std::exception

#include "rwe.hpp"
#include "../third-party/minhook/include/MinHook.h"

namespace llmo
{
  // Function interception.
  namespace hook
  {
    // Hook exception class.
    class Exception : public std::exception
    {
    public:
      // Hook exception codes.
      enum class Code
      {
        kCouldNotInitialize,
        kCouldNotUninitialize,
        kCouldNotCreate,
        kCouldNotEnable,
        kCouldNotDisable,
      };

      Exception(const std::uintptr_t address, const Code code) :
        std::exception{}, m_address(address), m_code(code) {}

      Exception(const Code code) :
        std::exception{}, m_code(code) {}

      std::uintptr_t getAddress() {
        return m_address;
      }

      Code getCode() {
        return m_code;
      }

    private:
      std::uintptr_t m_address{};
      Code m_code{Code::kCouldNotInitialize};
    };

    using Code = Exception::Code;

    // Hook engine, MinHook by default.
    // Throws llmo::Hook::Exception.
    class Engine
    {
    private:
      // Initialises hook engine.
      // It's private because should be called exactly once.
      // That's constructor's business.
      static bool Initialize() {
        return MH_OK == MH_Initialize();
      }

      // Uninitialises hook engine.
      // It's private because should be called exactly once.
      // That's destructor's business.
      static bool Uninitialize() {
        return MH_OK == MH_Uninitialize();
      }

      // Private constructor.
      // Throws kCouldNotInitialize if hook engine could not initialise.
      Engine()
      {
        if (!Initialize()) {
          throw Exception{Code::kCouldNotInitialize};
        }
      }

    public:
      // Uninitializes hook engine.
      // Throws kCouldNotUninitialize if hook engine could not uninitialise.
      ~Engine()
      {
        if (!Uninitialize()) {
          throw Exception{Code::kCouldNotUninitialize};
        }
      }
      
      // Creates hook, but doesn't enable.
      static bool Create(
        const std::uintptr_t address, 
        const void* function, 
        void** original)
      {
        static Engine instance{};

        return MH_OK == MH_CreateHook(
          reinterpret_cast<::LPVOID>(address), 
          const_cast<::LPVOID>(function), original);
      }
      
      // Template for create function.
      // T should be pointer to original.
      template <class T>
      static bool Create(
        const std::uintptr_t address, 
        const void* function, 
        T original)
      {
        return Create(address, function, 
          reinterpret_cast<void**>(original));
      }

      // Enables hook. Should be called after the creation.
      static bool Enable(const std::uintptr_t address) {
        return MH_OK == MH_EnableHook(reinterpret_cast<::LPVOID>(address));
      }

      // Disables hook, but doesn't remove.
      static bool Disable(const std::uintptr_t address) {
        return MH_OK == MH_DisableHook(reinterpret_cast<::LPVOID>(address));
      }

      // Removes hook.
      static bool Remove(const std::uintptr_t address) {
        return MH_OK == MH_RemoveHook(reinterpret_cast<::LPVOID>(address));
      }
    };

    // Template class for MinHook API.
    // T should be function prototype.
    template <class T>
    class Hook
    {
    public:
      // Doesn't create hook, just initialises the address.
      Hook(const std::uintptr_t address) : m_address(address) {}

      // Doesn't create hook, just initialises the address.
      Hook(const void* function) : Hook{reinterpret_cast<std::uintptr_t>(function)} {}

      // Removes hook.
      ~Hook() {
        Engine::Remove(m_address);
      }

      // Enables hook. Hook will be created at the first call.
      // Also can be recalled, if you wanna.
      void Enable(const void* function)
      {
        if (!m_isCreated)
        {
          if (!Engine::Create(m_address, function, &m_original)) {
            throw Exception{m_address, Code::kCouldNotCreate};
          }

          m_isCreated = true;
        }

        if (!m_isEnabled)
        {
          if (!Engine::Enable(m_address)) {
            throw Exception{m_address, Code::kCouldNotEnable};
          }

          m_isEnabled = true;
        }
      }

      // Disables hook, but doesn't remove. Can be recalled.
      void Disable()
      {
        if (m_isEnabled)
        {
          if (!Engine::Disable(m_address)) {
            throw Exception{m_address, Code::kCouldNotDisable};
          }

          m_isEnabled = false;
        }
      }

      bool isEnabled() {
        return m_isEnabled;
      }

      // You should pass callback's params to it.
      // Should be called anyway.
      template <typename... Args, class R = detail::return_type_T<T>>
      R Process(Args... args) {
        return m_original(std::forward<Args>(args)...);
      }

    private:
      bool m_isCreated{false};
      bool m_isEnabled{false};

      std::uintptr_t m_address{};
      T m_original{};
    };
  } // namespace hook

  using hook::Hook;
} // namespace llmo

#endif // LLMO_HOOK_HPP
