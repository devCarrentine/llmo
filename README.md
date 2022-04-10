# llmo
## Library for low-level memory operations and hooking.  
Fully compliant with C++11 standard.

```cpp
#include <cstdio>
#include <string>

#include "../include/rwe.hpp"
#include "../include/hook.hpp"

int __declspec(noinline) printString(const char* const string) {
  return std::puts(string);
}

int __declspec(noinline) printDigit(int digit) {
  return std::putchar('0' + digit);
}

llmo::Hook<decltype(&printDigit)> printDigitHook{&printDigit};
int __declspec(noinline) printDigitHooked(int digit) {
  return printDigitHook.Process(digit + 1);
}

int main()
{
  try
  {
    // Copying.
    const char* string{"Hello, world!"};
    llmo::rwe::Copy(string, "Bye, world!", sizeof("Bye, world!"));

    // Calling.
    int result{llmo::rwe::Call<decltype(&printString)>(&printString, string)}; // Output: Bye, world!

    // Writing.
    llmo::rwe::Write(&result, 4);

    // Hooking.
    printDigitHook.Enable(&printDigitHooked);

    // Reading.
    printDigit(llmo::rwe::Read<int>(&result)); // Output: 5
  }
  catch (llmo::rwe::Exception& ex) {
    // Handle RWE exceptions.
    std::printf("RWE exception at %x, code: %d\n", ex.getAddress(), ex.getCode());
  }
  catch (llmo::hook::Exception& ex) {
    // Handle hook exceptions.
    std::printf("Hook exception at %x, code: %d\n", ex.getAddress(), ex.getCode());
  }
}

```

# Credits
### MinHook. Copyright (C) 2009-2017 Tsuda Kageyu.
