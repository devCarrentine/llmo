#include "../include/rwe.hpp"

namespace llmo {
namespace rwe {

ScopedProtectionRemover::ScopedProtectionRemover(
	std::uintptr_t address, std::size_t size) :
	m_address(address), m_size(size)
{
	if (0 == address) {
		throw Exception::kAddressIsNull;
	}
	else if (0 == size) {
		throw Exception::kSizeIsZero;
	}
	else if (!isRegionAvailable(address)) {
		throw Exception::kRegionIsNotAvailable;
	}

	if (!setProtectionLevel(m_address, m_size, 
		MemoryProtection::kPageExecuteReadWrite, 
		m_protectionLevel))
	{
		throw Exception::kVirtualProtectFailed;
	}
}

ScopedProtectionRemover::~ScopedProtectionRemover()
{
	if (!setProtectionLevel(
		m_address, m_size, 
		m_protectionLevel,
		m_protectionLevel))
	{
		throw Exception::kVirtualProtectFailed;
	}
}

bool isRegionAvailable(std::uintptr_t address)
{
	::MEMORY_BASIC_INFORMATION mbi{};
	void* pointer{reinterpret_cast<void*>(address)};

	if (0 != ::VirtualQuery(pointer, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT) {
			return true;
		}
	}

	return false;
}

bool setProtectionLevel(
	std::uintptr_t address,
	std::size_t size,
	MemoryProtection next,
	MemoryProtection& previous)
{
	return TRUE == ::VirtualProtect(
		reinterpret_cast<::LPVOID>(address),
		size, static_cast<::DWORD>(next),
		reinterpret_cast<::PDWORD>(&previous));
}

void Set(std::uintptr_t address, std::int32_t value, std::size_t size)
{
	ScopedProtectionRemover instance{address, size};
	std::memset(reinterpret_cast<void*>(address), value, size);
}

void Nop(std::uintptr_t address, std::size_t size) {
	Set(address, 0x90, size);
}

void Set(void* pointer, std::int32_t value, std::size_t size) {
	Set(reinterpret_cast<std::uintptr_t>(pointer), value, size);
}

void Nop(void* pointer, std::size_t size) {
	Nop(reinterpret_cast<std::uintptr_t>(pointer), size);
}

} // namespace rwe
} // namepace llmo
