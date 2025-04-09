#pragma once

#include <atomic>
#include <source_location>
#include <type_traits>
#include "logger.hpp"
#include "raii_tool.hpp"

template <typename F, typename... Args>
    requires std::invocable<F, Args...>
inline void DropIfBusy(std::atomic_bool &busy_flag, const std::source_location &loc, F task, Args &&...args)
{
	bool expected = false;

	if (!busy_flag.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
	{
		Logger::Instance().Warning().Log("Task {} is already running, skipping...", loc.function_name());
		return;
	}

	auto SG = MakeScopeGuard([](std::atomic_bool &flag) { flag.store(false, std::memory_order_release); }, std::ref(busy_flag));

	Logger::Instance().Notice().Log("Task {} is running...", loc.function_name());

	try
	{
		task(std::forward<Args>(args)...);
	}
	catch (const std::exception &e)
	{
		Logger::Instance().Error().Log("Error in {}: {}", loc.function_name(), e.what());
		throw;
	}
	catch (...)
	{
		Logger::Instance().Error().Log("Unknown exception in {}", loc.function_name());
		throw;
	}
};
