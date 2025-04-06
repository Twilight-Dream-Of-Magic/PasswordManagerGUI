
#include <stdio.h>
#include "ui/PasswordManagerGUI.hpp"
#include <csignal>

// Main code
int main(int, char**)
{
	Logger::Instance().Init();
	Logger::Instance().Debug().Log("hello {}", "world!");

	{
		auto log_stream = Logger::Instance().Info().Stream();
		log_stream << 4 << 2;
	}

	std::signal
	(
		SIGABRT, 
		[](int sig)
		{
			Logger::Instance().Fatal().Log
			(
				"event = [signal_abort], signal = [{}], description = [SIGABRT triggered, application will now exit.]",
				sig
			);
			APP_Cleanup(CurrentApplicationData);
			std::_Exit(1);
		}
	);

	std::set_terminate
	(
		[]()
		{
			if (auto ex = std::current_exception())
			{
				try 
				{
					std::rethrow_exception(ex);
				}
				catch (const std::exception& e) 
				{
					Logger::Instance().Fatal().Log
					(
						"event = [uncaught_exception], type = [std::exception], message = [{}]", e.what()
					);
				}
				catch (...)
				{
					Logger::Instance().Fatal().Log("event = [uncaught_exception], type = [unknown]");
				}
			}
			else
			{
				Logger::Instance().Fatal().Log("event = [terminate], reason = [unknown]");
			}
			APP_Cleanup(CurrentApplicationData);
			std::abort();
		}
	);

	try
	{
		auto SG = MakeScopeGuard
		(
			[](ApplicationData&) 
			{
			APP_Cleanup(CurrentApplicationData);
			}, 
			std::ref(CurrentApplicationData)
		);

		APP_Inital(CurrentApplicationData);

		APP_Loop(CurrentApplicationData);
	}
	catch (std::exception& e)
	{
		Logger::Instance().Fatal().Log
		(
			"event = [exception_caught], type = [std::exception], message = [{}]", e.what()
		);
		throw;
	}

	return 0;
}
