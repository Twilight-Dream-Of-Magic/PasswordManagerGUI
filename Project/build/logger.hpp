#pragma once

#include <regex>
#include <syncstream>

template<typename T>
concept Printable = requires(T a, std::ostream& os)
{
	{ os << a } -> std::convertible_to<std::ostream&>;
};

//Logger
class Logger
{
public:
	enum class Level : uint32_t
	{
		DEBUG = 0,
		INFO = 1,
		NORMAL = 2,
		NOTICE = 3,
		WARNING = 4,
		ERROR = 5,
		FATAL = 6,
		MAX_LENGTH = 7
	};

	enum class Mask : uint32_t
	{
		SHOW_DEBUG = 1 << 0,
		SHOW_INFO = 1 << 1,
		SHOW_NORMAL = 1 << 2,
		SHOW_NOTICE = 1 << 3,
		SHOW_WARNING = 1 << 4,
		SHOW_ERROR = 1 << 5,
		SHOW_FATAL = 1 << 6,
		SHOW_TAG = 1 << 7,
		SHOW_TIME = 1 << 8,
		SHOW_COLOR = 1 << 9,
		COLOR_MESSAGE = 1 << 10,
		SHOW_MESSAGE = 1 << 11,
		NEW_LINE = 1 << 12,
		END_LINE = 1 << 13,
		LOG_TO_CONSOLE = 1 << 14,
		LOG_TO_FILE = 1 << 15,
		SHOW_SRC_INFO = 1 << 16,
		COLOR_SRC_INFO = 1 << 17,
		COLOR_TIME = 1 << 18,
		COLOR_TAG = 19
	};

	friend auto operator|(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator&(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator^(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator~(Logger::Mask a) -> std::underlying_type_t<Logger::Mask>;

	static Logger& Instance();

	~Logger();

	void Init(std::filesystem::path filepath = "./log.txt", uint32_t logmask = uint32_t(-1));

	uint32_t SetMask(uint32_t mask);

	uint32_t GetMask() const;

	void SetLogFile(const std::filesystem::path& filename, uint32_t mask = 0u);

	template<typename STR> requires(std::is_convertible_v<STR, std::string>)
	void Log(Logger::Level level, const STR& str, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		Print(level, str, mask, loc);
	}

	template <Printable... Types>
	void Log(Level level, const std::format_string<Types...> fmt, const std::tuple<Types...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		DoLog(level, fmt.get(), tpl_args, mask ,loc);
	}

private:
	template <Printable... Types>
	void DoLog(Level level, const std::string_view sv, const std::tuple<Types...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		try
		{
			const auto formatted = std::apply
			(
				[&](const Types&... args)
				{
					return std::vformat(sv, std::make_format_args(args...));
				}, 
				tpl_args
			);
			Print(level, formatted, mask, loc);
		}
		catch (const std::format_error&)
		{
			std::stringstream ss{};
			ss << "format_error: ";
			ss << sv;
			std::apply
			(
				[&](const Types&... args) 
				{
					(ss << ... << args);
				},
				tpl_args
			);
			Print(level, ss.str(), mask,loc);
		}
	}

	class LogHelper 
	{
	public:
		LogHelper& Mask(uint32_t mask)
		{
			__mask = mask;
		}
		LogHelper& Level(Logger::Level level)
		{
			__level = level;
		}
		template <Printable... Types>
		LogHelper& Log(const std::format_string<Types...> fmt, const Types&... args)
		{
			//try 
			//{
				const auto formatted = std::vformat(fmt.get(), std::make_format_args(args...));
				__logger.Print(__level, formatted, __mask, __loc);
			//}
			//catch (const std::format_error&)
			//{
			//	std::stringstream ss{};
			//	ss << "format_error: ";
			//	ss << fmt.get();
			//	(ss <<  ... << args);
			//	__logger.Print(__level, ss.str(), __mask, __loc);
			//}
			return *this;
		}
		LogHelper(Logger& logger, Logger::Level level = Logger::Level::NORMAL, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current()) :
		__logger(logger),
		__level(level),
		__mask(mask),
		__loc(loc)
		{}
	private:
		std::source_location __loc;
		Logger& __logger;
		Logger::Level __level = Logger::Level::NORMAL;
		uint32_t __mask = 0u;
	};

	Logger() = default;

	void Print(Logger::Level level, const std::string_view message, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	bool RotateLogFile(uint32_t try_count = 3, std::chrono::milliseconds t = std::chrono::milliseconds(3), uint32_t mask = 0u);

	void LogToFile(const std::string& str, uint32_t mask = 0u);

	static std::string GetCurrentTimeStr();

	static constexpr size_t MAX_FILE_SIZE = 1024 * 1024;
	std::ofstream			_fs;
	std::mutex				_mutex;
	std::filesystem::path	_filename;
	uint32_t				_mask = uint32_t(-1); 


	/// ----------- Helper方法 ------------
public:

	Logger::LogHelper Helper(Logger::Level level = Logger::Level::NORMAL, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, level, mask, loc);
	}

	Logger::LogHelper Normal(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, Logger::Level::NORMAL, mask, loc);
	}

	Logger::LogHelper Info(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, Logger::Level::INFO, mask, loc);
	}

	Logger::LogHelper Debug(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, Logger::Level::DEBUG, mask, loc);
	}

	Logger::LogHelper Notice(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, Logger::Level::NOTICE, mask, loc);
	}

	Logger::LogHelper Warning(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, Logger::Level::WARNING, mask, loc);
	}

	Logger::LogHelper Error(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, Logger::Level::ERROR, mask, loc);
	}

	Logger::LogHelper Fatal(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		return LogHelper(*this, Logger::Level::FATAL, mask, loc);
	}
};

/// ----------- 友元方法 ------------

inline auto operator|(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>
{
	return (std::underlying_type_t<Logger::Mask>(a) | std::underlying_type_t<Logger::Mask>(b));
}

inline auto operator&(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>
{
	return (std::underlying_type_t<Logger::Mask>(a) & std::underlying_type_t<Logger::Mask>(b));
}

inline auto operator^(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>
{
	return (std::underlying_type_t<Logger::Mask>(a) ^ std::underlying_type_t<Logger::Mask>(b));
}

inline auto operator~(Logger::Mask a) -> std::underlying_type_t<Logger::Mask>
{
	return (~std::underlying_type_t<Logger::Mask>(a));
}

/// ----------- public方法 ------------

inline Logger& Logger::Instance()
{
	static Logger instance;
	return instance;
}

inline Logger::~Logger()
{
	if(_fs.is_open())
	{
		_fs.flush();
		_fs.close();
	}
	_filename.clear();
	std::cout << std::flush;
	std::cerr << std::flush;
}

inline void Logger::Init(std::filesystem::path filepath, uint32_t logmask)
{
	_mask = logmask;
	SetLogFile(filepath, _mask);
}

inline uint32_t Logger::SetMask(uint32_t mask)
{
	std::scoped_lock lock(_mutex);
	auto			 old_mask = _mask;
	_mask = mask;
	return old_mask;
}

inline uint32_t Logger::GetMask() const
{
	return _mask;
}

inline void Logger::Print(Logger::Level level, const std::string_view message, uint32_t mask, const std::source_location& loc)
{
	using tag_str = std::string_view;
	using color_str = std::string_view;
	using level_config_t = std::tuple<tag_str, color_str>;

	static constexpr auto enum_integer = [](Logger::Level level) -> size_t
	{
		return static_cast<std::underlying_type_t<Logger::Level>>(level);
	};

	static constexpr std::array<level_config_t, enum_integer(Level::MAX_LENGTH)> level_config
	(
		{
		{"(DEBUG)",		"\033[0;36m"},  // DEBUG: 青色
		{"(INFO)" ,		"\033[0;32m"},  // INFO: 绿色
		{" ",			"\033[0;37m"},  // NORMAL: 白色/浅灰
		{"(NOTICE)",	"\033[1;34m"},  // NOTICE: 蓝色
		{"(WARNING)",	"\033[1;33m"},  // WARNING: 黄色
		{"(ERROR)",		"\033[1;31m"},  // ERROR: 红色
		{"(FATAL)",		"\033[1;91m"}   // FATAL: 亮红色	
		}
	);

	static constexpr auto get_config = [](Logger::Level level) -> const decltype(level_config)::const_reference
	{
		return level_config.at(enum_integer(level));
	};

	static constinit auto generate_source_info = [](bool show_color, const std::source_location& loc) -> std::string
	{

		std::filesystem::path full_path(loc.file_name());
		std::string filename = full_path.filename().string();
		std::string path = full_path.parent_path().string();
		std::string function_name = loc.function_name();

		static const std::regex lambda_regex(R"(.*lambda_[0-9]+.*)");
		if (std::regex_search(function_name, lambda_regex))
		{
			function_name = "[lambda]";
		}
		else 
		{
			// 过滤模板参数和修饰符，确保高亮正确的核心函数名, 省略了函数参数信息使其更直观
			static const std::regex func_regex(R"((.*::)?([~]?[A-Za-z_][A-Za-z0-9_]*)\s*(<.*>)?\s*\(.*\))");
			std::smatch match;
			if (std::regex_search(function_name, match, func_regex))
			{
				std::string prefix = match[1].str();	// 类名/命名空间
				std::string core_func = match[2].str();	// 函数名
				static constexpr std::string_view fmt_color = "\033[0;37m{}\033[1;36m{}\033[0m";
				static constexpr std::string_view fmt = "{}{}";
				if(show_color)
					function_name = std::format(fmt_color, prefix, core_func);
				else
					function_name = std::format(fmt, prefix, core_func);
				// 这里决定隐藏参数信息
				//std::string params = match[4].str();	// 参数列表
				//function_name = std::format("\033[0;37m{} \033[1;36m{}\033[0m\033[0;37m{}\033[0m", prefix, core_func, params);
			}
		}

		static constexpr std::string_view fmt_color = "  \033[0;37m{}\\\033[1;35m{}\033[0m:\033[1;33m{}\033[0m {}():\n";
		static constexpr std::string_view fmt = "  {}\\:{} {}():\n";
		if (show_color)
		{
			return std::format
			(
				fmt_color,
				path, filename, loc.line(), function_name
			);
		}
		else
		{
			return std::format
			(
				fmt,
				path, filename, loc.line(), function_name
			);
		}
	};

	static constexpr std::string_view reset_color_str = "\033[0m";
	static constexpr std::string_view time_color_str = "\033[3m\033[4m";
	static constexpr std::string_view tag_color_str = "\033[4m\033[7m";

	static const auto generate_text = [](uint32_t mask, Logger::Level level, const std::source_location& loc, const std::string_view message, bool show_color) -> std::stringstream
	{
		std::stringstream		ss{};
		auto					time_str = Logger::GetCurrentTimeStr();
		auto& [tag, color] = get_config(level);

		if (mask & ~~Logger::Mask::NEW_LINE)
			ss << '\n';
		if ((mask & ~~Logger::Mask::COLOR_TIME) && show_color)
			ss << time_color_str;
		if (mask & ~~Logger::Mask::SHOW_TIME)
			ss << time_str;
		if ((mask & ~~Logger::Mask::COLOR_TIME) && show_color)
			ss << reset_color_str;
		if (mask & ~~Logger::Mask::SHOW_SRC_INFO)
			ss << generate_source_info((mask & ~~Logger::Mask::COLOR_SRC_INFO) && show_color, loc);
		if (mask & ~~Logger::Mask::COLOR_MESSAGE && show_color)
			ss << color;
		if ((mask & ~~Logger::Mask::COLOR_TAG) && show_color)
			ss << tag_color_str;
		if (mask & ~~Logger::Mask::SHOW_TAG)
			ss << tag;
		if ((mask & ~~Logger::Mask::COLOR_TAG) && show_color)
			ss << reset_color_str;
		if ((mask & ~~Logger::Mask::COLOR_MESSAGE) && show_color)
			ss << color;
		if (mask & ~~Logger::Mask::SHOW_MESSAGE)
			ss << ' ' << message;
		if ((mask & ~~Logger::Mask::COLOR_MESSAGE) && show_color)
			ss << reset_color_str;
		if (mask & ~~Logger::Mask::END_LINE)
			ss << '\n';
		return ss;
	};

	const uint32_t log_mask = mask ? mask : _mask;

	if (!(log_mask & (1u << enum_integer(level))))
		return;

	const bool show_color = log_mask & ~~Logger::Mask::SHOW_COLOR;

	//这里要处理一下string_view和string析构的问题
	std::string msg(message);
	auto logging_task = [this, log_mask, level, loc, msg, show_color]() -> void
	{
		std::ostream& output_stream = (level == Logger::Level::ERROR || level == Logger::Level::FATAL) ? std::cerr : std::cout;

		if (_mask & ~~Logger::Mask::LOG_TO_CONSOLE)
		{
			std::string log_text = generate_text(log_mask, level, loc, msg, show_color).str();
			std::osyncstream(output_stream) << log_text; //这里使用osyncstream代替了锁
		}
		if (_mask & ~~Logger::Mask::LOG_TO_FILE)
		{
			std::string log_text = generate_text(log_mask, level, loc, msg, false).str();
			LogToFile(log_text, log_mask);
		}
	};

	// 对于非致命级别的日志，用 std::thread deatch() 异步写日志，不会阻塞主线程
	if(level != Logger::Level::FATAL)
	{
		std::thread
		(
			[this, logging_task]()
			{
				logging_task();
			}
		).detach();
	}
	else // FATAL 级别则同步写日志，确保日志输出后再抛异常退出
	{
		logging_task();
		throw std::runtime_error(message.data());
	}
}

/// ----------- private方法 ------------

inline void Logger::SetLogFile(const std::filesystem::path& filename, uint32_t mask)
{
	const auto handle_exception = [](decltype(*this) self, uint32_t mask, const std::filesystem::path& filepath, const std::string_view message)
	{
		const uint32_t mask_do_not_print_to_file = mask & ~Logger::Mask::LOG_TO_FILE;
		self.Log(Logger::Level::ERROR, "Set File {} failed : {}", std::tuple(filepath.string(), message), mask_do_not_print_to_file);
	};

	if (_fs.is_open())
	{
		_fs.close();
	}
	try
	{
		std::filesystem::create_directories(filename.parent_path());
		_fs.open(filename, std::ios::app);
		_filename = filename;
	}
	catch (const std::exception& e)
	{
		handle_exception(*this, mask, _filename, e.what());
	}
	catch (...)
	{
		handle_exception(*this,mask, _filename, "： Unknown exception");
	}
}

inline bool Logger::RotateLogFile(uint32_t try_count, std::chrono::milliseconds time_ms, uint32_t mask)
{
	for (uint32_t i = 0; i < try_count; ++i)
	{
		const auto handle_exception = [](decltype(*this) self, uint32_t mask, const std::filesystem::path& filepath, uint32_t try_count, uint32_t i, const std::string_view message)
		{
			const uint32_t mask_do_not_print_to_file = mask & ~Mask::LOG_TO_FILE; 
			self.Log(Logger::Level::ERROR, "Rotate File {} failed after {}, attempts {} : {}", std::tuple(filepath.string(), try_count, i + 1, message), mask_do_not_print_to_file);
		};

		try
		{
			if (_fs.is_open())
			{
				_fs.close();
			}

			auto new_name = _filename.parent_path() / std::format("{}_{}.{}{}", _filename.stem().string(), GetCurrentTimeStr(), i + 1u, _filename.extension().string());

			std::filesystem::rename(_filename, new_name);
			_fs.open(_filename, std::ios::app);
			return true;
		}
		catch (const std::exception& e)
		{
			handle_exception(*this, mask, _filename, try_count, i, e.what());
		}
		catch (...)
		{
			handle_exception(*this, mask, _filename, try_count, i, "Unknown exception");
		}
		//std::this_thread::sleep_for(time_ms); todo:这里使用协程调度
	}
	return false;
}

inline void Logger::LogToFile(const std::string& str, uint32_t mask)
{
	if (std::filesystem::exists(_filename) && std::filesystem::file_size(_filename) >= MAX_FILE_SIZE)
	{
		if (!RotateLogFile(3, std::chrono::milliseconds(3), mask)) {
			_mask &= ~Mask::LOG_TO_FILE;
			Log(Logger::Level::ERROR, "Failed to rotate log file: {}", std::tuple(_filename.string()));
			return;
		}
	}

	const auto handle_exception = [](decltype(*this) self, uint32_t mask, const std::filesystem::path& filepath, const std::string_view message)
	{
		const uint32_t mask_do_not_print_to_file = mask & ~Logger::Mask::LOG_TO_FILE;
		self.Log(Logger::Level::ERROR, "Failed to log to file {} : {}", std::tuple(filepath.string(), message), mask_do_not_print_to_file);
	};

	try
	{
		std::lock_guard<std::mutex> lock(_mutex);
		_fs << str;
		_fs.flush();
	}
	catch (const std::exception& e)
	{
		handle_exception(*this, mask, _filename.string(), e.what());
	}
	catch (...)
	{
		handle_exception(*this, mask, _filename.string(), " Unknown exception");
	}
}
 
inline std::string Logger::GetCurrentTimeStr()
{
	auto zt = std::chrono::zoned_time{ std::chrono::current_zone(), std::chrono::system_clock::now() };
	return std::format("[{:%Y-%m-%d %H:%M:%S}]", zt);
}

//// ---------- DEBUG 级别 ----------

inline void LogDebugHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::DEBUG, s, 0u, loc);
}

template <Printable... Args>
inline void LogDebugHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::DEBUG, fmt, tpl_args, 0u, loc);
}

//// ---------- INFO 级别 ----------

inline void LogInfoHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::INFO, s, 0u, loc);
}

template <Printable... Args>
inline void LogInfoHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::INFO, fmt, tpl_args, 0u, loc);
}

//// ---------- NORMAL 级别 ----------

inline void LogNormalHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NORMAL, s, 0u, loc);
}

template <Printable... Args>
inline void LogNormalHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NORMAL, fmt, tpl_args, 0u, loc);
}

//// ---------- NOTICE 级别 ----------

inline void LogNoticeHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NOTICE, s, 0u, loc);
}

template <Printable... Args>
inline void LogNoticeHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NOTICE, fmt, tpl_args, 0u, loc);
}

//// ---------- WARNING 级别 ----------

inline void LogWarnHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::WARNING, s, 0u, loc);
}

template <Printable... Args>
inline void LogWarnHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::WARNING, fmt, tpl_args, 0u, loc);
}

//// ---------- ERROR 级别 ----------

inline void LogErrorHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::ERROR, s, 0u, loc);
}

template <Printable... Args>
inline void LogErrorHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::ERROR, fmt, tpl_args, 0u, loc);
}

//// ---------- FATAL 级别 ----------

inline void LogFatalHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::FATAL, s, 0u, loc);
}

template <Printable... Args>
inline void LogFatalHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::FATAL, fmt, tpl_args, 0u, loc);
}
