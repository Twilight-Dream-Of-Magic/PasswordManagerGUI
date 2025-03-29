#pragma once

#include <regex>
#include <syncstream>

template<typename T>
concept Printable = requires(T a, std::ostream & os)
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
		SHOW_SRC_INFO = 1 << 9,
		SHOW_MESSAGE = 1 << 10,
		SHOW_COLOR = 1 << 11,
		NEW_LINE = 1 << 12,
		END_LINE = 1 << 13,
		LOG_TO_CONSOLE = 1 << 14,
		LOG_TO_FILE = 1 << 15,
		COLOR_MESSAGE = 1 << 16,
		COLOR_SRC_INFO = 1 << 17,
		COLOR_TIME = 1 << 18,
		COLOR_TAG = 1 << 19
	};

	struct SourceInfo {
		std::string path;
		std::string filename;
		std::string function_prefix;
		std::string function_core;
		uint_least32_t line;
	};

	friend auto operator|(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator&(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator^(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator~(Logger::Mask a) -> std::underlying_type_t<Logger::Mask>;

	static Logger& Instance();

	~Logger();

	void Init(std::filesystem::path filepath = "./log.txt", uint32_t logmask = -1u);

	uint32_t SetDefaultMask(uint32_t mask);

	uint32_t GetDefaultMask() const;

	void SetDefaultMaskFlag(Logger::Mask flag);

	void UnsetDefaultMaskFlag(Logger::Mask flag);

	void SetLogFile(const std::filesystem::path& filename, uint32_t mask = 0u);

	template<typename STR> requires(std::is_convertible_v<STR, std::string>)
		void Log(Logger::Level level, const STR& str, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		Print(level, str, mask, loc);
	}

	template <Printable... Types>
	void Log(Level level, const std::format_string<Types...>& fmt, const std::tuple<Types...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
	{
		DoLog(level, fmt.get(), tpl_args, mask, loc);
	}

	class LogHelper;

	/// ----------- Helper Chain ------------

	Logger::LogHelper Helper(Logger::Level level = Logger::Level::NORMAL, uint32_t mask = 0u,
		const std::source_location& loc = std::source_location::current());

	Logger::LogHelper Normal(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	Logger::LogHelper Info(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	Logger::LogHelper Debug(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	Logger::LogHelper Notice(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	Logger::LogHelper Warning(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	Logger::LogHelper Error(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	Logger::LogHelper Fatal(uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	/// ----------- Helper Chain ------------

private:

	template <Printable... Types>
	void DoLog(Level level, const std::string_view sv, const std::tuple<Types...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	Logger() = default;

	void Print(Logger::Level level, const std::string_view message, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current());

	bool RotateLogFile(uint32_t try_count = 3, std::chrono::milliseconds t = std::chrono::milliseconds(3), uint32_t mask = 0u);

	void LogToFile(const std::string& str, uint32_t mask = 0u);

	static std::string GetCurrentTimeStr();

	static SourceInfo ParseSourceInfo(const std::source_location& loc);

	static constexpr size_t MAX_FILE_SIZE = 1024 * 1024;
	std::ofstream			_fs;
	std::mutex				_mutex;
	std::filesystem::path	_filename;
	uint32_t				_mask = -1u;
};



/// ----------- Helper Class ------------

class Logger::LogHelper
{
public:
	class LogStream;

	LogHelper(Logger& logger, Logger::Level level = Logger::Level::NORMAL, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current()) :
		__logger(logger),
		__level(level),
		__local_mask(mask),
		__mask_enabled(0u),
		__mask_disabled(0u),
		__loc(loc) {
	}

	LogHelper(LogHelper&&) = default;
	LogHelper(const LogHelper&) = default;

	LogHelper::LogStream Stream() const;
	LogHelper& Mask(uint32_t mask);
	LogHelper& EnableMaskFlag(Logger::Mask flag);
	LogHelper& DisableMaskFlag(Logger::Mask flag);
	LogHelper& Level(Logger::Level level);
	LogHelper& Log(const std::string& str);


	template <Printable... Types>
	LogHelper& Log(const std::format_string<Types...>& fmt, const Types&... args);

private:
	LogHelper& operator=(LogHelper&&) = delete;
	LogHelper& operator=(const LogHelper&) = delete;
	uint32_t GetActiveMask() const;

	std::source_location __loc;
	Logger& __logger;
	Logger::Level __level;
	uint32_t __local_mask;
	uint32_t __mask_enabled;
	uint32_t __mask_disabled;
};

class Logger::LogHelper::LogStream
{
public:
	LogStream(const LogHelper& helper) :
		___ss(std::string(128, 0x00)),
		___helper(helper),
		___loged(false) {
	}
	LogStream& Log();
	~LogStream();
	template<Printable Type>
	LogStream& operator<<(const Type& data);
	LogStream(Logger::LogHelper::LogStream&&) = default;
	LogStream(const Logger::LogHelper::LogStream&) = default;

private:
	LogStream& operator=(Logger::LogHelper::LogStream&&) = delete;
	LogStream& operator=(const Logger::LogHelper::LogStream&) = delete;

	std::ostringstream ___ss;
	LogHelper ___helper;
	bool ___loged;
};

/// ----------- Helper Class ------------

/// ----------- Helper Chain Funciton ------------

inline Logger::LogHelper& Logger::LogHelper::Mask(uint32_t mask)
{
	__local_mask = mask;
	return *this;
}

inline Logger::LogHelper& Logger::LogHelper::EnableMaskFlag(Logger::Mask flag)
{
	__mask_enabled |= ~~flag;
	return *this;
}

inline Logger::LogHelper& Logger::LogHelper::DisableMaskFlag(Logger::Mask flag)
{
	__mask_disabled |= ~~flag;
	return *this;
}

inline uint32_t Logger::LogHelper::GetActiveMask() const
{
	return ((__local_mask ? __local_mask : __logger._mask) | __mask_enabled) & ~__mask_disabled;
}

inline Logger::LogHelper& Logger::LogHelper::Level(Logger::Level level)
{
	__level = level;
	return *this;
}

inline Logger::LogHelper& Logger::LogHelper::Log(const std::string& str)
{
	__logger.Print(__level, str, GetActiveMask(), __loc);
	return *this;
}

template <Printable... Types>
inline Logger::LogHelper& Logger::LogHelper::Log(const std::format_string<Types...>& fmt, const Types&... args)
{
	const auto formatted = std::vformat(fmt.get(), std::make_format_args(args...));
	__logger.Print(__level, formatted, GetActiveMask(), __loc);
	return *this;
}

inline Logger::LogHelper::LogStream& Logger::LogHelper::LogStream::Log()
{
	if (!___ss.str().empty())
	{
		___helper.Log(___ss.str());
		___loged = true;
	}
	return *this;
}

template<Printable Type>
inline Logger::LogHelper::LogStream& Logger::LogHelper::LogStream::operator<<(const Type& data)
{
	___ss << data;
	return *this;
}

inline Logger::LogHelper::LogStream Logger::LogHelper::Stream() const
{
	return LogHelper::LogStream(*this);
}

inline Logger::LogHelper::LogStream::~LogStream()
{
	if (!___loged) Log();
}

inline Logger::LogHelper Logger::Helper(Logger::Level level, uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, level, mask, loc);
}

inline Logger::LogHelper Logger::Normal(uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, Logger::Level::NORMAL, mask, loc);
}

inline Logger::LogHelper Logger::Info(uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, Logger::Level::INFO, mask, loc);
}

inline Logger::LogHelper Logger::Debug(uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, Logger::Level::DEBUG, mask, loc);
}

inline Logger::LogHelper Logger::Notice(uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, Logger::Level::NOTICE, mask, loc);
}

inline Logger::LogHelper Logger::Warning(uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, Logger::Level::WARNING, mask, loc);
}

inline Logger::LogHelper Logger::Error(uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, Logger::Level::ERROR, mask, loc);
}

inline Logger::LogHelper Logger::Fatal(uint32_t mask, const std::source_location& loc)
{
	return LogHelper(*this, Logger::Level::FATAL, mask, loc);
}

/// ----------- Helper Chain Funciton ------------

/// ----------- Friend Function ------------

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

/// ----------- Friend Function ------------

/// ----------- Public Function ------------

inline Logger& Logger::Instance()
{
	static Logger instance{};
	return instance;
}

inline Logger::~Logger()
{
	if (_fs.is_open())
	{
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

inline void Logger::SetDefaultMaskFlag(Logger::Mask flag)
{
	_mask |= ~~flag;
}

inline void Logger::UnsetDefaultMaskFlag(Logger::Mask flag)
{
	_mask &= ~flag;
}

inline uint32_t Logger::SetDefaultMask(uint32_t mask)
{
	std::scoped_lock lock(_mutex);
	auto			 old_mask = _mask;
	_mask = mask;
	return old_mask;
}

inline uint32_t Logger::GetDefaultMask() const
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
		{"(DEBUG)",		"\033[1;36m"},  // DEBUG: 青色
		{"(INFO)" ,		"\033[1;34m"},  // INFO: 蓝色
		{"",			"\033[1;37m"},  // NORMAL: 白色
		{"(NOTICE)",	"\033[1;32m"},  // NOTICE: 绿色
		{"(WARNING)",	"\033[1;33m"},  // WARNING: 黄色
		{"(ERROR)",		"\033[1;31m"},  // ERROR: 红色
		{"(FATAL)",		"\033[1;91m"}   // FATAL: 亮红色	
		}
	);

	static constexpr auto get_config = [](Logger::Level level) -> const decltype(level_config)::const_reference
	{
		return level_config.at(enum_integer(level));
	};

	static const auto generate_text = [](uint32_t mask, Level level,
		const SourceInfo& src_info,
		std::string_view message, 
		bool show_color) -> std::string
	{
		// 颜色常量
		static constexpr std::string_view reset_color = "\033[0m";   // 恢复样式
		static constexpr std::string_view time_color = "\033[3;4m";  // 斜体+下划线
		static constexpr std::string_view path_color = "\033[0;37m"; // 灰色
		static constexpr std::string_view file_color = "\033[1;35m"; // 亮洋红
		static constexpr std::string_view line_color = "\033[1;33m"; // 黄色
		static constexpr std::string_view func_pre_color = "\033[0;37m"; // 灰色
		static constexpr std::string_view func_core_color = "\033[1;36m"; // 青色
		static constexpr std::string_view tag_color = "\033[4;7m";  // 下划线+反色

		std::ostringstream ss{};
		const auto& [tag, msg_color] = level_config[enum_integer(level)];

		const bool new_line = mask & ~~Mask::NEW_LINE;
		const bool show_time = mask & ~~Mask::SHOW_TIME;
		const bool color_time = show_color && show_time && (mask & ~~Mask::COLOR_TIME);
		const bool show_source_info = mask & ~~Mask::SHOW_SRC_INFO;
		const bool color_source_info = show_color && show_source_info && (mask & ~~Mask::COLOR_SRC_INFO);
		const bool show_tag = mask & ~~Mask::SHOW_TAG;
		const bool color_tag = show_color && show_tag && (mask & ~~Mask::COLOR_TAG);
		const bool show_message = mask & ~~Mask::SHOW_MESSAGE;
		const bool color_message = show_color && show_message && (mask & ~~Mask::COLOR_MESSAGE);
		const bool end_line = mask & ~~Mask::END_LINE;

		if (new_line) 
			ss << '\n';
		if (color_time)
			ss << time_color;
		if (show_time)
			ss << GetCurrentTimeStr();
		if (color_time)
			ss << reset_color;
		if (show_time)
			ss << "  ";
		if (color_source_info)
			ss << path_color;
		if (show_source_info)
			ss << src_info.path << "\\";
		if (color_source_info)
			ss << file_color;
		if (show_source_info)
			ss << src_info.filename << ":";
		if (color_source_info)
			ss << line_color;
		if (show_source_info)
			ss << src_info.line <<" ";
		if (color_source_info)
			ss << func_pre_color;
		if (show_source_info)
			ss << src_info.function_prefix;
		if (color_source_info)
			ss << func_core_color;
		if (show_source_info)
			ss << src_info.function_core << "():\n";
		if (color_source_info)
			ss << reset_color;
		if (color_tag)
			ss << msg_color << tag_color;
		if (show_tag)
			ss << tag;
		if (color_tag)
			ss << reset_color;
		if (show_tag)
			ss << " ";
		if (color_message)
			ss << msg_color;
		if (show_message)
			ss << message;
		if (color_message)
			ss << reset_color;
		if (end_line)
			ss << '\n';

		return ss.str();
	};


	const uint32_t task_mask = mask ? mask : _mask;
	const Logger::Level task_level = level;

	SourceInfo souce_info{};
	if (task_mask & ~~Logger::Mask::SHOW_SRC_INFO) souce_info = ParseSourceInfo(loc);

	if (!(task_mask & (1u << enum_integer(level))))
		return;

	const bool show_color = task_mask & ~~Logger::Mask::SHOW_COLOR;

	//这里要处理一下string_view和string析构的问题
	std::string msg(message);
	auto logging_task = [this, task_mask, task_level, souce_info, msg, show_color](bool should_flush = false) -> void
	{
		std::ostream& output_stream = (task_level == Logger::Level::ERROR || task_level == Logger::Level::FATAL) ? std::cerr : std::cout;

		if (_mask & ~~Logger::Mask::LOG_TO_CONSOLE)
		{
			std::string log_text = generate_text(task_mask, task_level, souce_info, msg, show_color);
			std::osyncstream(output_stream) << log_text; //这里使用osyncstream代替了锁
			if(should_flush) output_stream.flush();
		}
		if (_mask & ~~Logger::Mask::LOG_TO_FILE)
		{
			std::string log_text = generate_text(task_mask, task_level, souce_info, msg, false);
			LogToFile(log_text, task_mask);
			if (should_flush) _fs.flush();
		}
	};

	// 对于非致命级别的日志，用 std::thread deatch() 异步写日志，不会阻塞主线程
	if (level != Logger::Level::FATAL)
	{
		std::thread
		(
			[this, logging_task]()
			{
				logging_task();
			}
		).detach();
	}
	else // FATAL 级别则同步写日志
	{
		logging_task(true);
		throw std::runtime_error(msg);
	}
}

/// ----------- Public Function ------------


/// ----------- Private Function ------------


template <Printable... Types>
inline void Logger::DoLog(Level level, const std::string_view sv, const std::tuple<Types...>& tpl_args, uint32_t mask, const std::source_location& loc)
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
		std::ostringstream ss{};
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
		Print(level, ss.str(), mask, loc);
	}
}

inline Logger::SourceInfo  Logger::ParseSourceInfo(const std::source_location& loc) {
	static const std::regex lambda_regex(R"(.*lambda_[0-9]+.*)");
	static const std::regex func_regex(R"((.*::)?([~]?[A-Za-z_][A-Za-z0-9_]*)\s*(<.*>)?\s*\(.*\))");

	std::filesystem::path full_path(loc.file_name());
	Logger::SourceInfo info
	{
		.path = full_path.parent_path().string(),
		.filename = full_path.filename().string(),
		.function_prefix = {},
		.function_core = {},
		.line = loc.line()
	};

	std::smatch match;
	const std::string func_name(loc.function_name());

	if (std::regex_search(func_name, lambda_regex)) {
		info.function_core = "[lambda]";
	}
	else if (std::regex_search(func_name, match, func_regex)) {
		info.function_prefix = match[1].str();
		info.function_core = match[2].str();
	}
	return info;
}

inline void Logger::SetLogFile(const std::filesystem::path& filename, uint32_t mask)
{
	static const auto handle_exception = [](Logger& self, uint32_t mask, const std::filesystem::path& filepath, const std::string_view message)
	{
		const uint32_t mask_do_not_print_to_file = mask & ~Logger::Mask::LOG_TO_FILE;
		self.Log(Logger::Level::ERROR, "Set File {} failed : {}", std::tuple(filepath.string(), message), mask_do_not_print_to_file);
	};

	std::scoped_lock<std::mutex> lock(_mutex);

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
		handle_exception(*this, mask, filename, e.what());
	}
	catch (...)
	{
		handle_exception(*this, mask, filename, "Unknown exception");
	}
}

inline bool Logger::RotateLogFile(uint32_t try_count, std::chrono::milliseconds time_ms, uint32_t mask)
{
	for (uint32_t i = 0; i < try_count; ++i)
	{
		static const auto handle_exception = [](Logger& self, uint32_t mask, const std::filesystem::path& filepath, uint32_t try_count,
			uint32_t i, const std::string_view message)
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
			const auto zt = std::chrono::zoned_time{ std::chrono::current_zone(), std::chrono::system_clock::now() };
			const std::string_view time_str = std::format("{:%y-%m-%d-%H-%M-%S}", zt.get_local_time());
			const std::string_view stem_str = _filename.stem().string();
			const std::string_view extension_str = _filename.extension().string();
			const auto new_name = _filename.parent_path() / std::format("{}_{}_{}{}",
				stem_str,
				time_str,
				i,
				extension_str
			);

			std::lock_guard<std::mutex> lock(_mutex);
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

		if (i < try_count - 1)
		{
			std::this_thread::sleep_for(time_ms); //todo:这里使用协程调度
		}
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

	static const auto handle_exception = [](Logger& self, uint32_t mask, const std::filesystem::path& filepath, const std::string_view message)
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

/// ----------- Private Function ------------

//// ---------- DEBUG Level ----------

inline void LogDebugHelper(const std::string& s, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::DEBUG, s, mask, loc);
}

template <Printable... Args>
inline void LogDebugHelper(const std::format_string<Args...>& fmt, const std::tuple<Args...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::DEBUG, fmt, tpl_args, mask, loc);
}

//// ---------- INFO Level ----------

inline void LogInfoHelper(const std::string& s, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::INFO, s, mask, loc);
}

template <Printable... Args>
inline void LogInfoHelper(const std::format_string<Args...>& fmt, const std::tuple<Args...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::INFO, fmt, tpl_args, mask, loc);
}

//// ---------- NORMAL Level ----------

inline void LogNormalHelper(const std::string& s, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NORMAL, s, mask, loc);
}

template <Printable... Args>
inline void LogNormalHelper(const std::format_string<Args...>& fmt, const std::tuple<Args...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NORMAL, fmt, tpl_args, mask, loc);
}

//// ---------- NOTICE Level ----------

inline void LogNoticeHelper(const std::string& s, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NOTICE, s, mask, loc);
}

template <Printable... Args>
inline void LogNoticeHelper(const std::format_string<Args...>& fmt, const std::tuple<Args...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NOTICE, fmt, tpl_args, mask, loc);
}

//// ---------- WARNING Level ----------

inline void LogWarnHelper(const std::string& s, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::WARNING, s, mask, loc);
}

template <Printable... Args>
inline void LogWarnHelper(const std::format_string<Args...>& fmt, const std::tuple<Args...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::WARNING, fmt, tpl_args, mask, loc);
}

//// ---------- ERROR Level ----------

inline void LogErrorHelper(const std::string& s, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::ERROR, s, mask, loc);
}

template <Printable... Args>
inline void LogErrorHelper(const std::format_string<Args...>& fmt, const std::tuple<Args...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::ERROR, fmt, tpl_args, mask, loc);
}

//// ---------- FATAL Level ----------

inline void LogFatalHelper(const std::string& s, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::FATAL, s, mask, loc);
}

template <Printable... Args>
inline void LogFatalHelper(const std::format_string<Args...>& fmt, const std::tuple<Args...>& tpl_args, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::FATAL, fmt, tpl_args, mask, loc);
}