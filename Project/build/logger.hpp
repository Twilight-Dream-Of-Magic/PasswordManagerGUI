#pragma once

#include <regex>

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
		SHOW_NORMAL = 1 << 0,
		SHOW_WARNING = 1 << 1,
		SHOW_ERROR = 1 << 2,
		SHOW_NOTICE = 1 << 3,
		SHOW_DEBUG = 1 << 4,
		SHOW_INFO = 1 << 5,
		SHOW_TAG = 1 << 6,
		SHOW_TIME = 1 << 7,
		SHOW_COLOR = 1 << 8,
		SHOW_MESSAGE = 1 << 9,
		NEW_LINE = 1 << 10,
		END_LINE = 1 << 11,
		LOG_TO_CONSOLE = 1 << 12,
		LOG_TO_FILE = 1 << 13,
		SHOW_SRC_INFO = 1 << 14
	};

	friend auto operator|( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator&( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator^( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator~( Logger::Mask a ) -> std::underlying_type_t<Logger::Mask>;

	static Logger& Instance();

	template<typename STR> requires(std::is_convertible_v<STR, std::string>)
	void Log(Logger::Level level, const STR& str, const std::source_location& loc = std::source_location::current())
	{
		Print(level, str, loc);
	}

	template <Printable... Types>
	void Log(Level level, const std::format_string<Types...> fmt, const std::tuple<Types...>& tpl_args, const std::source_location& loc = std::source_location::current())
	{
		DoLog(level, fmt.get(), tpl_args, loc);
	}

	~Logger();

	uint32_t SetMask( uint32_t mask );

	void SetLogFile( const std::filesystem::path& filename );

private:
	template <Printable... Types>
	void DoLog(Level level,const std::string_view sv, const std::tuple<Types...>& tpl_args, const std::source_location& loc = std::source_location::current())
	{
		try
		{
			auto formatted = std::apply
			(
				[&](const Types&... args)
				{
					return std::vformat(sv, std::make_format_args(args...));
				}, 
				tpl_args
			);
			Print(level, formatted, loc);
		}
		catch (const std::format_error&)
		{
			std::stringstream ss;
			ss << sv;
			std::apply
			(
				[&](const Types&... args) 
				{
					((ss << args), ...);
				},
				tpl_args
			);
			Print(level, ss.str(), loc);
		}
	}

	Logger();

	void Print( Logger::Level level, const std::string_view message, const std::source_location& loc = std::source_location::current());
	
	bool RotateLogFile(/*uint32_t try_count = 1, std::chrono::milliseconds t = std::chrono::milliseconds(3)*/);

	void LogToFile(const std::string& str );

	std::string GetCurrentTimeStr();

	static constexpr size_t MAX_FILE_SIZE = 1024 * 1024;
	std::ofstream			_fs;
	std::mutex				_mutex;
	std::filesystem::path	_filename;
	uint32_t				_mask = uint32_t(-1);
};

// Singleton Mode
inline Logger& Logger::Instance()
{
	static Logger instance;
	return instance;
}

// 这里是不是public的，所以可以用string_view
inline void Logger::Print( Logger::Level level, const std::string_view message, const std::source_location& loc)
{
	using tag_str = std::string_view;
	using color_str = std::string_view;
	using level_config_t = std::tuple<tag_str, color_str>;

	static const auto enum_integer = []( Logger::Level level ) -> size_t
	{
		return static_cast<std::underlying_type_t<Logger::Level>>( level );
	};

	static const std::array<level_config_t, enum_integer(Level::MAX_LENGTH)> level_config
	(
		{
		{"(DEBUG) ",		"\033[1;36m"},  // DEBUG: 青色
		{"(INFO)" ,			"\033[1;32m"},  // INFO: 绿色
		{" ",				"\033[1;37m"},  // NORMAL: 白色/浅灰
		{"(NOTICE) ",		"\033[1;34m"},  // NOTICE: 蓝色
		{"(WARNING) ",		"\033[1;33m"},  // WARNING: 黄色
		{"(ERROR) ",		"\033[1;31m"},  // ERROR: 红色
		{"(FATAL) ",		"\033[1;91m"}   // FATAL: 亮红色	
		}
	);

	static const auto& [tag, color] = level_config[ enum_integer( level ) ];

	static const auto generate_source_info = [](const std::source_location& loc) -> std::string 
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
				function_name = std::format("\033[0;37m{}\033[1;36m{}\033[0m", prefix, core_func);
				// 这里决定隐藏参数信息
				//std::string params = match[4].str();	// 参数列表
				//function_name = std::format("\033[0;37m{} \033[1;36m{}\033[0m\033[0;37m{}\033[0m", prefix, core_func, params);
			}
		}

		return std::format
		(
			"  \033[0;37m{}\\\033[1;35m{}\033[0m:\033[1;33m{}\033[0m {}():\n",
			path, filename, loc.line(), function_name
		);
	};

	static const char* reset_color_str = "\033[0m";

	static const auto generate_text = [](Logger& self, Logger::Level level, const std::source_location& loc, const std::string_view message, bool show_color) -> std::stringstream
	{
		std::stringstream		ss;
		auto					time_str = self.GetCurrentTimeStr();
		if (self._mask & ~~Logger::Mask::NEW_LINE)
			ss << '\n';
		if (self._mask & ~~Logger::Mask::SHOW_TIME)
			ss << time_str;
		if (self._mask & ~~Logger::Mask::SHOW_SRC_INFO)
			ss << generate_source_info(loc);
		if (self._mask & ~~Logger::Mask::SHOW_COLOR && show_color)
			ss << reset_color_str << color;
		if (self._mask & ~~Logger::Mask::SHOW_TAG)
			ss << tag;
		if (self._mask & ~~Logger::Mask::SHOW_MESSAGE)
			ss << message;
		if (self._mask & ~~Logger::Mask::END_LINE)
			ss << '\n';
		if (self._mask & ~~Logger::Mask::SHOW_COLOR && show_color)
			ss << reset_color_str;
		return ss;
	};

	if ( !( _mask & ( 1u << enum_integer( level ) ) ) )
		return;

	auto logging_task = [this, level, loc, message]() -> void
	{
		std::ostream& output_stream = ( level == Logger::Level::ERROR ) ? std::cerr : std::cout;
		if (_mask & ~~Logger::Mask::LOG_TO_CONSOLE)
			output_stream << generate_text(*this, level, loc, message, true).str();
		if (_mask & ~~Logger::Mask::LOG_TO_FILE)
			LogToFile(generate_text(*this, level, loc, message, false).str());
	};

	// 对于非致命级别的日志，用 std::thread deatch() 异步写日志，不会阻塞主线程
	if(level != Logger::Level::FATAL)
	{
		std::thread
		(
			[this, logging_task]()
			{
				std::lock_guard<std::mutex> lock(_mutex);
				logging_task();
			}
		).detach();
	}
	else // FATAL 级别则同步写日志，确保日志输出后再抛异常退出
	{
		std::unique_lock<std::mutex> lock(_mutex);
		logging_task();
		lock.unlock();
		throw std::runtime_error(message.data());
	}
}

inline Logger::Logger()
{
	SetLogFile( "./log.txt" );
}

inline Logger::~Logger()
{
	if(this->_fs.is_open())
		this->_fs.close();
	this->_filename.clear();
	std::cout << std::flush;
	std::cerr << std::flush;
}

inline uint32_t Logger::SetMask( uint32_t mask )
{
	std::scoped_lock lock( _mutex );
	auto			 old_mask = _mask;
	_mask = mask;
	return old_mask;
}

inline void Logger::SetLogFile( const std::filesystem::path& filename )
{
	auto Rollbackor = RollBackor(_mask);

	if ( _fs.is_open() )
	{
		_fs.close();
	}
	try // todo: 真的处理各种可能异常，并解决
	{
		std::filesystem::create_directories( filename.parent_path() );
		_fs.open( filename, std::ios::app );
		_filename = filename;
	}
	catch ( const std::exception& e )
	{
		_mask = _mask & ~Logger::Mask::LOG_TO_FILE;
		std::string error_msg = "Failed to open log file " + _filename.string() + " : " + e.what();
		Log( Logger::Level::ERROR, error_msg );
	}
	catch ( ... )
	{
		_mask = _mask & ~Logger::Mask::LOG_TO_FILE;
		std::string error_msg = "Failed to open log file " + _filename.string() + "： Unknown exception";
		Log( Logger::Level::ERROR, error_msg );
	}
}

// todo: 设置重试次数和时间，名称改为TryRotateLogFile
inline bool Logger::RotateLogFile(/*uint32_t try_count, std::chrono::milliseconds t*/)
{
	try
	{
		if ( _fs.is_open() )
			_fs.close();

		auto new_name = _filename.parent_path() / std::format( "{}_{:%Y%m%d_%H%M%S}{}", _filename.stem().string(), std::chrono::system_clock::now(), _filename.extension().string() );

		std::filesystem::rename( _filename, new_name );
		_fs.open( _filename, std::ios::app );
	}
	catch ( const std::exception& e )
	{
		_mask &= ~Mask::LOG_TO_FILE;
		std::string error_msg = std::string( "Rotate failed: " ) + e.what();
		Log( Logger::Level::ERROR, error_msg );
	}
	catch (...)
	{
		_mask &= ~Mask::LOG_TO_FILE;
		std::string error_msg = "Failed to Rotate log file " + _filename.string() + " : Unknown exception";
		Log(Logger::Level::ERROR, error_msg);
	}
	return true;
}

inline void Logger::LogToFile( const std::string& str )
{
	auto Rollbackor = RollBackor( _mask );

	if ( std::filesystem::exists( _filename ) && std::filesystem::file_size( _filename ) >= MAX_FILE_SIZE )
	{
		RotateLogFile();
	}

	try
	{
		_fs << str;
		_fs.flush();
	}
	catch ( const std::exception& e )
	{
		_mask &= ~Mask::LOG_TO_FILE;
		std::string error_msg = "Failed to log to file " + _filename.string() + " : " + e.what();
		Log( Logger::Level::ERROR, error_msg );
	}
	catch ( ... )
	{
		_mask &= ~Mask::LOG_TO_FILE;
		std::string error_msg = "Failed to log to file " + _filename.string() + " : Unknown exception";
		Log( Logger::Level::ERROR, error_msg );
	}
}

inline std::string Logger::GetCurrentTimeStr()
{
	auto zt = std::chrono::zoned_time { std::chrono::current_zone(), std::chrono::system_clock::now() };
	return std::format( "[{:%Y-%m-%d %H:%M:%S}]", zt );
}

inline auto operator|( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>
{
	return ( std::underlying_type_t<Logger::Mask>( a ) | std::underlying_type_t<Logger::Mask>( b ) );
}

inline auto operator&( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>
{
	return ( std::underlying_type_t<Logger::Mask>( a ) & std::underlying_type_t<Logger::Mask>( b ) );
}

inline auto operator^( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>
{
	return ( std::underlying_type_t<Logger::Mask>( a ) ^ std::underlying_type_t<Logger::Mask>( b ) );
}

inline auto operator~( Logger::Mask a ) -> std::underlying_type_t<Logger::Mask>
{
	return ( ~std::underlying_type_t<Logger::Mask>( a ) );
}

//// ---------- DEBUG 级别 ----------

inline void LogDebugHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log( Logger::Level::DEBUG, s , loc);
}

template <Printable... Args>
inline void LogDebugHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::DEBUG, fmt, tpl_args, loc);
}

//// ---------- INFO 级别 ----------

inline void LogInfoHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::INFO, s, loc);
}

template <Printable... Args>
inline void LogInfoHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::INFO, fmt, tpl_args, loc);
}

//// ---------- NORMAL 级别 ----------

inline void LogNormalHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NORMAL, s, loc);
}

template <Printable... Args>
inline void LogNormalHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NORMAL, fmt, tpl_args, loc);
}

//// ---------- NOTICE 级别 ----------

inline void LogNoticeHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NOTICE, s, loc);
}

template <Printable... Args>
inline void LogNoticeHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::NOTICE, fmt, tpl_args, loc);
}

//// ---------- WARNING 级别 ----------

inline void LogWarnHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::WARNING, s, loc);
}

template <Printable... Args>
inline void LogWarnHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::WARNING, fmt, tpl_args, loc);
}

//// ---------- ERROR 级别 ----------

inline void LogErrorHelper(const std::string& s, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::ERROR, s, loc);
}

template <Printable... Args>
inline void LogErrorHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::ERROR, fmt, tpl_args, loc);
}

//// ---------- FATAL 级别 ----------

inline void LogFatalHelper(const std::string & s, const std::source_location & loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::FATAL, s, loc);
}

template <Printable... Args>
inline void LogFatalHelper(const std::format_string<Args...> fmt, const std::tuple<Args...>& tpl_args, const std::source_location& loc = std::source_location::current())
{
	Logger::Instance().Log(Logger::Level::FATAL, fmt, tpl_args, loc);
}
