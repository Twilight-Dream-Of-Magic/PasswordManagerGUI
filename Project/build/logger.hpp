#pragma once

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
	};

	inline friend auto operator|( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>;

	inline friend auto operator&( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>;

	inline friend auto operator^( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>;

	inline friend auto operator~( Logger::Mask a ) -> std::underlying_type_t<Logger::Mask>;

	static Logger& Instance();

	void Log(Logger::Level level, std::string& str);

	void Log(Logger::Level level, std::string&& str);

	// 可变参模板：接受一个「格式字符串 + N 个可打印参数」
	template <Printable... Types>
	void Log( Level level, const std::string& str, Types&&... args )
	{
		try
		{
			// 运行时格式化
			auto formatted = std::vformat( str, std::make_format_args( std::forward<Types>( args )... ) );
			Print( level, formatted );
		}
		catch ( const std::format_error& )
		{
			// 如果格式字符串与参数不匹配，降级为 stringstream
			std::stringstream ss;
			ss << str;
			( ( ss << std::forward<Types>( args ) ), ... );
			Print( level, ss.str() );
		}
	}

	template <Printable... Types>
	void Log( Level level, std::string&& str, Types&&... args )
	{
		try
		{
			auto formatted = std::vformat( str, std::make_format_args( std::forward<Types>( args )... ) );
			Print( level, formatted );
		}
		catch ( const std::format_error& )
		{
			std::stringstream ss;
			ss << str;
			( ( ss << std::forward<Types>( args ) ), ... );
			Print( level, ss.str() );
		}
	}

	~Logger();

	uint32_t SetMask( uint32_t mask );

	void SetLogFile( const std::filesystem::path& filename );

private:
	//Logger() = default;
	Logger();

	void Print( Logger::Level level, const std::string& message );

	void RotateLogFile();

	void LogToFile( const std::string& str );

	std::string GetCurrentTimeStr();

	static constexpr size_t MAX_FILE_SIZE = 1024 * 1024;
	std::ofstream			_fs;
	std::mutex				_mutex;
	std::filesystem::path	_filename;
	uint32_t				_mask = 0xFFFF;
};

inline Logger& Logger::Instance()
{
	static Logger instance;
	return instance;
}

inline void Logger::Print( Logger::Level level, const std::string& message )
{
	static const auto enum_integer = []( Logger::Level level ) -> size_t
	{
		return static_cast<std::underlying_type_t<Logger::Level>>( level );
	};

	static const std::array<const char*, enum_integer( Level::MAX_LENGTH )> color_strs
	{
		"\033[36m",  // DEBUG: 青色
		"\033[32m",  // INFO: 绿色
		"\033[37m",  // NORMAL: 白色/浅灰
		"\033[34m",  // NOTICE: 蓝色
		"\033[33m",  // WARNING: 黄色
		"\033[31m",  // ERROR: 红色
		"\033[91m"   // FATAL: 亮红色
	};

	static const std::array<const char*, enum_integer( Level::MAX_LENGTH )> tags { "(DEBUG)", "(INFO)", " ", "(NOTICE)", "(WARNING)", "(ERROR)", "(FATAL)" };
	static const auto get_colors = []( Logger::Level level ) -> const char*
	{
		return color_strs[ enum_integer( level ) ];
	};

	static const auto get_tag = []( Logger::Level level ) -> const char*
	{
		return tags[ enum_integer( level ) ];
	};

	static const char* reset_color_str = "\033[0m";
	if ( !( _mask & ( 1u << enum_integer( level ) ) ) )
		return;
	std::lock_guard<std::mutex> lock( _mutex );	 // 这里加锁是因为cout只是逐字符线程安全的
	std::stringstream			ss;
	std::ostream&				output_stream = ( level == Logger::Level::ERROR ) ? std::cerr : std::cout;
	auto						time_str = GetCurrentTimeStr();

	if ( _mask & ~~Logger::Mask::SHOW_TIME )
		ss << time_str;
	if ( _mask & ~~Logger::Mask::SHOW_TAG )
		ss << get_tag( level );
	if ( _mask & ~~Logger::Mask::SHOW_MESSAGE )
		ss << message;
	if ( _mask & ~~Logger::Mask::END_LINE )
		ss << '\n';
	if ( _mask & ~~Logger::Mask::SHOW_COLOR )
		output_stream << get_colors( level );
	if ( _mask & ~~Logger::Mask::LOG_TO_CONSOLE )
		output_stream << ss.str();
	if ( _mask & ~~Logger::Mask::SHOW_COLOR )
		output_stream << reset_color_str;
	if ( _mask & ~~Logger::Mask::LOG_TO_FILE )
		LogToFile( ss.str() );

	if(level == Logger::Level::FATAL)
	{
		//throw std::runtime_error(message);
		std::terminate();
	}
}

inline void Logger::Log( Logger::Level level, std::string& str )
{
	Print( level, str );
}

inline void Logger::Log( Logger::Level level, std::string&& str )
{
	Print( level, str );
}

inline Logger::~Logger()
{
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
	std::scoped_lock lock( _mutex );
	static auto		 mask0 = _mask;
	auto			 SG = ScopeGuard<uint32_t>( _mask, []( uint32_t& mask ) { mask = mask0; } );

	if ( _fs.is_open() )
	{
		_fs.close();
	}
	try
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

//Logger() = default;

inline Logger::Logger()
{
	SetLogFile( "./log.txt" );
}

inline void Logger::RotateLogFile()
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
		_mask &= ~static_cast<uint32_t>( Mask::LOG_TO_FILE );
		std::string error_msg = std::string( "Rotate failed: " ) + e.what();
		Log( Logger::Level::ERROR, error_msg );
	}
}

inline void Logger::LogToFile( const std::string& str )
{
	static auto mask0 = _mask;
	auto		SG = ScopeGuard<uint32_t>( _mask, []( uint32_t& mask ) { mask = mask0; } );

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
		_mask = _mask & ~Logger::Mask::LOG_TO_FILE;
		std::string error_msg = "Failed to log to file " + _filename.string() + " : " + e.what();
		Log( Logger::Level::ERROR, error_msg );
	}
	catch ( ... )
	{
		_mask = _mask & ~Logger::Mask::LOG_TO_FILE;
		std::string error_msg = "Failed to log to file " + _filename.string() + " : Unknown exception";
		Log( Logger::Level::ERROR, error_msg );
	}
}

inline std::string Logger::GetCurrentTimeStr()
{
	auto zt = std::chrono::zoned_time { std::chrono::current_zone(), std::chrono::system_clock::now() };
	return std::format( "[{:%Y-%m-%d %H:%M:%S}]", zt );
}

auto operator|( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>
{
	return ( std::underlying_type_t<Logger::Mask>( a ) | std::underlying_type_t<Logger::Mask>( b ) );
}

auto operator&( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>
{
	return ( std::underlying_type_t<Logger::Mask>( a ) & std::underlying_type_t<Logger::Mask>( b ) );
}

auto operator^( Logger::Mask a, Logger::Mask b ) -> std::underlying_type_t<Logger::Mask>
{
	return ( std::underlying_type_t<Logger::Mask>( a ) ^ std::underlying_type_t<Logger::Mask>( b ) );
}

auto operator~( Logger::Mask a ) -> std::underlying_type_t<Logger::Mask>
{
	return ( ~std::underlying_type_t<Logger::Mask>( a ) );
}

// ---------- DEBUG 级别 ----------

inline void LogDebugHelper( std::string& sv )
{
	Logger::Instance().Log( Logger::Level::DEBUG, sv );
}

inline void LogDebugHelper( std::string&& sv )
{
	Logger::Instance().Log( Logger::Level::DEBUG, sv );
}

template <Printable... Args>
inline void LogDebugHelper( std::string_view str_view, Args&&... args )
{
	std::string info = std::string(str_view.begin(), str_view.end());
	Logger::Instance().Log( Logger::Level::DEBUG, info, args... );
}

template <std::convertible_to<std::string> StringType, Printable... Args>
inline void LogDebugHelper( const StringType&& str, Args&&... args, const std::source_location& loc = std::source_location::current() )
{
	std::string source_location_info = std::format( "[{}:{} {}] ", loc.file_name(), loc.line(), loc.function_name() );
	Logger::Instance().Log( Logger::Level::DEBUG, source_location_info + str, args );
}

// ---------- INFO 级别 ----------

inline void LogInfoHelper( const std::string& str )
{
	Logger::Instance().Log( Logger::Level::INFO, str );
}

inline void LogInfoHelper( std::string&& str )
{
	Logger::Instance().Log( Logger::Level::INFO, str );
}

template <Printable... Args>
inline void LogInfoHelper( std::string_view str_view, Args&&... args )
{
	std::string info = std::string(str_view.begin(), str_view.end());
	Logger::Instance().Log( Logger::Level::INFO, info, args... );
}

template <std::convertible_to<std::string> StringType, Printable... Args>
inline void LogInfoHelper( const StringType&& str, Args&&... args, const std::source_location& loc = std::source_location::current() )
{
	std::string source_location_info = std::format( "[{}:{} {}] ", loc.file_name(), loc.line(), loc.function_name() );
	Logger::Instance().Log( Logger::Level::INFO, source_location_info + str, args... );
}

// ---------- NORMAL 级别 ----------

inline void LogNormalHelper( const std::string& str )
{
	Logger::Instance().Log( Logger::Level::NORMAL, str );
}

inline void LogNormalHelper( std::string&& str )
{
	Logger::Instance().Log( Logger::Level::NORMAL, str );
}

template <Printable... Args>
inline void LogNormalHelper( std::string_view str_view, Args&&... args )
{
	std::string info = std::string(str_view.begin(), str_view.end());
	Logger::Instance().Log( Logger::Level::NORMAL, info, args... );
}

template <std::convertible_to<std::string> StringType, Printable... Args>
inline void LogNormalHelper( const StringType&& str, Args&&... args, const std::source_location& loc = std::source_location::current() )
{
	std::string source_location_info = std::format( "[{}:{} {}] ", loc.file_name(), loc.line(), loc.function_name() );
	Logger::Instance().Log( Logger::Level::NORMAL, source_location_info + str, args... );
}

// ---------- NOTICE 级别 ----------

inline void LogNoticeHelper( const std::string& str )
{
	Logger::Instance().Log( Logger::Level::NOTICE, str );
}

inline void LogNoticeHelper( std::string&& str )
{
	Logger::Instance().Log( Logger::Level::NOTICE, str );
}

template <Printable... Args>
inline void LogNoticeHelper( std::string_view str_view, Args&&... args )
{
	std::string info = std::string(str_view.begin(), str_view.end());
	Logger::Instance().Log( Logger::Level::NOTICE, info, args... );
}

template <std::convertible_to<std::string> StringType, Printable... Args>
inline void LogNoticeHelper( const StringType&& str, Args&&... args, const std::source_location& loc = std::source_location::current() )
{
	std::string source_location_info = std::format( "[{}:{} {}] ", loc.file_name(), loc.line(), loc.function_name() );
	Logger::Instance().Log( Logger::Level::NOTICE, source_location_info + str, args... );
}

// ---------- WARNING 级别 ----------

inline void LogWarnHelper( const std::string& str )
{
	Logger::Instance().Log( Logger::Level::WARNING, str );
}

inline void LogWarnHelper( std::string&& str )
{
	Logger::Instance().Log( Logger::Level::WARNING, str );
}

template <Printable... Args>
inline void LogWarnHelper( std::string_view str_view, Args&&... args )
{
	std::string info = std::string(str_view.begin(), str_view.end());
	Logger::Instance().Log( Logger::Level::WARNING, info, args... );
}

template <std::convertible_to<std::string> StringType, Printable... Args>
inline void LogWarnHelper( const StringType&& str, Args&&... args, const std::source_location& loc = std::source_location::current() )
{
	std::string source_location_info = std::format( "[{}:{} {}] ", loc.file_name(), loc.line(), loc.function_name() );
	Logger::Instance().Log( Logger::Level::WARNING, source_location_info + str, args... );
}

// ---------- ERROR 级别 ----------

inline void LogErrorHelper( const std::string& str )
{
	Logger::Instance().Log( Logger::Level::ERROR, str );
}

inline void LogErrorHelper( std::string&& str )
{
	Logger::Instance().Log( Logger::Level::ERROR, str );
}

template <Printable... Args>
inline void LogErrorHelper( std::string_view str_view, Args&&... args )
{
	std::string info = std::string(str_view.begin(), str_view.end());
	Logger::Instance().Log( Logger::Level::ERROR, info, args... );
}

template <std::convertible_to<std::string> StringType, Printable... Args>
inline void LogErrorHelper( const StringType&& str, Args&&... args, const std::source_location& loc = std::source_location::current() )
{
	std::string source_location_info = std::format( "[{}:{} {}] ", loc.file_name(), loc.line(), loc.function_name() );
	Logger::Instance().Log( Logger::Level::ERROR, source_location_info + str, args... );
}

// ---------- FATAL 级别 ----------

inline void LogFatalHelper( const std::string& str )
{
	Logger::Instance().Log( Logger::Level::FATAL, str );
}

inline void LogFatalHelper( std::string&& str )
{
	Logger::Instance().Log( Logger::Level::FATAL, str );
}

template <Printable... Args>
inline void LogFatalHelper( std::string_view str_view, Args&&... args )
{
	std::string info = std::string(str_view.begin(), str_view.end());
	Logger::Instance().Log( Logger::Level::FATAL, info, args... );
}

template <std::convertible_to<std::string> StringType, Printable... Args>
inline void LogFatalHelper( const StringType&& str, Args&&... args, const std::source_location& loc = std::source_location::current() )
{
	std::string source_location_info = std::format( "[{}:{} {}] ", loc.file_name(), loc.line(), loc.function_name() );
	Logger::Instance().Log( Logger::Level::FATAL, source_location_info + str, args... );
}
