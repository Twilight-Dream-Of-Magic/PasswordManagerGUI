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

	struct SourceInfo
	{
		std::string_view path;
		std::string_view filename;
		std::string_view function_prefix;
		std::string_view function_core;
		uint_least32_t line;
	};

	struct LogTask
	{
		Logger::SourceInfo source_info;
		std::string message;
		std::underlying_type_t<Logger::Mask> mask;
		Logger::Level level;

		template<typename SrcInfo, typename Msg>
			requires
		std::constructible_from<Logger::SourceInfo, SrcInfo&&>&&
			std::constructible_from<std::string, Msg&&>
			LogTask
			(
				SrcInfo&& src,
				Msg&& msg,
				std::underlying_type_t<Logger::Mask> msk,
				Logger::Level lvl
			)
			noexcept
			(
				std::is_nothrow_constructible_v<Logger::SourceInfo, SrcInfo&&>&&
				std::is_nothrow_constructible_v<std::string, Msg&&>
				)
			:
			source_info(std::forward<SrcInfo>(src)),
			message(std::forward<Msg>(msg)),
			mask(msk),
			level(lvl) {
		}

		LogTask(const LogTask&) noexcept = default;
		LogTask& operator=(const LogTask&) noexcept = default;
		LogTask(LogTask&&) noexcept = default;
		LogTask& operator=(LogTask&&) noexcept = default;
	};

	class LogSink
	{
	public:
		virtual ~LogSink() = default;

		virtual void BeforeWrite(size_t task_queue_len) = 0;
		virtual void Write(std::span<const LogTask> tasks) = 0;
		virtual void Flush() = 0;
	};

	class DefaultConsoleSink;
	class DefaultFileSink;

	friend auto operator|(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator&(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator^(Logger::Mask a, Logger::Mask b) -> std::underlying_type_t<Logger::Mask>;

	friend auto operator~(Logger::Mask a) -> std::underlying_type_t<Logger::Mask>;

	static Logger& Instance();

	~Logger();

	void Init(std::filesystem::path filepath = "./log.txt", uint32_t logmask = 0xFFFFFFFFu);

	void InitWithOutDefaultSink(uint32_t logmask = 0xFFFFFFFFu);

	void AppendSink(std::unique_ptr<Logger::LogSink> sink);

	void StopAndWaitAll();

	uint32_t SetDefaultMask(uint32_t mask);

	uint32_t GetDefaultMask() const;

	void SetDefaultMaskFlag(Logger::Mask flag);

	void UnsetDefaultMaskFlag(Logger::Mask flag);

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

	void AppendTask(Logger::LogTask&& task);

	void BackgourndThreadLoop(std::stop_token st);

	static std::string GetCurrentTimeStr();

	static SourceInfo ParseSourceInfo(const std::source_location& loc);

	enum class GenLogTextProxy
	{
		LogToConsole,
		LogToFile,
		//LogToNetwork,
		//LogToDataBase
	};

	template <Logger::GenLogTextProxy Proxy>
	static std::string GenerateLogText(const Logger::LogTask& task);

	template <typename>
	static constexpr bool always_false = false;
	static constexpr size_t MAX_BUFFER_SIZE = 256u;
	static constexpr size_t MAX_BACK_BUFFER_LEN = 24u;

	std::mutex				mutex_;
	std::condition_variable cv_;
	std::deque<std::vector<Logger::LogTask>> backbuffers_;
	std::deque<std::vector<Logger::LogTask>> recycled_buffers_;
	std::deque<std::unique_ptr<Logger::LogSink>> sinks_;
	std::vector<Logger::LogTask> frontbuffer_;
	std::optional<std::jthread> background_thread_;
	uint32_t				default_mask_ = 0xFFFFFFFFu;
};

/// ----------- SinK Class ------------

class Logger::DefaultFileSink : public Logger::LogSink
{
public:
	explicit DefaultFileSink(const std::filesystem::path& path, size_t max_flie_size = 1024 * 1024 * 64) :
		file_mutex_(),
		max_flie_size_(max_flie_size)
	{
		SetLogFile(path);
	}
	DefaultFileSink(const DefaultFileSink&) = delete;
	DefaultFileSink& operator=(const DefaultFileSink&) = delete;
	DefaultFileSink(DefaultFileSink&&) = delete;
	DefaultFileSink& operator=(DefaultFileSink&&) = delete;

	void BeforeWrite(size_t) override;

	void Write(std::span<const LogTask> tasks) override;

	void Flush() override;

private:
	bool SetLogFile(const std::filesystem::path& filepath);
	bool RollToNewFile();

	std::ofstream			fs_;
	std::filesystem::path	filepath_;
	std::mutex				file_mutex_;
	size_t max_flie_size_;
};


class Logger::DefaultConsoleSink : public Logger::LogSink
{
public:
	DefaultConsoleSink() = default;
	DefaultConsoleSink(const DefaultConsoleSink&) = delete;
	DefaultConsoleSink& operator=(const DefaultConsoleSink&) = delete;
	DefaultConsoleSink(DefaultConsoleSink&&) = delete;
	DefaultConsoleSink& operator=(DefaultConsoleSink&&) = delete;

	void BeforeWrite([[maybe_unused]] size_t task_queue_len) override {}
	void Write(std::span<const LogTask> tasks) override;
	void Flush() override;
};

/// ----------- SinK Class ------------


/// ----------- Helper Class ------------

class Logger::LogHelper
{
public:
	class LogStream;

	LogHelper(Logger& logger, Logger::Level level = Logger::Level::NORMAL, uint32_t mask = 0u, const std::source_location& loc = std::source_location::current()) :
		logger__(logger),
		level__(level),
		local_mask__(mask),
		mask_enabled__(0u),
		mask_disabled__(0u),
		loc__(loc) {
	}

	LogHelper(LogHelper&&) = default;
	LogHelper(const LogHelper&) = default;

	LogHelper::LogStream Stream() const;
	LogHelper& Mask(uint32_t mask);
	LogHelper& EnableMaskFlag(Logger::Mask flag);
	LogHelper& DisableMaskFlag(Logger::Mask flag);
	LogHelper& Level(Logger::Level level);

	template<typename STR> requires(std::is_convertible_v<STR, std::string>)
		LogHelper& Log(STR str);

	template <Printable... Types>
	LogHelper& Log(const std::format_string<Types...>& fmt, const Types&... args);

private:
	LogHelper& operator=(LogHelper&&) = delete;
	LogHelper& operator=(const LogHelper&) = delete;
	uint32_t GetActiveMask() const;

	std::source_location loc__;
	Logger& logger__;
	Logger::Level level__;
	uint32_t local_mask__;
	uint32_t mask_enabled__;
	uint32_t mask_disabled__;
};

class Logger::LogHelper::LogStream
{
public:
	LogStream(const LogHelper& helper) :
		ss___(),
		helper___(helper),
		logged___(false) {
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

	std::ostringstream ss___;
	LogHelper helper___;
	bool logged___;
};

/// ----------- Helper Class ------------

/// ----------- Helper Chain Funciton ------------

inline Logger::LogHelper& Logger::LogHelper::Mask(uint32_t mask)
{
	local_mask__ = mask;
	return *this;
}

inline Logger::LogHelper& Logger::LogHelper::EnableMaskFlag(Logger::Mask flag)
{
	mask_enabled__ |= ~~flag;
	return *this;
}

inline Logger::LogHelper& Logger::LogHelper::DisableMaskFlag(Logger::Mask flag)
{
	mask_disabled__ |= ~~flag;
	return *this;
}

inline uint32_t Logger::LogHelper::GetActiveMask() const
{
	return ((local_mask__ ? local_mask__ : logger__.default_mask_) | mask_enabled__) & ~mask_disabled__;
}

inline Logger::LogHelper& Logger::LogHelper::Level(Logger::Level level)
{
	level__ = level;
	return *this;
}

template<typename STR> requires(std::is_convertible_v<STR, std::string>)
inline Logger::LogHelper& Logger::LogHelper::Log(STR str)
{
	logger__.Print(level__, str, GetActiveMask(), loc__);
	return *this;
}

template <Printable... Types>
inline Logger::LogHelper& Logger::LogHelper::Log(const std::format_string<Types...>& fmt, const Types&... args)
{
	const auto formatted = std::vformat(fmt.get(), std::make_format_args(args...));
	logger__.Print(level__, formatted, GetActiveMask(), loc__);
	return *this;
}

inline Logger::LogHelper::LogStream& Logger::LogHelper::LogStream::Log()
{
	if (!ss___.str().empty())
	{
		helper___.Log(ss___.str());
		logged___ = true;
	}
	return *this;
}

template<Printable Type>
inline Logger::LogHelper::LogStream& Logger::LogHelper::LogStream::operator<<(const Type& data)
{
	ss___ << data;
	return *this;
}

inline Logger::LogHelper::LogStream Logger::LogHelper::Stream() const
{
	return LogHelper::LogStream(*this);
}

inline Logger::LogHelper::LogStream::~LogStream()
{
	if (!logged___) Log();
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
	StopAndWaitAll();
	std::cout << std::flush;
	std::cerr << std::flush;
}

inline void Logger::Init(std::filesystem::path filepath, uint32_t logmask)
{
	default_mask_ = logmask;

	auto default_console_sink = std::make_unique<Logger::DefaultConsoleSink>();
	AppendSink(std::move(default_console_sink));

	auto default_file_sink = std::make_unique<Logger::DefaultFileSink>(filepath);
	AppendSink(std::move(default_file_sink));

	while (recycled_buffers_.size() < 12)
	{
		std::vector<Logger::LogTask> buffer;
		buffer.reserve(MAX_BUFFER_SIZE);
		recycled_buffers_.push_back(std::move(buffer));
	}

	if (background_thread_.has_value())
	{
		StopAndWaitAll();
	}

	background_thread_ = std::jthread
	(
		[this](std::stop_token st)
		{
			BackgourndThreadLoop(st);
		}
	);
}

inline void Logger::InitWithOutDefaultSink(uint32_t logmask)
{
	default_mask_ = logmask;

	while (recycled_buffers_.size() < 12)
	{
		std::vector<Logger::LogTask> buffer;
		buffer.reserve(MAX_BUFFER_SIZE);
		recycled_buffers_.push_back(std::move(buffer));
	}

	if (background_thread_.has_value())
	{
		StopAndWaitAll();
	}

	background_thread_ = std::jthread
	(
		[this](std::stop_token st)
		{
			BackgourndThreadLoop(st);
		}
	);
}


inline void Logger::AppendSink(std::unique_ptr<Logger::LogSink> sink)
{
	sinks_.emplace_back(std::move(sink));
}

inline void Logger::StopAndWaitAll()
{
	if (background_thread_.has_value())
	{
		background_thread_->request_stop();
		background_thread_->join();
		background_thread_.reset();
	}
}

inline void Logger::SetDefaultMaskFlag(Logger::Mask flag)
{
	default_mask_ |= ~~flag;
}

inline void Logger::UnsetDefaultMaskFlag(Logger::Mask flag)
{
	default_mask_ &= ~flag;
}

inline uint32_t Logger::SetDefaultMask(uint32_t mask)
{
	std::scoped_lock lock(mutex_);
	auto			 old_mask = default_mask_;
	default_mask_ = mask;
	return old_mask;
}

inline uint32_t Logger::GetDefaultMask() const
{
	return default_mask_;
}

inline void Logger::Print(Logger::Level level, const std::string_view message, uint32_t mask, const std::source_location& loc)
{
	static auto asycn_log = [](Logger& self, Logger::Level level, const std::string_view message, uint32_t mask, const std::source_location& loc)
		{
			self.AppendTask
			(
				Logger::LogTask
				(
					Logger::ParseSourceInfo(loc),
					message,
					mask,
					level
				)
			);
		};

	static auto sycn_log = [](Logger& self, Logger::Level level, const std::string_view message, uint32_t mask, const std::source_location& loc)
	{
		std::array<Logger::LogTask, 1> task
		{
			Logger::LogTask
			(
				Logger::ParseSourceInfo(loc),
				message,
				mask,
				level
			)
		};

		for (auto& sink : self.sinks_)
		{
			sink->BeforeWrite(1);
			sink->Write(std::span<const LogTask>(task));
			sink->Flush();
		}
	};


	if (level == Logger::Level::FATAL)
	{
		sycn_log(*this, level, message, mask, loc);
		//throw std::runtime_error(std::string("FATAL: ") + std::string(message));
	}
	else
	{
		asycn_log(*this, level, message, mask, loc);
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

inline Logger::SourceInfo Logger::ParseSourceInfo(const std::source_location& loc)
{
	using namespace std::string_view_literals;

	static const std::regex lambda_regex(R"(.*lambda_[0-9]+.*)");
	static const std::regex func_regex(R"((.*::)?([~]?[A-Za-z_][A-Za-z0-9_]*)\s*(<.*>)?\s*\(.*\))");

	std::string_view file_name(loc.file_name());
	const size_t last_slash = file_name.find_last_of("/\\");
	SourceInfo info
	{
		.path = (last_slash != std::string_view::npos)
				? file_name.substr(0, last_slash)
				: ""sv,
		.filename = (last_slash != std::string_view::npos)
				   ? file_name.substr(last_slash + 1)
				   : file_name,
		.function_prefix = {},
		.function_core = {},
		.line = loc.line()
	};

	std::string_view func_name(loc.function_name());
	std::cmatch match;
	const char* const func_start = func_name.data();
	const char* const func_end = func_start + func_name.size();

	if (std::regex_search(func_start, func_end, lambda_regex))
	{
		info.function_core = "[lambda]"sv;
	}
	else if (std::regex_search(func_start, func_end, match, func_regex))
	{
		if (match[1].matched)
		{
			info.function_prefix =
			{
				match[1].first,
				static_cast<size_t>(match[1].length())
			};
		}
		if (match[2].matched)
		{
			info.function_core =
			{
				match[2].first,
				static_cast<size_t>(match[2].length())
			};
		}
	}

	return info;
}

inline std::string Logger::GetCurrentTimeStr()
{
	auto zt = std::chrono::zoned_time{ std::chrono::current_zone(), std::chrono::system_clock::now() };
	return std::format("[{:%Y-%m-%d %H:%M:%S}]", zt.get_local_time());
}

inline void Logger::AppendTask(Logger::LogTask&& task)
{
	std::scoped_lock lock(mutex_);
	if (frontbuffer_.size() < MAX_BUFFER_SIZE)
	{
		frontbuffer_.emplace_back(std::move(task));
	}
	else
	{
		backbuffers_.emplace_back(std::move(frontbuffer_));
		if (recycled_buffers_.size() > 0)
		{
			frontbuffer_ = std::move(recycled_buffers_.front());
			frontbuffer_.clear();
			recycled_buffers_.pop_front();
		}
		else
		{
			std::vector<Logger::LogTask> taskbuffer;
			taskbuffer.reserve(MAX_BUFFER_SIZE);
			frontbuffer_ = std::move(taskbuffer);
		}

		frontbuffer_.emplace_back(std::move(task));
		cv_.notify_one();
	}
}

template <Logger::GenLogTextProxy Proxy>
inline std::string Logger::GenerateLogText(const Logger::LogTask& task)
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

	static const auto generate_text_with_color = [](uint32_t mask, Level level,
		const SourceInfo& src_info,
		std::string_view message) -> std::string
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
			const bool color_time = show_time && (mask & ~~Mask::COLOR_TIME);
			const bool show_source_info = mask & ~~Mask::SHOW_SRC_INFO;
			const bool color_source_info = show_source_info && (mask & ~~Mask::COLOR_SRC_INFO);
			const bool show_tag = mask & ~~Mask::SHOW_TAG;
			const bool color_tag = show_tag && (mask & ~~Mask::COLOR_TAG);
			const bool show_message = mask & ~~Mask::SHOW_MESSAGE;
			const bool color_message = show_message && (mask & ~~Mask::COLOR_MESSAGE);
			const bool end_line = mask & ~~Mask::END_LINE;

			if (new_line)
				ss << '\n';
			if (color_time)
				ss << time_color;
			if (show_time)
				ss << Logger::GetCurrentTimeStr();
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
				ss << src_info.line << " ";
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

	static const auto generate_text = [](uint32_t mask, Level level,
		const SourceInfo& src_info,
		std::string_view message) -> std::string
		{
			std::ostringstream ss{};
			const auto& [tag, _] = level_config[enum_integer(level)];

			const bool new_line = mask & ~~Mask::NEW_LINE;
			const bool show_time = mask & ~~Mask::SHOW_TIME;
			const bool show_source_info = mask & ~~Mask::SHOW_SRC_INFO;
			const bool show_tag = mask & ~~Mask::SHOW_TAG;
			const bool show_message = mask & ~~Mask::SHOW_MESSAGE;
			const bool end_line = mask & ~~Mask::END_LINE;

			if (new_line)
				ss << '\n';
			if (show_time)
				ss << Logger::GetCurrentTimeStr();
			if (show_time)
				ss << "  ";
			if (show_source_info) //todo: 颜色以外的方式来格式化显示源信息
			{
				ss << src_info.path << "\\";
				ss << src_info.filename << ":";
				ss << src_info.line << " ";
				ss << src_info.function_prefix;
				ss << src_info.function_core << "():\n";
			}
			if (show_tag)
				ss << tag << " ";
			if (show_message)
				ss << message;
			if (end_line)
				ss << '\n';

			return ss.str();
		};

	const auto task_mask = task.mask ? task.mask : Logger::Instance().default_mask_;

	if constexpr (Proxy == Logger::GenLogTextProxy::LogToConsole)
	{
		return generate_text_with_color(task_mask, task.level, task.source_info, task.message);
	}
	else if constexpr (Proxy == Logger::GenLogTextProxy::LogToFile)
	{
		return generate_text(task_mask, task.level, task.source_info, task.message);
	}
	else
	{
		static_assert(Logger::always_false<Proxy>, "Unsupported log proxy type");
		return "";
	}
};

inline void Logger::BackgourndThreadLoop(std::stop_token st)
{
	using namespace std::chrono_literals;

	while (!st.stop_requested())
	{
		std::deque<std::vector<Logger::LogTask>> taskbuffers;
		{
			std::unique_lock lock(mutex_);

			cv_.wait_for
			(
				lock,
				200ms,
				[this, &st]() -> bool
				{
					return st.stop_requested() || !backbuffers_.empty();
				}
			);

			if (backbuffers_.empty())
			{
				backbuffers_.emplace_back(std::move(frontbuffer_));
				if (recycled_buffers_.size() > 0)
				{
					frontbuffer_ = std::move(recycled_buffers_.front());
					frontbuffer_.clear();
					recycled_buffers_.pop_front();
				}
				else
				{
					std::vector<Logger::LogTask> taskbuffer;
					taskbuffer.reserve(MAX_BUFFER_SIZE);
					frontbuffer_ = std::move(taskbuffer);
				}
			}

			taskbuffers.swap(backbuffers_);
		}

		if (taskbuffers.size() > MAX_BACK_BUFFER_LEN)
		{
			taskbuffers.erase(taskbuffers.begin(), taskbuffers.begin() + 4u);
			Print(Logger::Level::INFO, "Too many log tasks, drop...");
		}

		for (auto& sink : sinks_)
		{
			sink->BeforeWrite(Logger::MAX_BUFFER_SIZE * taskbuffers.size());
		}

		for (auto& sink : sinks_)
		{
			for (auto& tasks : taskbuffers)
			{
				std::span<const LogTask> span_tasks(tasks);
				sink->Write(span_tasks);
			}
		}

		for (auto& sink : sinks_)
		{
			sink->Flush();
		}

		//回收内存空间，尽量
		if (recycled_buffers_.size() < 16)
		{
			recycled_buffers_.insert(recycled_buffers_.end(), std::make_move_iterator(taskbuffers.begin()), std::make_move_iterator(taskbuffers.end()));
		}
		else if (recycled_buffers_.size() > 64)
		{
			recycled_buffers_.erase(recycled_buffers_.begin(), recycled_buffers_.end() - 4);
		}
	}
}

/// ----------- Private Function ------------


/// ----------- Default SinK Function -------

inline void Logger::DefaultFileSink::BeforeWrite(size_t)
{
	using namespace std::chrono_literals;
	// check if file is open
	for (size_t count = 0; !fs_.is_open() && count < 5; ++count)
	{
		std::filesystem::create_directories(filepath_.parent_path());
		fs_.open(filepath_, std::ios::app);
		std::this_thread::sleep_for(5ms * (1ull << count));
	}

	// check if file should rolling
	for (size_t count = 0; (fs_.tellp() >= 0 && static_cast<size_t>(fs_.tellp()) > max_flie_size_) && count < 5; ++count) {
		if (!RollToNewFile())
		{
			std::cerr << "(ERROR): Failed to roll log file : " << filepath_.string();
			std::this_thread::sleep_for(5ms * (1ull << count));
		}
	}
}

inline void Logger::DefaultFileSink::Write(std::span<const  Logger::LogTask> tasks)
{
	std::lock_guard<std::mutex> lock(file_mutex_);
	for (const auto& task : tasks)
	{
		fs_ << Logger::GenerateLogText<Logger::GenLogTextProxy::LogToFile>(task);
	}
}

inline void Logger::DefaultFileSink::Flush()
{
	std::lock_guard<std::mutex> lock(file_mutex_);
	fs_.flush();
}

inline bool Logger::DefaultFileSink::SetLogFile(const std::filesystem::path& filepath)
{
	std::scoped_lock<std::mutex> lock(file_mutex_);

	if (fs_.is_open())
	{
		//fs_.close();
		throw std::runtime_error(std::format("File {} is opened by another Sink", filepath.string()));
		return false;
	}
	try
	{
		std::filesystem::create_directories(filepath.parent_path());
		fs_.open(filepath, std::ios::app);
		filepath_ = filepath;
		return true;
	}
	catch (const std::exception& e)
	{
		std::cerr << std::format("(Error): Set File {} failed : {}. ", filepath.string(), e.what());
		throw;
	}
	return false;
}

inline bool Logger::DefaultFileSink::RollToNewFile()
{
	std::lock_guard<std::mutex> lock(file_mutex_);

	try
	{
		if (fs_.is_open())
		{
			fs_.close();
		}

		const auto zt = std::chrono::zoned_time{ std::chrono::current_zone(), std::chrono::system_clock::now() };
		const auto local_time = zt.get_local_time();
		const auto new_name = filepath_.parent_path() / std::format("{}_{:%Y.%m.%d_%H.%M.%S}{}",
			filepath_.stem().string(),
			local_time,
			filepath_.extension().string()
		);

		std::filesystem::rename(filepath_, new_name);
		fs_.open(filepath_, std::ios::app);
		return true;
	}
	catch (const std::exception& e)
	{
		std::cerr << std::format("(Error): Roll to new file [{}] failed : {} ", filepath_.string(), e.what());
		//throw;
	}
	return false;
}

inline void Logger::DefaultConsoleSink::Write(std::span<const Logger::LogTask> tasks)
{
	for (const auto& task : tasks)
	{
		std::ostream& output_stream = (task.level == Logger::Level::ERROR || task.level == Logger::Level::FATAL) ? std::cerr : std::cout;
		std::osyncstream(output_stream) << Logger::GenerateLogText<Logger::GenLogTextProxy::LogToConsole>(task);
	}
}

inline void Logger::DefaultConsoleSink::Flush()
{
	std::cout << std::flush;
	std::cerr << std::flush;
}

/// ----------- Default SinK Function ------