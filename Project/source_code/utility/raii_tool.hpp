#pragma once

#include <tuple>
#include <type_traits>
#include <utility>

template <bool moveable = false, typename F = void(), typename... Args>
    requires(std::invocable<F, Args...>)
class ScopeGuard
{
  public:
	using callback_t = std::decay_t<F>;

	template <std::invocable<Args...> _F>
	    requires std::convertible_to<_F, callback_t>
	explicit ScopeGuard(_F &&fn, Args &&...data)
	    : data_(std::forward_as_tuple(std::forward<Args>(data)...))
	    , fn_(std::forward<_F>(fn))
	    , active_(true)
	{
	}

	~ScopeGuard()
	{
		if (active_)
		{
			if constexpr (sizeof...(Args) == 0)
			{
				fn_();
			}
			else
			{
				std::apply([this](auto &&...args) { fn_(args...); }, data_);
			}
		}
	}

	ScopeGuard(const ScopeGuard &)            = delete;
	ScopeGuard &operator=(const ScopeGuard &) = delete;

	ScopeGuard(ScopeGuard &&o) noexcept
	    requires(moveable)
	    : data_(std::move(o.data_))
	    , fn_(std::move(o.fn_))
	    , active_(o.active_)
	{
		o.active_ = false;
	}

	ScopeGuard &operator=(ScopeGuard &&o) noexcept
	    requires(moveable)
	{
		if (this != &o)
		{
			if constexpr (sizeof...(Args))
				data_ = std::move(o.data_);
			fn_       = std::move(o.fn_);
			active_   = o.active_;
			o.active_ = false;
		}
		return *this;
	}

	ScopeGuard &dismiss()
	{
		active_ = false;
		return *this;
	}

	bool is_active() const { return active_; }

  private:
	std::tuple<Args &&...> data_;
	callback_t             fn_;
	bool                   active_;
};

template <bool moveable = false, typename F, typename... Args>
inline auto MakeScopeGuard(F &&fn, Args &&...args)
    requires(std::invocable<F, Args...>)
{
	return ScopeGuard<moveable, F &&, Args &&...>(std::forward<F>(fn), std::forward<Args>(args)...);
}

template <typename T>
    requires std::is_copy_constructible_v<T> && std::is_copy_assignable_v<T> && requires(T a, const T &b) {
	    { a = b } -> std::same_as<T &>;
    }
class RollBacker
{
	using data_t = std::decay_t<T>;

  public:
	explicit RollBacker(T &val)
	    : now_(val)
	    , old_(val)
	    , active_(true)
	{
	}
	RollBacker(T &&val) = delete;
	~RollBacker()
	{
		if (active_)
			now_ = old_;
	}
	RollBacker()                                  = delete;
	RollBacker(const RollBacker &)                = delete;
	RollBacker &operator=(const RollBacker &)     = delete;
	RollBacker(RollBacker &&) noexcept            = delete;
	RollBacker &operator=(RollBacker &&) noexcept = delete;

	RollBacker &dismiss()
	{

		active_ = false;
		return *this;
	}

	bool is_active() const { return active_; }

	data_t &get_now() const { return now_; }

	const data_t &get_old() const { return old_; }

  private:
	data_t      &now_;
	const data_t old_;
	bool         active_;
};
