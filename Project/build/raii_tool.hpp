#pragma once

#include <tuple>
#include <type_traits>
#include <utility>

template <bool moveable = false, typename F = void(), typename... Args>
requires( std::invocable<F, Args...> )
class ScopeGuard
{
public:
	using callback_t = std::decay_t<F>;

	template <std::invocable<Args...> _F>
	requires std::convertible_to<_F, callback_t>
	explicit ScopeGuard( _F&& fn, Args&&... data ) : _data( std::forward_as_tuple( std::forward<Args>( data )... ) ), _fn( std::forward<_F>( fn ) ), _active( true )
	{
	}

	~ScopeGuard()
	{
		if ( _active )
		{
			if constexpr ( sizeof...( Args ) == 0 )
			{
				_fn();
			}
			else
			{
				std::apply( [ this ]( auto&&... args ) { _fn( args... ); }, _data );
			}
		}
	}

	ScopeGuard( const ScopeGuard& ) = delete;
	ScopeGuard& operator=( const ScopeGuard& ) = delete;

	ScopeGuard( ScopeGuard&& o ) noexcept
		requires( moveable )
		: _data( std::move( o._data ) ), _fn( std::move( o._fn ) ), _active( o._active )
	{
		o._active = false;
	}

	ScopeGuard& operator=( ScopeGuard&& o ) noexcept
		requires( moveable )
	{
		if ( this != &o )
		{
			if constexpr ( sizeof...( Args ) )
				_data = std::move( o._data );
			_fn = std::move( o._fn );
			_active = o._active;
			o._active = false;
		}
		return *this;
	}

	ScopeGuard& dismiss()
	{
		_active = false;
		return *this;
	}

	bool is_active() const
	{
		return _active;
	}

private:
	std::tuple<Args&&...> _data;
	callback_t			  _fn;
	bool				  _active;
};

template <bool moveable = false, typename F, typename... Args>
inline auto MakeScopeGuard( F&& fn, Args&&... args )
requires( std::invocable<F, Args...> )
{
	return ScopeGuard<moveable, F&&, Args&&...>( std::forward<F>( fn ), std::forward<Args>( args )... );
}

template <typename T>
requires std::is_copy_constructible_v<T> && std::is_copy_assignable_v<T> && requires( T a, const T& b )
{
	{ a = b } -> std::same_as<T&>;
}
class RollBacker
{
	using data_t = std::decay_t<T>;

public:
	explicit RollBacker( T& val ) : _now( val ), _old( val ), _active( true ) {}
	RollBacker( T&& val ) = delete;
	~RollBacker()
	{
		if ( _active )
			_now = _old;
	}
	RollBacker() = delete;
	RollBacker( const RollBacker& ) = delete;
	RollBacker& operator=( const RollBacker& ) = delete;
	RollBacker( RollBacker&& ) noexcept = delete;
	RollBacker& operator=( RollBacker&& ) noexcept = delete;

	RollBacker& dismiss()
	{

		_active = false;
		return *this;
	}

	bool is_active() const
	{
		return _active;
	}

	data_t& get_now() const
	{
		return _now;
	}

	const data_t& get_old() const
	{
		return _old;
	}

private:
	data_t&		 _now;
	const data_t _old;
	bool		 _active;
};
