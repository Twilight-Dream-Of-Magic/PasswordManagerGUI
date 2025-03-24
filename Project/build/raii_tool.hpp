#pragma once

//ScopeGuard
template<typename T, std::invocable<T&> F = void(T&)>
class ScopeGuard
{
	using data_t = std::decay_t<T>;
	using callback_t = std::decay_t<F>;
public:
	template<std::invocable<T&> _F> requires std::convertible_to<_F, callback_t>
	explicit ScopeGuard(data_t& data, _F&& fn) :_data(data), _fn(std::forward<_F>(fn)) {}
	~ScopeGuard() {if(_fn) _fn(_data);}
	ScopeGuard(const ScopeGuard&) = delete;
	ScopeGuard& operator=(const ScopeGuard&) = delete;
	ScopeGuard(ScopeGuard&&) noexcept = delete;
	ScopeGuard& operator=(ScopeGuard&&) noexcept = delete;

private:
	data_t& _data;
	callback_t _fn;
};
