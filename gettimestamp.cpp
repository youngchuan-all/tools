
// 将时间转换成对应时间戳 
// T1时间戳类型：比如std::chrono::seconds 
// T2:时间点类型 比如 decltype(std::chrono::system_lock::now()) == std::time_point<std::chrono::system_lock>
// 用法参考：longlong now timeStampInSeconds = getTimeStamp<std::chrono::seconds,decltype(std::chrono::system_lock::now())>(std::chrono::system_lock::now());
template<typename T1, typename T2>
long long getTimeStamp(const T2 &tp)
{
	return std::chrono::duration_cast<T1>(tp.time_since_epoch()).count();
}

// demo
#if 0
int main()
{
	auto now = std::chrono::system_clock::now();
	auto secondTimeStamp = getTimeStamp<std::chrono::seconds,decltype(now)>(now);

	return secondTimeStamp;
}
#endif
