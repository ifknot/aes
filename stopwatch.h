#ifndef AES_CPP17_STOPWATCH_H
#define AES_CPP17_STOPWATCH_H

#include <chrono>

namespace util {

    template<typename PolicyT = std::chrono::nanoseconds,
            typename PolicyClock = std::chrono::steady_clock>
    class stopwatch {

        using clock_t = PolicyClock;

    public:

        using time_point_t = typename clock_t::time_point;

        stopwatch() = default;

        int64_t static diff(time_point_t& before, time_point_t& after);

        time_point_t static now();

        time_point_t start();

        time_point_t stop();

        int64_t elapsed();

    private:

        time_point_t before;
        time_point_t after;

    };

    template<typename PolicyT, typename PolicyClock>
    int64_t stopwatch<PolicyT, PolicyClock>::diff(time_point_t &before, time_point_t &after) {
        return std::chrono::duration_cast<PolicyT>(after - before).count();
    }

    template<typename PolicyT, typename PolicyClock>
    int64_t stopwatch<PolicyT, PolicyClock>::elapsed() {
        return diff(before, after);
    }

    template<typename PolicyT, typename PolicyClock>
    typename stopwatch<PolicyT, PolicyClock>::time_point_t stopwatch<PolicyT, PolicyClock>::stop() {
        after = clock_t::now();
        return after;
    }

    template<typename PolicyT, typename PolicyClock>
    typename stopwatch<PolicyT, PolicyClock>::time_point_t stopwatch<PolicyT, PolicyClock>::start() {
        before = clock_t::now();
        return before;
    }

    template<typename PolicyT, typename PolicyClock>
    typename stopwatch<PolicyT, PolicyClock>::time_point_t stopwatch<PolicyT, PolicyClock>::now() {
        return clock_t::now();
    }

}

#endif //AES_CPP17_STOPWATCH_H
