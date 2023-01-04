#pragma once

extern "C"
{
#include <cchecks.h>
}

#include "cppchecks/core.h"

namespace CPPCHECKS_NAMESPACE
{
    class Status
    {
    public:
        enum Value
        {
            Pending = CChecksStatusPending,
            Skipped = CChecksStatusSkipped,
            Passed = CChecksStatusPassed,
            Warning = CChecksStatusWarning,
            Failed = CChecksStatusFailed,
            SystemError = CChecksStatusSystemError,
        };

        Status() = default;
        constexpr Status(Value status) : _value(status) {}
        constexpr operator Value() const { return _value; }
        explicit operator bool() const = delete;

        bool is_pending() const;
        bool has_passed() const;
        bool has_failed() const;

        CChecksStatus c_status() const;

    private:
        Value _value;
    };
} // namespace CPPCHECKS_NAMESPACE
