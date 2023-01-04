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

        bool is_pending();
        bool has_passed();
        bool has_failed();

    private:
        Value _value;
    };
} // namespace CPPCHECKS_NAMESPACE
