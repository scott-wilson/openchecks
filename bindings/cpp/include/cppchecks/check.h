#pragma once

extern "C"
{
#include <cchecks.h>
}

#include <optional>
#include <string>
#include <bitset>

#include "cppchecks/core.h"
#include "cppchecks/item.h"
#include "cppchecks/items.h"
#include "cppchecks/status.h"
#include "cppchecks/result.h"

namespace CPPCHECKS_NAMESPACE
{
    enum class CheckHint
    {
        None = CCHECKS_CHECK_HINT_NONE,
        AutoFix = CCHECKS_CHECK_HINT_AUTO_FIX,
    };

    template <class T>
    class BaseCheck
    {
    public:
        BaseCheck();
        virtual std::string title() = 0;
        virtual std::string description() = 0;
        virtual CheckHint hint() = 0;
        virtual CPPCHECKS_NAMESPACE::CheckResult<T> check() = 0;
        virtual std::optional<std::string> auto_fix() { return std::string("Auto fix is not implemented."); }

    private:
        CChecksBaseCheck _check;
        static const char *title_fn(const CChecksBaseCheck *check);
        static const char *description_fn(const CChecksBaseCheck *check);
        static CChecksCheckHint hint_fn(const CChecksBaseCheck *check);
        static CChecksCheckResult check_fn(const CChecksBaseCheck *check);
        static CChecksAutoFixResult auto_fix_fn(const CChecksBaseCheck *check);
    };

} // namespace CPPCHECKS_NAMESPACE
