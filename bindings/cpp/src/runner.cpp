#include <cstring>

#include "cppchecks/runner.h"

namespace CPPCHECKS_NAMESPACE
{
    template <class T>
    CPPCHECKS_NAMESPACE::CheckResult<T> run(const CPPCHECKS_NAMESPACE::BaseCheck<T> &check)
    {
        CPPCHECKS_NAMESPACE::CheckResult(cchecks_run(&check._check));
    }

    template <class T>
    CPPCHECKS_NAMESPACE::CheckResult<T> auto_fix(CPPCHECKS_NAMESPACE::BaseCheck<T> &check)
    {
        CPPCHECKS_NAMESPACE::CheckResult(cchecks_auto_fix(&check._check));
    }
} // namespace CPPCHECKS_NAMESPACE
