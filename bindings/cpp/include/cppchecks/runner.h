#pragma once

extern "C"
{
#include <cchecks.h>
}

#include <optional>
#include <string>
#include <bitset>

#include "cppchecks/core.h"
#include "cppchecks/check.h"
#include "cppchecks/result.h"

namespace CPPCHECKS_NAMESPACE
{
    template <class T>
    CPPCHECKS_NAMESPACE::CheckResult<T> run(const CPPCHECKS_NAMESPACE::BaseCheck<T> &check);

    template <class T>
    CPPCHECKS_NAMESPACE::CheckResult<T> auto_fix(CPPCHECKS_NAMESPACE::BaseCheck<T> &check);
} // namespace CPPCHECKS_NAMESPACE
