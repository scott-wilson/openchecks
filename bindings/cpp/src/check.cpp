#include <cstring>

#include "cppchecks/check.h"

namespace CPPCHECKS_NAMESPACE
{
    template <class T>
    BaseCheck<T>::BaseCheck()
    {
        _check.title_fn = title_fn;
        _check.description_fn = description_fn;
        _check.hint_fn = hint_fn;
        _check.check_fn = check_fn;
        _check.auto_fix_fn = auto_fix_fn;
    }

    template <class T>
    const char *BaseCheck<T>::title_fn(const CChecksBaseCheck *check)
    {
        return ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->title().c_str();
    }

    template <class T>
    const char *BaseCheck<T>::description_fn(const CChecksBaseCheck *check)
    {
        return ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->description().c_str();
    }

    template <class T>
    CChecksCheckHint BaseCheck<T>::hint_fn(const CChecksBaseCheck *check)
    {
        return ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->hint();
    }

    template <class T>
    CChecksCheckResult BaseCheck<T>::check_fn(const CChecksBaseCheck *check)
    {
        return ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->check()._result;
    }

    template <class T>
    CChecksAutoFixResult BaseCheck<T>::auto_fix_fn(const CChecksBaseCheck *check)
    {
        auto auto_fix_result = ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->auto_fix();

        if (!auto_fix_result)
        {
            return cchecks_check_auto_fix_ok();
        }
        else
        {
            return cchecks_check_auto_fix_error(auto_fix_result.value().c_str());
        }
    }
} // namespace CPPCHECKS_NAMESPACE
