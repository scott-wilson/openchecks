#include "cppchecks/status.h"
#include "cppchecks/core.h"

namespace CPPCHECKS_NAMESPACE
{
    bool Status::is_pending() const
    {
        return cchecks_status_is_pending((CChecksStatus *)&_value);
    }

    bool Status::has_passed() const
    {
        return cchecks_status_has_passed((CChecksStatus *)&_value);
    }

    bool Status::has_failed() const
    {
        return cchecks_status_has_failed((CChecksStatus *)&_value);
    }

    CChecksStatus Status::c_status() const
    {
        switch (_value)
        {
        case Status::Value::Pending:
            return CChecksStatusPending;
        case Status::Value::Skipped:
            return CChecksStatusSkipped;
        case Status::Value::Passed:
            return CChecksStatusPassed;
        case Status::Value::Warning:
            return CChecksStatusWarning;
        case Status::Value::Failed:
            return CChecksStatusFailed;
        case Status::Value::SystemError:
            return CChecksStatusSystemError;
        }
    }

} // namespace CPPCHECKS_NAMESPACE
