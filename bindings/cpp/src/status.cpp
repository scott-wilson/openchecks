#include "cppchecks/status.h"
#include "cppchecks/core.h"

namespace CPPCHECKS_NAMESPACE
{
    bool Status::is_pending()
    {
        return cchecks_status_is_pending((CChecksStatus *)&_value);
    }

    bool Status::has_passed()
    {
        return cchecks_status_has_passed((CChecksStatus *)&_value);
    }

    bool Status::has_failed()
    {
        return cchecks_status_has_failed((CChecksStatus *)&_value);
    }

} // namespace CPPCHECKS_NAMESPACE
