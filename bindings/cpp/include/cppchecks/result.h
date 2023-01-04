#pragma once

extern "C"
{
#include <cchecks.h>
}

#include <optional>
#include <string>
#include <vector>

#include "cppchecks/core.h"
#include "cppchecks/item.h"
#include "cppchecks/items.h"
#include "cppchecks/status.h"

namespace CPPCHECKS_NAMESPACE
{
    template <class T>
    class CheckResult
    {
    public:
        CheckResult(CPPCHECKS_NAMESPACE::Status status, const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip, std::optional<std::string> error);
        static CheckResult passed(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip);
        static CheckResult skipped(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip);
        static CheckResult warning(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip);
        static CheckResult failed(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip);
        ~CheckResult();

        const CPPCHECKS_NAMESPACE::Status &status();
        std::string message();
        std::optional<CPPCHECKS_NAMESPACE::Items<T>> items();
        bool can_fix();
        bool can_skip();
        std::optional<std::string> error();
        double check_duration();
        double fix_duration();

    private:
        CheckResult() {}
        CheckResult(CChecksCheckResult result) : _result(result) {}
        CChecksCheckResult _result;

        static void items_destroy_fn(CChecksItem *item);
    };

} // namespace CPPCHECKS_NAMESPACE