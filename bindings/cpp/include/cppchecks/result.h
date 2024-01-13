#pragma once

extern "C"
{
#include <cchecks.h>
}

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>
#include <cstring>

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
        CheckResult(CPPCHECKS_NAMESPACE::Status status, const std::string &message, const std::vector<CPPCHECKS_NAMESPACE::Item<T>> &items, bool can_fix, bool can_skip, std::string error) : _items(items)
        {
            CChecksStatus cstatus = status.c_status();
            const char *cmessage = message.c_str();
            size_t item_size = sizeof(CPPCHECKS_NAMESPACE::Item<T>);
            size_t item_count = items.size();
            const char *cerror = error.c_str();

            _result = cchecks_check_result_new(cstatus, cmessage, (CChecksItem *)_items.data(), item_size, item_count, can_fix, can_skip, cerror, items_destroy_fn);
        }

        static CheckResult passed(const std::string &message, const std::vector<CPPCHECKS_NAMESPACE::Item<T>> &items, bool can_fix, bool can_skip)
        {
            return CheckResult{CPPCHECKS_NAMESPACE::Status::Passed, message, items, can_fix, can_skip, ""};
        }

        static CheckResult skipped(const std::string &message, const std::vector<CPPCHECKS_NAMESPACE::Item<T>> &items, bool can_fix, bool can_skip)
        {
            return CheckResult{CPPCHECKS_NAMESPACE::Status::Skipped, message, items, can_fix, can_skip, ""};
        }

        static CheckResult warning(const std::string &message, const std::vector<CPPCHECKS_NAMESPACE::Item<T>> &items, bool can_fix, bool can_skip)
        {
            return CheckResult{CPPCHECKS_NAMESPACE::Status::Warning, message, items, can_fix, can_skip, ""};
        }

        static CheckResult failed(const std::string &message, const std::vector<CPPCHECKS_NAMESPACE::Item<T>> &items, bool can_fix, bool can_skip)
        {
            return CheckResult{CPPCHECKS_NAMESPACE::Status::Failed, message, items, can_fix, can_skip, ""};
        }

        virtual ~CheckResult()
        {
            // TODO: This causes double frees.
            // cchecks_check_result_destroy(&this->_result);
        }

        const CPPCHECKS_NAMESPACE::Status status() const
        {
            return CPPCHECKS_NAMESPACE::Status(cchecks_check_result_status((CChecksCheckResult *)&_result));
        }

        std::string_view message() const
        {
            return std::string_view(cchecks_check_result_message(&_result).string);
        }

        CPPCHECKS_NAMESPACE::Items<T> items() const
        {
            const CChecksItems *citems = cchecks_check_result_items(&_result);

            const CChecksItem *ptr = citems->ptr;
            auto items = CPPCHECKS_NAMESPACE::Items<T>((const CPPCHECKS_NAMESPACE::Item<T> *)ptr, citems->length);
            return items;
        }

        bool can_fix() const
        {
            return cchecks_check_result_can_fix(&_result);
        }

        bool can_skip() const
        {
            return cchecks_check_result_can_skip(&_result);
        }

        std::string error() const
        {
            CChecksStringView cerr = cchecks_check_result_error(&_result);

            if (!cerr.string)
            {
                return std::string();
            }
            else
            {
                return std::string(cerr.string);
            }
        }

        double check_duration() const
        {
            return cchecks_check_result_check_duration(&_result);
        }

        double fix_duration() const
        {
            return cchecks_check_result_fix_duration(&_result);
        }

    private:
        CheckResult() {}
        CheckResult(CChecksCheckResult result) : _result(result) {}
        CChecksCheckResult _result;
        std::vector<CPPCHECKS_NAMESPACE::Item<T>> _items;

        static void items_destroy_fn(CChecksItem *item)
        {
            // Do not destroy the items, since C++ will handle the destruction.
            // The items are owned by the class itself, and the C result type references it.
        }
    };

} // namespace CPPCHECKS_NAMESPACE
