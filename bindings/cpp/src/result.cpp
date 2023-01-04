#include <cstring>

#include "cppchecks/result.h"
#include "cppchecks/core.h"

template <class T>
inline CPPCHECKS_NAMESPACE::Item<T> *clone_vector(std::vector<CPPCHECKS_NAMESPACE::Item<T>> &items)
{
    return (CPPCHECKS_NAMESPACE::Item<T> *)malloc(sizeof(CPPCHECKS_NAMESPACE::Item<T>) * items.size());
}

namespace CPPCHECKS_NAMESPACE
{

    template <class T>
    CheckResult<T>::CheckResult(CPPCHECKS_NAMESPACE::Status status, const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip, std::optional<std::string> error)
    {
        CChecksStatus cstatus = (CChecksStatus)(status);
        char *cmessage = message.c_str();
        CChecksItem *citems = nullptr;
        size_t item_size = sizeof(CPPCHECKS_NAMESPACE::Item<T>);
        size_t item_count = 0;
        char *cerror = nullptr;

        if (items)
        {
            citems = (CChecksItem *)clone_vector(items.value());
            item_count = items.value().size();
        }

        if (error)
        {
            cerror = error.value().c_str();
        }

        _result = cchecks_check_result_new(cstatus, cmessage, citems, item_size, item_count, can_fix, can_skip, cerror, items_destroy_fn);
    }

    template <class T>
    CheckResult<T> CheckResult<T>::passed(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip)
    {
        char *cmessage = message.c_str();
        CChecksItem *citems = nullptr;
        size_t item_size = sizeof(CPPCHECKS_NAMESPACE::Item<T>);
        size_t item_count = 0;

        if (items)
        {
            citems = (CChecksItem *)clone_vector(items.value());
            item_count = items.value().size();
        }

        CheckResult<T> result;
        result._result = cchecks_check_result_passed(cmessage, citems, item_size, item_count, can_fix, can_skip, items_destroy_fn);

        return result;
    }

    template <class T>
    CheckResult<T> CheckResult<T>::skipped(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip)
    {
        char *cmessage = message.c_str();
        CChecksItem *citems = nullptr;
        size_t item_size = sizeof(CPPCHECKS_NAMESPACE::Item<T>);
        size_t item_count = 0;

        if (items)
        {
            citems = (CChecksItem *)clone_vector(items.value());
            item_count = items.value().size();
        }

        CheckResult<T> result;
        result._result = cchecks_check_result_skipped(cmessage, citems, item_size, item_count, can_fix, can_skip, items_destroy_fn);

        return result;
    }

    template <class T>
    CheckResult<T> CheckResult<T>::warning(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip)
    {
        char *cmessage = message.c_str();
        CChecksItem *citems = nullptr;
        size_t item_size = sizeof(CPPCHECKS_NAMESPACE::Item<T>);
        size_t item_count = 0;

        if (items)
        {
            citems = (CChecksItem *)clone_vector(items.value());
            item_count = items.value().size();
        }

        CheckResult<T> result;
        result._result = cchecks_check_result_warning(cmessage, citems, item_size, item_count, can_fix, can_skip, items_destroy_fn);

        return result;
    }

    template <class T>
    CheckResult<T> CheckResult<T>::failed(const std::string &message, const std::optional<std::vector<CPPCHECKS_NAMESPACE::Item<T>>> &items, bool can_fix, bool can_skip)
    {
        char *cmessage = message.c_str();
        CChecksItem *citems = nullptr;
        size_t item_size = sizeof(CPPCHECKS_NAMESPACE::Item<T>);
        size_t item_count = 0;

        if (items)
        {
            citems = (CChecksItem *)clone_vector(items.value());
            item_count = items.value().size();
        }

        CheckResult<T> result;
        result._result = cchecks_check_result_failed(cmessage, citems, item_size, item_count, can_fix, can_skip, items_destroy_fn);

        return result;
    }

    template <class T>
    CheckResult<T>::~CheckResult()
    {
        cchecks_check_result_destroy(&_result);
    }

    template <class T>
    const CPPCHECKS_NAMESPACE::Status &CheckResult<T>::status()
    {
        return CPPCHECKS_NAMESPACE::Status(cchecks_check_result_status(&_result));
    }

    template <class T>
    std::string CheckResult<T>::message()
    {
        return std::string(cchecks_check_result_message(&_result).string);
    }

    template <class T>
    std::optional<CPPCHECKS_NAMESPACE::Items<T>> CheckResult<T>::items()
    {
        const CChecksItems *citems = cchecks_check_result_items(&_result);

        if (!citems)
        {
            return std::nullopt;
        }
        else
        {
            return CPPCHECKS_NAMESPACE::Items<T>(citems->ptr, citems->length);
        }
    }

    template <class T>
    bool CheckResult<T>::can_fix()
    {
        return cchecks_check_result_can_fix(&_result);
    }

    template <class T>
    bool CheckResult<T>::can_skip()
    {
        return cchecks_check_result_can_skip(&_result);
    }

    template <class T>
    std::optional<std::string> CheckResult<T>::error()
    {
        CChecksStringView cerr = cchecks_check_result_error(&_result);

        if (!cerr.string)
        {
            return std::nullopt;
        }
        else
        {
            return std::string(cerr.string);
        }
    }

    template <class T>
    double CheckResult<T>::check_duration()
    {
        return cchecks_check_result_check_duration(&_result);
    }

    template <class T>
    double CheckResult<T>::fix_duration()
    {
        return cchecks_check_result_fix_duration(&_result);
    }

    template <class T>
    void CheckResult<T>::items_destroy_fn(CChecksItem *item)
    {
        free((CPPCHECKS_NAMESPACE::Item<T> *)item);
    }

} // namespace CPPCHECKS_NAMESPACE
