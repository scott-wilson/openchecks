#pragma once

extern "C"
{
#include <cchecks.h>
}

#include <optional>
#include <string>

#include "cppchecks/core.h"

namespace CPPCHECKS_NAMESPACE
{
    template <class T>
    class Item
    {
    public:
        Item(T value, std::optional<std::string> type_hint);

        const T &value() const { return this->_value; }
        const std::optional<std::string> &type_hint() const { return this->_type_hint; }

        // Display
        virtual std::string display() const = 0;
        // Debug
        virtual std::string debug() const = 0;

        // Ordering
        virtual inline bool operator<(const Item<T> &other) const = 0;
        virtual inline bool operator>(const Item<T> &other) const { return &other < this; }
        virtual inline bool operator<=(const Item<T> &other) const { return !(this > &other); }
        virtual inline bool operator>=(const Item<T> &other) const { return !(this < &other); }

        // Comparison
        virtual inline bool operator==(const Item<T> &other) const = 0;
        virtual inline bool operator!=(const Item<T> &other) const { return !(this == &other); }

    private:
        CChecksItem _item;
        T _value;
        std::optional<std::string> _type_hint;

        static const char *type_hint_fn(const CChecksItem *item);
        static const void *value_fn(const CChecksItem *item);
        static void clone_fn(const CChecksItem *item, CChecksItem *other);
        static void destroy_fn(CChecksItem *item);
        static CChecksString debug_fn(const CChecksItem *item);
        static CChecksString display_fn(const CChecksItem *item);
        static bool lt_fn(const CChecksItem *item, const CChecksItem *other);
        static bool eq_fn(const CChecksItem *item, const CChecksItem *other);
    };
} // namespace CPPCHECKS_NAMESPACE
