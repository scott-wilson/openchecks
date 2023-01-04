#pragma once

extern "C"
{
#include <cchecks.h>
}

#include <iterator>

#include "cppchecks/core.h"
#include "cppchecks/item.h"

namespace CPPCHECKS_NAMESPACE
{
    template <class T>
    class Items
    {
    public:
        class iterator
        {
        public:
            iterator(const CPPCHECKS_NAMESPACE::Item<T> *items);
            iterator &operator++();
            iterator operator++(int);
            bool operator==(iterator other) const;
            bool operator!=(iterator other) const;
            const CPPCHECKS_NAMESPACE::Item<T> &operator*();

            // iterator traits
            using difference_type = size_t;
            using value_type = CPPCHECKS_NAMESPACE::Item<T>;
            using pointer = const CPPCHECKS_NAMESPACE::Item<T> *;
            using reference = const CPPCHECKS_NAMESPACE::Item<T> &;
            using iterator_category = std::input_iterator_tag;

        private:
            const CPPCHECKS_NAMESPACE::Item<T> *_items;
        };

        Items(const CChecksItem *items, size_t count);

        iterator begin();
        iterator end();

    private:
        const CPPCHECKS_NAMESPACE::Item<T> *_items;
        size_t _count;
    };
} // namespace CPPCHECKS_NAMESPACE
