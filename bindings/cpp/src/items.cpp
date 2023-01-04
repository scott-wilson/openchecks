#include <cstring>

#include "cppchecks/items.h"
#include "cppchecks/core.h"

namespace CPPCHECKS_NAMESPACE
{

    template <class T>
    Items<T>::iterator::iterator(const CPPCHECKS_NAMESPACE::Item<T> *items) : _items(items) {}

    template <class T>
    typename Items<T>::iterator &Items<T>::iterator::operator++() { return *this + 1; }

    template <class T>
    typename Items<T>::iterator Items<T>::iterator::operator++(int)
    {
        iterator retval = *this;
        ++(*this);
        return retval;
    }

    template <class T>
    bool Items<T>::iterator::operator==(iterator other) const
    {
        return _items == other._items;
    }

    template <class T>
    bool Items<T>::iterator::operator!=(iterator other) const
    {
        return !(*this == other);
    }

    template <class T>
    const CPPCHECKS_NAMESPACE::Item<T> &Items<T>::iterator::operator*()
    {
        return _items;
    }

    template <class T>
    Items<T>::Items(const CChecksItem *items, size_t count) : _items(items), _count(count) {}

    template <class T>
    typename Items<T>::iterator Items<T>::begin()
    {
        return Items<T>::iterator(_items);
    }

    template <class T>
    typename Items<T>::iterator Items<T>::end()
    {
        return Items<T>::iterator(_items + _count);
    }

} // namespace CPPCHECKS_NAMESPACE
