#include <cstring>

#include "cppchecks/item.h"
#include "cppchecks/core.h"

void destroy_str_fn(struct CChecksString *str)
{
    delete[] str->string;
}

namespace CPPCHECKS_NAMESPACE
{
    template <class T>
    Item<T>::Item(T value, std::optional<std::string> type_hint)
    {
        CChecksItem item;
        item.type_hint_fn = nullptr;
        item.value_fn = nullptr;
        item.clone_fn = nullptr;
        item.destroy_fn = nullptr;
        item.debug_fn = nullptr;
        item.display_fn = nullptr;
        item.lt_fn = nullptr;
        item.eq_fn = nullptr;
    }

    template <class T>
    const char *Item<T>::type_hint_fn(const CChecksItem *item)
    {
        Item<T> *cppitem = (Item<T> *)item;

        if (cppitem->_type_hint)
        {
            return cppitem->_type_hint.value().c_str();
        }
        else
        {
            return nullptr;
        }
    }

    template <class T>
    const void *Item<T>::value_fn(const CChecksItem *item)
    {
        Item<T> *cppitem = (Item<T> *)item;

        return (void *)&cppitem->_value;
    }

    template <class T>
    void Item<T>::clone_fn(const CChecksItem *item, CChecksItem *other)
    {
        Item<T> *cppitem = (Item<T> *)item;
        Item<T> *cppother = (Item<T> *)other;
        other = Item(cppitem);
    }

    template <class T>
    void Item<T>::destroy_fn(CChecksItem *item)
    {
        Item<T> *cppitem = (Item<T> *)item;
        cppitem->~Item();
    }

    template <class T>
    CChecksString Item<T>::debug_fn(const CChecksItem *item)
    {
        Item<T> *cppitem = (Item<T> *)item;

        std::string msg = cppitem->debug();

        char *cstr = new char[msg.length() + 1];
        std::strcpy(cstr, msg.c_str());

        CChecksString cchecks_msg;
        cchecks_msg.string = cstr;
        cchecks_msg.destroy_fn = destroy_str_fn;

        return cchecks_msg;
    }

    template <class T>
    CChecksString Item<T>::display_fn(const CChecksItem *item)
    {
        Item<T> *cppitem = (Item<T> *)item;

        std::string msg = cppitem->display();

        char *cstr = new char[msg.length() + 1];
        std::strcpy(cstr, msg.c_str());

        CChecksString cchecks_msg;
        cchecks_msg.string = cstr;
        cchecks_msg.destroy_fn = destroy_str_fn;

        return cchecks_msg;
    }

    template <class T>
    bool Item<T>::lt_fn(const CChecksItem *item, const CChecksItem *other)
    {
        Item<T> *cppitem = (Item<T> *)item;
        Item<T> *cppother = (Item<T> *)other;

        return cppitem < cppother;
    }

    template <class T>
    bool Item<T>::eq_fn(const CChecksItem *item, const CChecksItem *other)
    {
        Item<T> *cppitem = (Item<T> *)item;
        Item<T> *cppother = (Item<T> *)other;

        return cppitem == cppother;
    }

} // namespace CPPCHECKS_NAMESPACE
