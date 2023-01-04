#pragma once

#include <cppchecks/item.h>
#include <string>
#include <sstream>
#include <optional>

class IntItem : public cppchecks::Item<int>
{
public:
    IntItem(int value, std::optional<std::string> type_hint) : cppchecks::Item<int>(value, type_hint) {}

    virtual std::string display() const
    {
        return std::to_string(this->value());
    }

    virtual std::string debug() const
    {
        std::ostringstream stream;
        stream << "Item(" << this->value() << ")";

        return std::string(stream.str());
    }

    virtual inline bool operator<(const Item<int> &other) const { return this->value() < other.value(); }

    virtual inline bool operator==(const Item<int> &other) const { return this->value() == other.value(); }
};
