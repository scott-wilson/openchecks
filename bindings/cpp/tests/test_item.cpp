#include <gtest/gtest.h>
#include <cppchecks/item.h>
#include <string>
#include <sstream>
#include <optional>

#include "item_impl.h"

TEST(Item, IntItemDisplaySuccess)
{
    IntItem item{1, std::string("test")};
}
