#include <cppchecks/core.h>
#include <cppchecks/item.h>
#include <cppchecks/items.h>
#include <gtest/gtest.h>
#include <vector>

#include "item_impl.h"
#include "items_impl.h"

TEST(CheckItems, IterateSuccess) {
  std::vector<IntItem> vec{IntItem(0, ""), IntItem(1, ""), IntItem(2, "")};
  IntItems items{vec};
  size_t index = 0;

  for (index = 0; index < items.length(); index++) {
    const std::optional<IntItem> item = items[index];

    ASSERT_NE(item, std::nullopt);
    ASSERT_EQ(item->value(), index);
  }

  const std::optional<IntItem> item = items[100];
  ASSERT_EQ(item, std::nullopt);

  ASSERT_EQ(index, vec.size());
}
