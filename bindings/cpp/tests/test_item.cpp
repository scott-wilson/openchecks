extern "C" {
#include <openchecks.h>
}

#include <gtest/gtest.h>
#include <openchecks/item.h>
#include <sstream>
#include <string>

#include "item_impl.h"

TEST(Item, IntItemValueSuccess) {
  IntItem item{1, std::string("test")};
  ASSERT_EQ(item.value(), 1);
}

TEST(Item, IntItemTypeHintSuccess) {
  IntItem item{1, std::string("test")};
  ASSERT_EQ(item.type_hint(), std::string("test"));

  item = IntItem{1, ""};
  ASSERT_EQ(item.type_hint(), "");
}

TEST(Item, IntItemDisplaySuccess) {
  IntItem item{1, std::string("test")};

  ASSERT_EQ(item.display(), "1");
}

TEST(Item, IntItemDebugSuccess) {
  IntItem item{1, std::string("test")};

  ASSERT_EQ(item.debug(), "Item(1)");
}

TEST(Item, IntItemCloneSuccess) {
  IntItem item{1, std::string("test")};
  IntItem other{2, std::string("other")};
  other.clone(item);

  ASSERT_EQ(item.value(), other.value());
  ASSERT_EQ(item.type_hint(), other.type_hint());
  ASSERT_NE(&item, &other);
}

TEST(Item, IntItemLtSuccess) {
  IntItem item{1, std::string("test")};
  IntItem other{2, std::string("test")};

  ASSERT_LT(item, other);

  item = IntItem{1, std::string("test")};
  other = IntItem{1, std::string("test")};

  ASSERT_FALSE(item < other);
}

TEST(Item, IntItemLeSuccess) {
  IntItem item{1, std::string("test")};
  IntItem other{2, std::string("test")};

  ASSERT_LE(item, other);

  item = IntItem{1, std::string("test")};
  other = IntItem{1, std::string("test")};

  ASSERT_LE(item, other);

  item = IntItem{2, std::string("test")};
  other = IntItem{1, std::string("test")};

  ASSERT_FALSE(item <= other);
}

TEST(Item, IntItemGtSuccess) {
  IntItem item{2, std::string("test")};
  IntItem other{1, std::string("test")};

  ASSERT_GT(item, other);

  item = IntItem{1, std::string("test")};
  other = IntItem{1, std::string("test")};

  ASSERT_FALSE(item > other);
}

TEST(Item, IntItemGeSuccess) {
  IntItem item{2, std::string("test")};
  IntItem other{1, std::string("test")};

  ASSERT_GE(item, other);

  item = IntItem{1, std::string("test")};
  other = IntItem{1, std::string("test")};

  ASSERT_GE(item, other);

  item = IntItem{1, std::string("test")};
  other = IntItem{2, std::string("test")};

  ASSERT_FALSE(item >= other);
}

TEST(Item, IntItemEqSuccess) {
  IntItem item{1, std::string("test")};
  IntItem other{1, std::string("test")};

  ASSERT_EQ(item, other);

  item = IntItem{1, std::string("test")};
  other = IntItem{2, std::string("test")};

  ASSERT_FALSE(item == other);
}

TEST(Item, IntItemNeSuccess) {
  IntItem item{1, std::string("test")};
  IntItem other{2, std::string("test")};

  ASSERT_NE(item, other);

  item = IntItem{1, std::string("test")};
  other = IntItem{1, std::string("test")};

  ASSERT_FALSE(item != other);
}

TEST(Item, CIntItemValueSuccess) {
  IntItem item{1, std::string("test")};
  ASSERT_EQ(*(int *)openchecks_item_value((OpenChecksItem *)&item), 1);
}

TEST(Item, CIntItemTypeHintSuccess) {
  IntItem item{1, std::string("test")};
  OpenChecksItem *citem = (OpenChecksItem *)&item;
  const char *ctype_hint = openchecks_item_type_hint(citem);

  ASSERT_STREQ(ctype_hint, "test");

  item = IntItem{1, ""};
  citem = (OpenChecksItem *)&item;
  ctype_hint = openchecks_item_type_hint(citem);

  ASSERT_EQ(ctype_hint, nullptr);
}

TEST(Item, CIntItemDisplaySuccess) {
  IntItem item{1, std::string("test")};
  OpenChecksItem *citem = (OpenChecksItem *)&item;
  OpenChecksString display = openchecks_item_display(citem);

  ASSERT_STREQ(display.string, "1");

  openchecks_string_destroy(&display);
}

TEST(Item, CIntItemDebugSuccess) {
  IntItem item{1, std::string("test")};
  OpenChecksItem *citem = (OpenChecksItem *)&item;
  OpenChecksString debug = openchecks_item_debug(citem);

  ASSERT_STREQ(debug.string, "Item(1)");

  openchecks_string_destroy(&debug);
}

TEST(Item, CIntItemCloneSuccess) {
  IntItem item{1, std::string("test")};
  IntItem *other = (IntItem *)openchecks_item_clone((OpenChecksItem *)&item);

  ASSERT_EQ(item.value(), other->value());
  ASSERT_EQ(item.type_hint(), other->type_hint());
  ASSERT_NE(&item, &(*other));
}

TEST(Item, CIntItemLtSuccess) {
  IntItem item{1, std::string("test")};
  IntItem other{2, std::string("test")};

  ASSERT_TRUE(
      openchecks_item_lt((OpenChecksItem *)&item, (OpenChecksItem *)&other));

  item = IntItem{1, std::string("test")};
  other = IntItem{1, std::string("test")};

  ASSERT_FALSE(
      openchecks_item_lt((OpenChecksItem *)&item, (OpenChecksItem *)&other));
}

TEST(Item, CIntItemEqSuccess) {
  IntItem item{1, std::string("test")};
  IntItem other{1, std::string("test")};

  ASSERT_TRUE(
      openchecks_item_eq((OpenChecksItem *)&item, (OpenChecksItem *)&other));

  item = IntItem{1, std::string("test")};
  other = IntItem{2, std::string("test")};

  ASSERT_FALSE(
      openchecks_item_eq((OpenChecksItem *)&item, (OpenChecksItem *)&other));
}
