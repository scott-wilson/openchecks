#pragma once

#include <iostream>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include <openchecks/core.h>
#include <openchecks/item.h>
#include <openchecks/items.h>
#include <openchecks/result.h>
#include <openchecks/status.h>

const std::string_view PRINTABLE_CHARS =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*"
    "+,-./:;<=>?@[\\]^_`{|}~ \t\n\r";

using IntItem = OPENCHECKS_NAMESPACE::Item<int>;
using IntItems = OPENCHECKS_NAMESPACE::Items<int>;
using IntResult = OPENCHECKS_NAMESPACE::CheckResult<int>;

IntItem create_int_item(FuzzedDataProvider &provider) {
  return IntItem{
      provider.ConsumeIntegral<int>(),
      provider.ConsumeRandomLengthString(),
  };
}

std::string get_message(FuzzedDataProvider &provider) {
  std::string message = provider.ConsumeRandomLengthString();

  for (size_t i = 0; i < message.size(); i++) {
    message[i] = PRINTABLE_CHARS[message[i] % PRINTABLE_CHARS.size()];
  }

  return message;
}

IntItems create_int_items(FuzzedDataProvider &provider) {
  size_t item_count = provider.ConsumeIntegralInRange<size_t>(0, 10);
  std::vector<IntItem> items = std::vector<IntItem>();

  for (size_t i = 0; i < item_count; i++) {
    items.push_back(create_int_item(provider));
  }

  return IntItems{items};
}
