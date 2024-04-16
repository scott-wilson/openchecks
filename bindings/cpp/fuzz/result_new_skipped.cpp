#include <cassert>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include <cppchecks/result.h>

#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  std::string message = get_message(provider);
  bool can_fix = provider.ConsumeBool();
  bool can_skip = provider.ConsumeBool();
  IntItems int_items = create_int_items(provider);

  IntResult result = IntResult::skipped(message, int_items, can_fix, can_skip);

  assert(result.status() == CPPCHECKS_NAMESPACE::Status::Skipped);
  assert(result.message() == message);
  assert(result.can_fix() == can_fix);
  assert(result.can_skip() == can_skip);
  assert(result.error() == std::nullopt);

  return 0;
}
