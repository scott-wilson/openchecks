#include <cassert>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include <openchecks.h>
}

#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  std::string message = get_message(provider);
  const char *message_cstr = message.c_str();
  bool can_fix = provider.ConsumeBool();
  bool can_skip = provider.ConsumeBool();
  IntItems *int_items = create_int_items(provider);

  OpenChecksCheckResult result = openchecks_check_result_failed(
      message_cstr, (OpenChecksItems *)int_items, can_fix, can_skip);

  std::string_view result_message =
      std::string_view(openchecks_check_result_message(&result).string);
  const OpenChecksItems *result_items = openchecks_check_result_items(&result);
  const char *error = openchecks_check_result_error(&result);

  assert(openchecks_check_result_status(&result) == OpenChecksStatusFailed);
  assert(message == result_message);
  assert(openchecks_items_eq((OpenChecksItems *)int_items, result_items));

  assert(openchecks_check_result_can_fix(&result) == can_fix);
  assert(openchecks_check_result_can_skip(&result) == can_skip);
  assert(error == nullptr);

  openchecks_check_result_destroy(&result);
  return 0;
}
