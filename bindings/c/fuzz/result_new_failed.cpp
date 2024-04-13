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
#include <cchecks.h>
}

#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  std::string message = get_message(provider);
  const char *message_cstr = message.c_str();
  bool can_fix = provider.ConsumeBool();
  bool can_skip = provider.ConsumeBool();
  IntItems *int_items = create_int_items(provider);

  CChecksCheckResult result = cchecks_check_result_failed(
      message_cstr, (CChecksItems *)int_items, can_fix, can_skip);

  std::string_view result_message =
      std::string_view(cchecks_check_result_message(&result).string);
  const CChecksItems *result_items = cchecks_check_result_items(&result);
  const char *error = cchecks_check_result_error(&result);

  assert(cchecks_check_result_status(&result) == CChecksStatusFailed);
  assert(message == result_message);

  assert(cchecks_check_result_can_fix(&result) == can_fix);
  assert(cchecks_check_result_can_skip(&result) == can_skip);
  assert(error == nullptr);

  cchecks_check_result_destroy(&result);
  return 0;
}
