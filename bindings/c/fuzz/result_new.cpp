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
  OpenChecksStatus status =
      (OpenChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
          (uint8_t)OpenChecksStatusPending,
          (uint8_t)OpenChecksStatusSystemError);
  std::string message = get_message(provider);
  const char *message_cstr = message.c_str();
  bool has_error = provider.ConsumeBool();
  bool can_fix = provider.ConsumeBool();
  bool can_skip = provider.ConsumeBool();
  IntItems *int_items = create_int_items(provider);
  std::string error = get_message(provider);
  const char *error_ptr;

  if (has_error) {
    error_ptr = error.c_str();
  } else {
    error_ptr = nullptr;
  }

  OpenChecksCheckResult result = openchecks_check_result_new(
      status, message_cstr, (OpenChecksItems *)int_items, can_fix, can_skip,
      error_ptr);

  OpenChecksStatus result_status = openchecks_check_result_status(&result);
  std::string_view result_message =
      std::string_view(openchecks_check_result_message(&result).string);
  const OpenChecksItems *result_items = openchecks_check_result_items(&result);
  const char *result_error = openchecks_check_result_error(&result);

  assert(result_status == status);
  assert(message == result_message);
  assert(openchecks_items_eq((OpenChecksItems *)int_items, result_items));

  if (status == OpenChecksStatusSystemError) {
    assert(openchecks_check_result_can_fix(&result) == false);
    assert(openchecks_check_result_can_skip(&result) == false);
  } else {
    assert(openchecks_check_result_can_fix(&result) == can_fix);
    assert(openchecks_check_result_can_skip(&result) == can_skip);
  }

  if (has_error) {
    assert(std::string_view(result_error) == error);
  } else {
    assert(result_error == nullptr);
  }

  openchecks_check_result_destroy(&result);
  return 0;
}
