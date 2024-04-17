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

  CPPCHECKS_NAMESPACE::Status status =
      (CChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
          (uint8_t)CChecksStatusPending, (uint8_t)CChecksStatusSystemError);
  std::string message = get_message(provider);
  bool can_fix = provider.ConsumeBool();
  bool can_skip = provider.ConsumeBool();
  IntItems int_items = create_int_items(provider);
  std::optional<std::string> error =
      provider.ConsumeBool() ? std::optional<std::string>(get_message(provider))
                             : std::nullopt;

  IntResult result =
      IntResult{status, message, int_items, can_fix, can_skip, error};

  assert(result.status() == status);
  assert(result.message() == message);
  assert(result.error() == error);

  if (status == CPPCHECKS_NAMESPACE::Status::SystemError) {
    assert(result.can_fix() == false);
    assert(result.can_skip() == false);
  } else {
    assert(result.can_fix() == can_fix);
    assert(result.can_skip() == can_skip);
  }

  return 0;
}
