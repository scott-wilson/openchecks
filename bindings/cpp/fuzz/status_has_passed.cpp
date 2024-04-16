#include <cassert>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include <cppchecks/status.h>

#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  CPPCHECKS_NAMESPACE::Status status =
      (CChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
          (uint8_t)CChecksStatusPending, (uint8_t)CChecksStatusSystemError);

  if (status == CPPCHECKS_NAMESPACE::Status::Passed ||
      status == CPPCHECKS_NAMESPACE::Status::Warning) {
    assert(status.has_passed() == true);
  } else {
    assert(status.has_passed() == false);
  }
  return 0;
}
