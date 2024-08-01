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

  if (status == OpenChecksStatusPassed || status == OpenChecksStatusWarning) {
    assert(openchecks_status_has_passed(&status) == true);
  } else {
    assert(openchecks_status_has_passed(&status) == false);
  }
  return 0;
}
