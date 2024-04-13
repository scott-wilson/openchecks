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
  CChecksStatus status =
      (CChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
          (uint8_t)CChecksStatusPending, (uint8_t)CChecksStatusSystemError);

  if (status == CChecksStatusPending) {
    assert(cchecks_status_is_pending(&status) == true);
  } else {
    assert(cchecks_status_is_pending(&status) == false);
  }
  return 0;
}
