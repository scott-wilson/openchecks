#pragma once

#include <bitset>
#include <string>

extern "C" {
#include <openchecks.h>
}

#include "openchecks/check.h"
#include "openchecks/core.h"
#include "openchecks/result.h"

namespace OPENCHECKS_NAMESPACE {
template <class T>
OPENCHECKS_NAMESPACE::CheckResult<T>
run(const OPENCHECKS_NAMESPACE::BaseCheck<T> &check) {
  OpenChecksCheckResult result =
      openchecks_run((const OpenChecksBaseCheck *)&check);
  return OPENCHECKS_NAMESPACE::CheckResult<T>{result};
}

template <class T>
OPENCHECKS_NAMESPACE::CheckResult<T>
auto_fix(OPENCHECKS_NAMESPACE::BaseCheck<T> &check) {
  OpenChecksBaseCheck *c_check = (OpenChecksBaseCheck *)&check;
  OpenChecksCheckResult c_result = openchecks_auto_fix(c_check);
  return OPENCHECKS_NAMESPACE::CheckResult<T>{c_result};
}
} // namespace OPENCHECKS_NAMESPACE
