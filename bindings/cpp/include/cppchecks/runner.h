#pragma once

#include <bitset>
#include <string>

extern "C" {
#include <cchecks.h>
}

#include "cppchecks/check.h"
#include "cppchecks/core.h"
#include "cppchecks/result.h"

namespace CPPCHECKS_NAMESPACE {
template <class T>
CPPCHECKS_NAMESPACE::CheckResult<T>
run(const CPPCHECKS_NAMESPACE::BaseCheck<T> &check) {
  CChecksCheckResult result = cchecks_run((const CChecksBaseCheck *)&check);
  return CPPCHECKS_NAMESPACE::CheckResult<T>{result};
}

template <class T>
CPPCHECKS_NAMESPACE::CheckResult<T>
auto_fix(CPPCHECKS_NAMESPACE::BaseCheck<T> &check) {
  CChecksBaseCheck *c_check = (CChecksBaseCheck *)&check;
  CChecksCheckResult c_result = cchecks_auto_fix(c_check);
  return CPPCHECKS_NAMESPACE::CheckResult<T>{c_result};
}
} // namespace CPPCHECKS_NAMESPACE
