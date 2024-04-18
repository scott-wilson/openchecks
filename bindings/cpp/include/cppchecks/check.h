#pragma once

#include <bitset>
#include <cstring>
#include <optional>
#include <string>

extern "C" {
#include <cchecks.h>
}

#include "cppchecks/core.h"
#include "cppchecks/item.h"
#include "cppchecks/items.h"
#include "cppchecks/result.h"
#include "cppchecks/status.h"

namespace CPPCHECKS_NAMESPACE {
class CheckHint {
public:
  enum Value : CChecksCheckHint {
    None = CCHECKS_CHECK_HINT_NONE,
    AutoFix = CCHECKS_CHECK_HINT_AUTO_FIX,
  };

  constexpr CheckHint(Value hint) : _value(hint) {}
  constexpr CheckHint(CChecksCheckHint &hint)
      : _value((CheckHint::Value)hint) {}

  constexpr operator Value() const { return _value; }
  explicit operator bool() const = delete;

  void insert(CheckHint other) { _value = (Value)(_value | other._value); }

  bool contains(CheckHint other) const { return _value & other._value; }

  CChecksCheckHint c_hint() const { return _value; }

private:
  Value _value;
};

template <class T> class BaseCheck : private CChecksBaseCheck {
public:
  BaseCheck() {
    title_fn = title_impl;
    description_fn = description_impl;
    hint_fn = hint_impl;
    check_fn = check_impl;
    auto_fix_fn = auto_fix_impl;
  }

  virtual const std::string &title() const = 0;
  virtual const std::string &description() const = 0;
  virtual const CheckHint hint() const = 0;
  virtual CPPCHECKS_NAMESPACE::CheckResult<T> check() const = 0;
  virtual std::optional<std::string> auto_fix() {
    return std::string("Auto fix is not implemented.");
  }

private:
  static const char *title_impl(const CChecksBaseCheck *check) {
    return ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->title().c_str();
  }

  static const char *description_impl(const CChecksBaseCheck *check) {
    return ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->description().c_str();
  }

  static CChecksCheckHint hint_impl(const CChecksBaseCheck *check) {
    CPPCHECKS_NAMESPACE::BaseCheck<T> *cpp_check =
        (CPPCHECKS_NAMESPACE::BaseCheck<T> *)check;
    CPPCHECKS_NAMESPACE::CheckHint hint = cpp_check->hint();
    CChecksCheckHint c_hint = hint.c_hint();

    return c_hint;
  }

  static CChecksCheckResult check_impl(const CChecksBaseCheck *check) {
    CPPCHECKS_NAMESPACE::CheckResult<T> result =
        ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->check();

    CChecksCheckResult c_result = (CChecksCheckResult)result;

    ((CChecksCheckResult *)&result)->message = nullptr;
    ((CChecksCheckResult *)&result)->items = nullptr;
    ((CChecksCheckResult *)&result)->error = nullptr;

    return c_result;
  }

  static CChecksAutoFixResult auto_fix_impl(CChecksBaseCheck *check) {
    std::optional<std::string> auto_fix_result =
        ((CPPCHECKS_NAMESPACE::BaseCheck<T> *)check)->auto_fix();

    if (!auto_fix_result) {
      return cchecks_check_auto_fix_ok();
    } else {
      return cchecks_check_auto_fix_error(auto_fix_result.value().c_str());
    }
  }
};

} // namespace CPPCHECKS_NAMESPACE
