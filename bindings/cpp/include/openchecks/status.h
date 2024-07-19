#pragma once

extern "C" {
#include <openchecks.h>
}

#include "openchecks/core.h"

namespace OPENCHECKS_NAMESPACE {
class Status {
public:
  enum Value {
    Pending = OpenChecksStatusPending,
    Skipped = OpenChecksStatusSkipped,
    Passed = OpenChecksStatusPassed,
    Warning = OpenChecksStatusWarning,
    Failed = OpenChecksStatusFailed,
    SystemError = OpenChecksStatusSystemError,
  };

  Status() = default;
  constexpr Status(Value status) : _value(status) {}
  constexpr Status(OpenChecksStatus status) : _value((Status::Value)status) {}

  constexpr operator Value() const { return _value; }
  explicit operator bool() const = delete;

  bool is_pending() const {
    return openchecks_status_is_pending((OpenChecksStatus *)&_value);
  }

  bool has_passed() const {
    return openchecks_status_has_passed((OpenChecksStatus *)&_value);
  }

  bool has_failed() const {
    return openchecks_status_has_failed((OpenChecksStatus *)&_value);
  }

  OpenChecksStatus c_status() const {
    switch (_value) {
    case Status::Value::Pending:
      return OpenChecksStatusPending;
    case Status::Value::Skipped:
      return OpenChecksStatusSkipped;
    case Status::Value::Passed:
      return OpenChecksStatusPassed;
    case Status::Value::Warning:
      return OpenChecksStatusWarning;
    case Status::Value::Failed:
      return OpenChecksStatusFailed;
    case Status::Value::SystemError:
      return OpenChecksStatusSystemError;
    default:
      return OpenChecksStatusSystemError;
    }
  }

private:
  Value _value;
};
} // namespace OPENCHECKS_NAMESPACE
