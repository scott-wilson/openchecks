#pragma once

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
#include <cchecks.h>
}

#include "cppchecks/core.h"
#include "cppchecks/item.h"
#include "cppchecks/items.h"
#include "cppchecks/status.h"

namespace CPPCHECKS_NAMESPACE {
template <class T> class BaseCheck;

template <class T> class CheckResult : private CChecksCheckResult {
public:
  friend class BaseCheck<T>;
  CheckResult(CPPCHECKS_NAMESPACE::Status status, const std::string &message,
              const std::optional<Items<T>> &items, bool can_fix, bool can_skip,
              std::optional<std::string> error = std::nullopt) {
    CChecksStatus cstatus = status.c_status();
    const char *cmessage = message.c_str();
    CChecksItems *citems = nullptr;

    if (items) {
      citems = cchecks_items_clone((CChecksItems *)&(items.value()));
    }

    const char *cerror;

    if (error.has_value()) {
      cerror = error.value().c_str();
    } else {
      cerror = nullptr;
    }

    CChecksCheckResult result = cchecks_check_result_new(
        cstatus, cmessage, citems, can_fix, can_skip, cerror);

    CChecksCheckResult::status = result.status;
    CChecksCheckResult::message = result.message;
    CChecksCheckResult::items = result.items;
    CChecksCheckResult::can_fix = result.can_fix;
    CChecksCheckResult::can_skip = result.can_skip;
    CChecksCheckResult::error = result.error;
    CChecksCheckResult::check_duration = result.check_duration;
    CChecksCheckResult::fix_duration = result.fix_duration;

    result.message = nullptr;
    result.items = nullptr;
    result.error = nullptr;
  }

  CheckResult(CChecksCheckResult &result) {
    CChecksCheckResult c_result =
        cchecks_check_result_new(result.status, result.message, result.items,
                                 result.can_fix, result.can_skip, result.error);

    CChecksCheckResult::status = c_result.status;
    CChecksCheckResult::message = c_result.message;
    CChecksCheckResult::items = c_result.items;
    CChecksCheckResult::can_fix = c_result.can_fix;
    CChecksCheckResult::can_skip = c_result.can_skip;
    CChecksCheckResult::error = c_result.error;
    CChecksCheckResult::check_duration = result.check_duration;
    CChecksCheckResult::fix_duration = result.fix_duration;

    c_result.message = nullptr;
    c_result.items = nullptr;
    c_result.error = nullptr;
  }

  CheckResult(CheckResult &result) {
    CChecksCheckResult c_result =
        cchecks_check_result_new(result.status, result.message, result.items,
                                 result.can_fix, result.can_skip, result.error);

    CChecksCheckResult::status = c_result.status;
    CChecksCheckResult::message = c_result.message;
    CChecksCheckResult::items = c_result.items;
    CChecksCheckResult::can_fix = c_result.can_fix;
    CChecksCheckResult::can_skip = c_result.can_skip;
    CChecksCheckResult::error = c_result.error;
    CChecksCheckResult::check_duration = result.check_duration;
    CChecksCheckResult::fix_duration = result.fix_duration;

    c_result.message = nullptr;
    c_result.items = nullptr;
    c_result.error = nullptr;
  }

  static CheckResult passed(const std::string &message, const Items<T> &items,
                            bool can_fix, bool can_skip) {
    return CheckResult{CPPCHECKS_NAMESPACE::Status::Passed,
                       message,
                       items,
                       can_fix,
                       can_skip,
                       std::nullopt};
  }

  static CheckResult skipped(const std::string &message, const Items<T> &items,
                             bool can_fix, bool can_skip) {
    return CheckResult{CPPCHECKS_NAMESPACE::Status::Skipped,
                       message,
                       items,
                       can_fix,
                       can_skip,
                       std::nullopt};
  }

  static CheckResult warning(const std::string &message, const Items<T> &items,
                             bool can_fix, bool can_skip) {
    return CheckResult{CPPCHECKS_NAMESPACE::Status::Warning,
                       message,
                       items,
                       can_fix,
                       can_skip,
                       std::nullopt};
  }

  static CheckResult failed(const std::string &message, const Items<T> &items,
                            bool can_fix, bool can_skip) {
    return CheckResult{CPPCHECKS_NAMESPACE::Status::Failed,
                       message,
                       items,
                       can_fix,
                       can_skip,
                       std::nullopt};
  }

  virtual ~CheckResult() {
    cchecks_check_result_destroy((CChecksCheckResult *)this);
  }

  const CPPCHECKS_NAMESPACE::Status status() const {
    return CPPCHECKS_NAMESPACE::Status(
        cchecks_check_result_status((CChecksCheckResult *)this));
  }

  std::string_view message() const {
    return std::string_view(cchecks_check_result_message(this).string);
  }

  const std::optional<CPPCHECKS_NAMESPACE::Items<T>> items() const {
    const CPPCHECKS_NAMESPACE::Items<T> *items =
        (const CPPCHECKS_NAMESPACE::Items<T> *)cchecks_check_result_items(this);

    if (items == nullptr) {
      return std::nullopt;
    } else {
      return std::optional<CPPCHECKS_NAMESPACE::Items<T>>(*items);
    }
  }

  bool can_fix() const { return cchecks_check_result_can_fix(this); }

  bool can_skip() const { return cchecks_check_result_can_skip(this); }

  std::optional<std::string_view> error() const {
    const char *cerr = cchecks_check_result_error(this);

    if (cerr == nullptr) {
      return std::nullopt;
    } else {
      return std::optional<std::string_view>(cerr);
    }
  }

  double check_duration() const {
    return cchecks_check_result_check_duration(this);
  }

  double fix_duration() const {
    return cchecks_check_result_fix_duration(this);
  }

private:
  CheckResult() {}
};

} // namespace CPPCHECKS_NAMESPACE
