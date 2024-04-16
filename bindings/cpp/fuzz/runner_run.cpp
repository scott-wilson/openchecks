#include <cassert>
#include <optional>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include <cppchecks/check.h>
#include <cppchecks/result.h>
#include <cppchecks/runner.h>
#include <cppchecks/status.h>

#include "common.h"

class Check : public CPPCHECKS_NAMESPACE::BaseCheck<int> {
public:
  Check(std::string title, std::string description,
        CPPCHECKS_NAMESPACE::CheckHint hint, CPPCHECKS_NAMESPACE::Status status,
        CPPCHECKS_NAMESPACE::Status fix_status, std::string message,
        std::optional<IntItems> items, bool can_fix, bool can_skip,
        std::optional<std::string> error)
      : _title(title), _description(description), _hint(hint), _status(status),
        _fix_status(fix_status), _message(message), _items(items),
        _can_fix(can_fix), _can_skip(can_skip), _error(error) {}

  virtual const std::string &title() const { return _title; }

  virtual const std::string &description() const { return _description; }

  virtual const CPPCHECKS_NAMESPACE::CheckHint hint() const {
    return this->_hint;
  }

  virtual CPPCHECKS_NAMESPACE::CheckResult<int> check() const {
    return CPPCHECKS_NAMESPACE::CheckResult{_status,  _message,  _items,
                                            _can_fix, _can_skip, _error};
  }

  virtual std::optional<std::string> auto_fix() {
    if (_error) {
      return _error;
    } else {
      _status = _fix_status;
      return std::nullopt;
    }
  }

  std::string _title;
  std::string _description;
  CPPCHECKS_NAMESPACE::CheckHint _hint;
  CPPCHECKS_NAMESPACE::Status _status;
  CPPCHECKS_NAMESPACE::Status _fix_status;
  std::string _message;
  std::optional<IntItems> _items;
  bool _can_fix;
  bool _can_skip;
  std::optional<std::string> _error;
};

CPPCHECKS_NAMESPACE::CheckHint get_hint(FuzzedDataProvider &provider) {
  CPPCHECKS_NAMESPACE::CheckHint hint = CPPCHECKS_NAMESPACE::CheckHint::None;

  if (provider.ConsumeBool()) {
    hint.insert(CPPCHECKS_NAMESPACE::CheckHint::AutoFix);
  }

  return hint;
}

Check create_check(FuzzedDataProvider &provider) {
  std::string title = get_message(provider);
  std::string description = get_message(provider);
  CPPCHECKS_NAMESPACE::CheckHint hint = get_hint(provider);
  CPPCHECKS_NAMESPACE::Status status =
      (CChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
          (uint8_t)CChecksStatusPending, (uint8_t)CChecksStatusSystemError);
  CPPCHECKS_NAMESPACE::Status fix_status =
      (CChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
          (uint8_t)CChecksStatusPending, (uint8_t)CChecksStatusSystemError);
  std::string message = get_message(provider);
  std::optional<IntItems> items =
      provider.ConsumeBool()
          ? std::optional<IntItems>(create_int_items(provider))
          : std::nullopt;
  bool can_fix = provider.ConsumeBool();
  bool can_skip = provider.ConsumeBool();
  std::optional<std::string> error =
      provider.ConsumeBool() ? std::optional<std::string>(get_message(provider))
                             : std::nullopt;

  return Check{title,   description, hint,    status,   fix_status,
               message, items,       can_fix, can_skip, error};
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  Check check = create_check(provider);

  assert(check.title() == check._title);
  assert(check.description() == check._description);
  assert(check.hint() == check._hint);

  IntResult result = check.check();

  CPPCHECKS_NAMESPACE::Status result_status = result.status();
  std::string_view result_message = result.message();
  std::optional<IntItems> result_items = result.items();
  std::optional<std::string_view> result_error = result.error();

  if (result_status == CPPCHECKS_NAMESPACE::Status::SystemError) {
    assert(result.can_fix() == false);
    assert(result.can_skip() == false);
  } else {
    assert(result.can_fix() == check._can_fix);
    assert(result.can_skip() == check._can_skip);
  }

  if (result_status.has_failed() && result.can_fix()) {
    CPPCHECKS_NAMESPACE::CheckResult fix_result =
        CPPCHECKS_NAMESPACE::auto_fix(check);

    CPPCHECKS_NAMESPACE::Status fix_result_status = fix_result.status();
    std::string_view fix_result_message = fix_result.message();
    const std::optional<IntItems> fix_result_items = fix_result.items();
    const std::optional<std::string_view> fix_result_error = fix_result.error();

    CPPCHECKS_NAMESPACE::CheckHint fix_hint = check.hint();

    if (!fix_hint.contains(CPPCHECKS_NAMESPACE::CheckHint::AutoFix)) {
      assert(fix_result_status == CPPCHECKS_NAMESPACE::Status::SystemError);
      assert(fix_result_message == "Check does not implement auto fix.");
      assert(fix_result_items == std::nullopt);
      assert(fix_result_error == std::nullopt);
    } else if (fix_result_error) {
      assert(fix_result_status == CPPCHECKS_NAMESPACE::Status::SystemError);
      assert(fix_result_message == "Error in auto fix.");
      assert(fix_result_items == std::nullopt);
      assert(fix_result_error.value() == check._error);
    } else {
      assert(fix_result_status == check._fix_status);
      assert(fix_result_message == check._message);

      if (!check._items) {
        assert(fix_result_items == std::nullopt);
      } else {
        assert(fix_result_items != std::nullopt);
        assert(fix_result_items == check._items);
      }

      assert(fix_result_error == std::nullopt);
    }

    if (fix_result_status == CPPCHECKS_NAMESPACE::Status::SystemError) {
      assert(fix_result.can_fix() == false);
      assert(fix_result.can_skip() == false);
    } else {
      assert(fix_result.can_fix() == check._can_fix);
      assert(fix_result.can_skip() == check._can_skip);
    }
  }

  return 0;
}
