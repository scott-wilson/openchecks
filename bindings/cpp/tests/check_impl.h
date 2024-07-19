#pragma once

#include <optional>
#include <string>

#include <openchecks/check.h>
#include <openchecks/core.h>
#include <openchecks/result.h>
#include <openchecks/status.h>

#include "items_impl.h"

class Check : public OPENCHECKS_NAMESPACE::BaseCheck<int> {
public:
  Check(std::string title, std::string description,
        OPENCHECKS_NAMESPACE::CheckHint hint, OPENCHECKS_NAMESPACE::Status status,
        OPENCHECKS_NAMESPACE::Status fix_status, std::string message,
        std::optional<IntItems> items, bool can_fix, bool can_skip,
        std::optional<std::string> error)
      : _title(title), _description(description), _hint(hint), _status(status),
        _fix_status(fix_status), _message(message), _items(items),
        _can_fix(can_fix), _can_skip(can_skip), _error(error) {}

  virtual const std::string &title() const { return _title; }

  virtual const std::string &description() const { return _description; }

  virtual const OPENCHECKS_NAMESPACE::CheckHint hint() const {
    return this->_hint;
  }

  virtual OPENCHECKS_NAMESPACE::CheckResult<int> check() const {
    return OPENCHECKS_NAMESPACE::CheckResult{_status,  _message,  _items,
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
  OPENCHECKS_NAMESPACE::CheckHint _hint;
  OPENCHECKS_NAMESPACE::Status _status;
  OPENCHECKS_NAMESPACE::Status _fix_status;
  std::string _message;
  std::optional<IntItems> _items;
  bool _can_fix;
  bool _can_skip;
  std::optional<std::string> _error;
};
