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

typedef struct Check {
  CChecksBaseCheck header;
  std::string title;
  std::string description;
  CChecksCheckHint hint;
  CChecksStatus status;
  CChecksStatus fix_status;
  std::string message;
  bool has_items;
  IntItems *items;
  bool can_fix;
  bool can_skip;
  bool has_error;
  std::string error;
} Check;

const char *check_title_fn(const CChecksBaseCheck *check) {
  return ((Check *)check)->title.c_str();
}

const char *check_description_fn(const CChecksBaseCheck *check) {
  return ((Check *)check)->description.c_str();
}

CChecksCheckHint check_hint_fn(const CChecksBaseCheck *check) {
  return ((Check *)check)->hint;
}

CChecksCheckResult check_run_fn(const CChecksBaseCheck *check) {
  CChecksStatus status = ((Check *)check)->status;
  const char *message = ((Check *)check)->message.c_str();
  CChecksItems *items;
  bool can_fix = ((Check *)check)->can_fix;
  bool can_skip = ((Check *)check)->can_skip;
  const char *error;

  if (((Check *)check)->has_items) {
    items = (CChecksItems *)((Check *)check)->items;
  } else {
    items = nullptr;
  }

  if (((Check *)check)->has_error) {
    error = ((Check *)check)->error.c_str();
  } else {
    error = nullptr;
  }

  return cchecks_check_result_new(status, message, items, can_fix, can_skip,
                                  error);
}

CChecksAutoFixResult check_auto_fix_fn(CChecksBaseCheck *check) {
  if (((Check *)check)->has_error) {
    return cchecks_check_auto_fix_error(((Check *)check)->error.c_str());
  } else {
    ((Check *)check)->status = ((Check *)check)->fix_status;
    return cchecks_check_auto_fix_ok();
  }
}

CChecksCheckHint get_hint(FuzzedDataProvider &provider) {
  CChecksCheckHint hint = CCHECKS_CHECK_HINT_NONE;

  if (provider.ConsumeBool()) {
    hint |= CCHECKS_CHECK_HINT_AUTO_FIX;
  }

  return hint;
}

Check create_check(FuzzedDataProvider &provider) {
  Check check;
  check.header.title_fn = check_title_fn;
  check.header.description_fn = check_description_fn;
  check.header.hint_fn = check_hint_fn;
  check.header.check_fn = check_run_fn;
  check.header.auto_fix_fn = check_auto_fix_fn;

  check.title = get_message(provider);
  check.description = get_message(provider);
  check.hint = get_hint(provider);
  check.status = (CChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
      (uint8_t)CChecksStatusPending, (uint8_t)CChecksStatusSystemError);
  check.fix_status = (CChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
      (uint8_t)CChecksStatusPending, (uint8_t)CChecksStatusSystemError);
  check.message = get_message(provider);
  check.has_items = provider.ConsumeBool();
  check.can_fix = provider.ConsumeBool();
  check.can_skip = provider.ConsumeBool();
  check.has_error = provider.ConsumeBool();

  if (check.has_items) {
    check.items = create_int_items(provider);
  } else {
    check.items = nullptr;
  }

  if (check.has_error) {
    check.error = get_message(provider);
  }

  return check;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  Check check = create_check(provider);

  assert(std::string_view(
             cchecks_check_title(((CChecksBaseCheck *)&check)).string) ==
         check.title);
  assert(std::string_view(
             cchecks_check_description(((CChecksBaseCheck *)&check)).string) ==
         check.description);
  assert(cchecks_check_hint((CChecksBaseCheck *)&check) == check.hint);

  CChecksCheckResult result = cchecks_run((CChecksBaseCheck *)&check);

  CChecksStatus result_status = cchecks_check_result_status(&result);
  std::string_view result_message =
      std::string_view(cchecks_check_result_message(&result).string);
  const CChecksItems *result_items = cchecks_check_result_items(&result);
  const char *result_error = cchecks_check_result_error(&result);

  if (result_status == CChecksStatusSystemError) {
    assert(cchecks_check_result_can_fix(&result) == false);
    assert(cchecks_check_result_can_skip(&result) == false);
  } else {
    assert(cchecks_check_result_can_fix(&result) == check.can_fix);
    assert(cchecks_check_result_can_skip(&result) == check.can_skip);
  }

  if (cchecks_status_has_failed(&result_status) &&
      cchecks_check_result_can_fix(&result)) {
    CChecksCheckResult fix_result =
        cchecks_auto_fix((CChecksBaseCheck *)&check);

    CChecksStatus fix_result_status = cchecks_check_result_status(&fix_result);
    std::string_view fix_result_message =
        std::string_view(cchecks_check_result_message(&fix_result).string);
    const CChecksItems *fix_result_items =
        cchecks_check_result_items(&fix_result);
    const char *fix_result_error = cchecks_check_result_error(&fix_result);

    CChecksCheckHint fix_hint = cchecks_check_hint((CChecksBaseCheck *)&check);

    if ((fix_hint & CCHECKS_CHECK_HINT_AUTO_FIX) !=
        CCHECKS_CHECK_HINT_AUTO_FIX) {
      assert(fix_result_status == CChecksStatusSystemError);
      assert(fix_result_message == "Check does not implement auto fix.");
      assert(fix_result_items == nullptr);
      assert(fix_result_error == nullptr);
    } else if (fix_result_error != nullptr) {
      assert(fix_result_status == CChecksStatusSystemError);
      assert(fix_result_message == "Error in auto fix.");
      assert(fix_result_items == nullptr);
      assert(std::string_view(fix_result_error) == check.error);
    } else {
      assert(fix_result_status == check.fix_status);
      assert(fix_result_message == check.message);

      if (check.items == nullptr) {
        assert(fix_result_items == nullptr);
      } else {
        assert(fix_result_items != nullptr);

        cchecks_items_eq(fix_result_items, ((CChecksItems *)check.items));
      }

      assert(fix_result_error == nullptr);
    }

    if (fix_result_status == CChecksStatusSystemError) {
      assert(cchecks_check_result_can_fix(&fix_result) == false);
      assert(cchecks_check_result_can_skip(&fix_result) == false);
    } else {
      assert(cchecks_check_result_can_fix(&fix_result) == check.can_fix);
      assert(cchecks_check_result_can_skip(&fix_result) == check.can_skip);
    }

    cchecks_check_result_destroy(&fix_result);
  }

  cchecks_check_result_destroy(&result);

  if ((CChecksItems *)check.items != nullptr) {
    cchecks_items_destroy((CChecksItems *)check.items);
  }
  return 0;
}
