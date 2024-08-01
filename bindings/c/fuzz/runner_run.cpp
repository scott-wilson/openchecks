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

typedef struct Check {
  OpenChecksBaseCheck header;
  std::string title;
  std::string description;
  OpenChecksCheckHint hint;
  OpenChecksStatus status;
  OpenChecksStatus fix_status;
  std::string message;
  bool has_items;
  IntItems *items;
  bool can_fix;
  bool can_skip;
  bool has_error;
  std::string error;
} Check;

const char *check_title_fn(const OpenChecksBaseCheck *check) {
  return ((Check *)check)->title.c_str();
}

const char *check_description_fn(const OpenChecksBaseCheck *check) {
  return ((Check *)check)->description.c_str();
}

OpenChecksCheckHint check_hint_fn(const OpenChecksBaseCheck *check) {
  return ((Check *)check)->hint;
}

OpenChecksCheckResult check_run_fn(const OpenChecksBaseCheck *check) {
  OpenChecksStatus status = ((Check *)check)->status;
  const char *message = ((Check *)check)->message.c_str();
  OpenChecksItems *items;
  bool can_fix = ((Check *)check)->can_fix;
  bool can_skip = ((Check *)check)->can_skip;
  const char *error;

  if (((Check *)check)->has_items) {
    items = (OpenChecksItems *)((Check *)check)->items;
  } else {
    items = nullptr;
  }

  if (((Check *)check)->has_error) {
    error = ((Check *)check)->error.c_str();
  } else {
    error = nullptr;
  }

  return openchecks_check_result_new(status, message, items, can_fix, can_skip,
                                     error);
}

OpenChecksAutoFixResult check_auto_fix_fn(OpenChecksBaseCheck *check) {
  if (((Check *)check)->has_error) {
    return openchecks_check_auto_fix_error(((Check *)check)->error.c_str());
  } else {
    ((Check *)check)->status = ((Check *)check)->fix_status;
    return openchecks_check_auto_fix_ok();
  }
}

OpenChecksCheckHint get_hint(FuzzedDataProvider &provider) {
  OpenChecksCheckHint hint = OPENCHECKS_CHECK_HINT_NONE;

  if (provider.ConsumeBool()) {
    hint |= OPENCHECKS_CHECK_HINT_AUTO_FIX;
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
  check.status = (OpenChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
      (uint8_t)OpenChecksStatusPending, (uint8_t)OpenChecksStatusSystemError);
  check.fix_status = (OpenChecksStatus)provider.ConsumeIntegralInRange<uint8_t>(
      (uint8_t)OpenChecksStatusPending, (uint8_t)OpenChecksStatusSystemError);
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
             openchecks_check_title(((OpenChecksBaseCheck *)&check)).string) ==
         check.title);
  assert(std::string_view(
             openchecks_check_description(((OpenChecksBaseCheck *)&check))
                 .string) == check.description);
  assert(openchecks_check_hint((OpenChecksBaseCheck *)&check) == check.hint);

  OpenChecksCheckResult result = openchecks_run((OpenChecksBaseCheck *)&check);

  OpenChecksStatus result_status = openchecks_check_result_status(&result);
  std::string_view result_message =
      std::string_view(openchecks_check_result_message(&result).string);
  const OpenChecksItems *result_items = openchecks_check_result_items(&result);
  const char *result_error = openchecks_check_result_error(&result);

  assert(result_message == check.message);
  assert(openchecks_items_eq(result_items, ((OpenChecksItems *)check.items)));

  if (check.has_error) {
    assert(result_error != nullptr);
    assert(std::string_view(result_error) == check.error);
  } else {
    assert(result_error == nullptr);
  }

  if (result_status == OpenChecksStatusSystemError) {
    assert(openchecks_check_result_can_fix(&result) == false);
    assert(openchecks_check_result_can_skip(&result) == false);
  } else {
    assert(openchecks_check_result_can_fix(&result) == check.can_fix);
    assert(openchecks_check_result_can_skip(&result) == check.can_skip);
  }

  if (openchecks_status_has_failed(&result_status) &&
      openchecks_check_result_can_fix(&result)) {
    OpenChecksCheckResult fix_result =
        openchecks_auto_fix((OpenChecksBaseCheck *)&check);

    OpenChecksStatus fix_result_status =
        openchecks_check_result_status(&fix_result);
    std::string_view fix_result_message =
        std::string_view(openchecks_check_result_message(&fix_result).string);
    const OpenChecksItems *fix_result_items =
        openchecks_check_result_items(&fix_result);
    const char *fix_result_error = openchecks_check_result_error(&fix_result);

    OpenChecksCheckHint fix_hint =
        openchecks_check_hint((OpenChecksBaseCheck *)&check);

    if ((fix_hint & OPENCHECKS_CHECK_HINT_AUTO_FIX) !=
        OPENCHECKS_CHECK_HINT_AUTO_FIX) {
      assert(fix_result_status == OpenChecksStatusSystemError);
      assert(fix_result_message == "Check does not implement auto fix.");
      assert(fix_result_items == nullptr);
      assert(fix_result_error == nullptr);
    } else if (fix_result_error != nullptr) {
      assert(fix_result_status == OpenChecksStatusSystemError);
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

        openchecks_items_eq(fix_result_items, ((OpenChecksItems *)check.items));
      }

      assert(fix_result_error == nullptr);
    }

    if (fix_result_status == OpenChecksStatusSystemError) {
      assert(openchecks_check_result_can_fix(&fix_result) == false);
      assert(openchecks_check_result_can_skip(&fix_result) == false);
    } else {
      assert(openchecks_check_result_can_fix(&fix_result) == check.can_fix);
      assert(openchecks_check_result_can_skip(&fix_result) == check.can_skip);
    }

    openchecks_check_result_destroy(&fix_result);
  }

  openchecks_check_result_destroy(&result);

  if ((OpenChecksItems *)check.items != nullptr) {
    openchecks_items_destroy((OpenChecksItems *)check.items);
  }
  return 0;
}
