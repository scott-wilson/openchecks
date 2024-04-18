#include <tuple>
#include <vector>

#include <gtest/gtest.h>

#include <cppchecks/core.h>
#include <cppchecks/item.h>
#include <cppchecks/items.h>
#include <cppchecks/result.h>
#include <cppchecks/runner.h>
#include <cppchecks/status.h>

#include "check_impl.h"
#include "item_impl.h"
#include "items_impl.h"
#include "result_impl.h"

// clang-format off
class CheckParameterizedTestFixture
    : public ::testing::TestWithParam<std::tuple<
    std::string,  // title
    std::string,  // description
    CPPCHECKS_NAMESPACE::CheckHint,  // hint
    CPPCHECKS_NAMESPACE::Status,  // status
    CPPCHECKS_NAMESPACE::Status,  // fix_status
    std::string,  // message
    std::optional<IntItems>,  // items
    bool,  // can_fix
    bool,  // can_skip
    std::optional<std::string>  // error
    >> {};
// clang-format on

TEST_P(CheckParameterizedTestFixture, ResultSuccess) {
  std::string title = std::get<0>(GetParam());
  std::string description = std::get<1>(GetParam());
  CPPCHECKS_NAMESPACE::CheckHint hint = std::get<2>(GetParam());
  CPPCHECKS_NAMESPACE::Status status = std::get<3>(GetParam());
  CPPCHECKS_NAMESPACE::Status fix_status = std::get<4>(GetParam());
  std::string message = std::get<5>(GetParam());
  std::optional<IntItems> items = std::get<6>(GetParam());
  bool can_fix = std::get<7>(GetParam());
  bool can_skip = std::get<8>(GetParam());
  std::optional<std::string> error = std::get<9>(GetParam());

  Check check = Check{title,   description, hint,    status,   fix_status,
                      message, items,       can_fix, can_skip, error};

  assert(check.title() == check._title);
  assert(check.description() == check._description);
  assert(check.hint() == check._hint);

  IntResult result = CPPCHECKS_NAMESPACE::run(check);

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

  assert(result_message == check._message);
  assert(result_items == check._items);
  assert(result_error == check._error);

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
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
    CheckResult,
    CheckParameterizedTestFixture,
    ::testing::Combine(
        ::testing::Values(std::string("title"), std::string("")),
        ::testing::Values(std::string("description"), std::string("")),
        ::testing::Values(CPPCHECKS_NAMESPACE::CheckHint::None, CPPCHECKS_NAMESPACE::CheckHint::AutoFix),
        ::testing::Values(CPPCHECKS_NAMESPACE::Status::Pending,
        CPPCHECKS_NAMESPACE::Status::Skipped,
        CPPCHECKS_NAMESPACE::Status::Passed,
        CPPCHECKS_NAMESPACE::Status::Warning,
        CPPCHECKS_NAMESPACE::Status::Failed,
        CPPCHECKS_NAMESPACE::Status::SystemError),
        ::testing::Values(CPPCHECKS_NAMESPACE::Status::Pending,
        CPPCHECKS_NAMESPACE::Status::Skipped,
        CPPCHECKS_NAMESPACE::Status::Passed,
        CPPCHECKS_NAMESPACE::Status::Warning,
        CPPCHECKS_NAMESPACE::Status::Failed,
        CPPCHECKS_NAMESPACE::Status::SystemError),
        ::testing::Values(std::string("message"), std::string("")),
        ::testing::Values(
            IntItems{std::vector<IntItem>{IntItem(0, ""), IntItem(1, ""), IntItem(2, "")}},
            IntItems{std::vector<IntItem>{IntItem(0, "")}},
            IntItems{std::vector<IntItem>{}},
            std::nullopt
        ),
        ::testing::Bool(),
        ::testing::Bool(),
        ::testing::Values(std::string("error"), std::string(), std::nullopt)
    )
);
// clang-format on
