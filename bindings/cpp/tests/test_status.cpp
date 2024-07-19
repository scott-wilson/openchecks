#include <gtest/gtest.h>
#include <openchecks/status.h>
#include <tuple>
#include <vector>

TEST(Status, IsStatusPendingSuccess) {
  auto cases = std::vector{
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Pending, true),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Skipped, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Passed, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Warning, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Failed, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::SystemError, false),
  };

  OPENCHECKS_NAMESPACE::Status status;
  bool expected;

  for (auto &&test_case : cases) {
    status = std::get<0>(test_case);
    expected = std::get<1>(test_case);
    ASSERT_EQ(status.is_pending(), expected);
  }
}

TEST(Status, HasStatusPassedSuccess) {
  auto cases = std::vector{
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Pending, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Skipped, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Passed, true),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Warning, true),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Failed, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::SystemError, false),
  };

  OPENCHECKS_NAMESPACE::Status status;
  bool expected;

  for (auto &&test_case : cases) {
    status = std::get<0>(test_case);
    expected = std::get<1>(test_case);
    ASSERT_EQ(status.has_passed(), expected);
  }
}

TEST(Status, HasStatusFailedSuccess) {
  auto cases = std::vector{
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Pending, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Skipped, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Passed, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Warning, false),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::Failed, true),
      std::make_tuple(OPENCHECKS_NAMESPACE::Status::SystemError, true),
  };

  OPENCHECKS_NAMESPACE::Status status;
  bool expected;

  for (auto &&test_case : cases) {
    status = std::get<0>(test_case);
    expected = std::get<1>(test_case);
    ASSERT_EQ(status.has_failed(), expected);
  }
}
