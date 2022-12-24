use checks::{CheckResult, Item, Status};

#[derive(Debug, PartialEq, PartialOrd)]
struct TestItem {
    value: u8,
}

impl std::fmt::Display for TestItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Test")
    }
}

impl Item for TestItem {
    type Value = u8;

    fn value(&self) -> Self::Value {
        self.value
    }
}

#[test]
fn test_check_result_new_success() {
    let status = Status::Passed;
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    assert_eq!(result.status(), &status);
    assert_eq!(result.message(), message);
    assert!(result.items().is_none());
    assert_eq!(result.can_fix(), can_fix);
    assert_eq!(result.can_skip(), can_skip);
    assert!(result.error().is_none());
}

#[test]
fn test_check_result_debug_success() {
    let status = Status::Passed;
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    let debug_msg = format!("{:?}", result);
    assert_eq!(&debug_msg, "CheckResult { status: Passed, message: \"test\", items: None, can_fix: false, can_skip: true, error: None, check_duration: 0ns, fix_duration: 0ns }")
}

#[test]
fn test_check_result_new_passed() {
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new_passed(message, items, can_fix, can_skip);

    assert_eq!(result.status(), &Status::Passed);
    assert_eq!(result.message(), message);
    assert_eq!(result.items(), &None);
    assert_eq!(result.can_fix(), false);
    assert_eq!(result.can_skip(), true);
}

#[test]
fn test_check_result_new_skipped() {
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new_skipped(message, items, can_fix, can_skip);

    assert_eq!(result.status(), &Status::Skipped);
    assert_eq!(result.message(), message);
    assert_eq!(result.items(), &None);
    assert_eq!(result.can_fix(), false);
    assert_eq!(result.can_skip(), true);
}

#[test]
fn test_check_result_new_warning() {
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new_warning(message, items, can_fix, can_skip);

    assert_eq!(result.status(), &Status::Warning);
    assert_eq!(result.message(), message);
    assert_eq!(result.items(), &None);
    assert_eq!(result.can_fix(), false);
    assert_eq!(result.can_skip(), true);
}

#[test]
fn test_check_result_new_failed() {
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new_failed(message, items, can_fix, can_skip);

    assert_eq!(result.status(), &Status::Failed);
    assert_eq!(result.message(), message);
    assert_eq!(result.items(), &None);
    assert_eq!(result.can_fix(), false);
    assert_eq!(result.can_skip(), true);
}

#[test]
fn test_can_fix() {
    // Can skip
    let status = Status::Passed;
    let message = "test";
    let items = None;
    let can_fix = true;
    let can_skip = true;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    assert_eq!(result.can_fix(), can_fix);

    // Cannot skip
    let status = Status::Passed;
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = false;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    assert_eq!(result.can_fix(), can_fix);

    // Cannot skip - System Error
    let status = Status::SystemError;
    let message = "test";
    let items = None;
    let can_fix = true;
    let can_skip = false;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    assert_eq!(result.can_fix(), false);
}

#[test]
fn test_can_skip() {
    // Can skip
    let status = Status::Passed;
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    assert_eq!(result.can_skip(), can_skip);

    // Cannot skip
    let status = Status::Passed;
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = false;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    assert_eq!(result.can_skip(), can_skip);

    // Cannot skip - System Error
    let status = Status::SystemError;
    let message = "test";
    let items = None;
    let can_fix = false;
    let can_skip = true;
    let error = None;

    let result: CheckResult<TestItem, Vec<TestItem>> =
        CheckResult::new(status, message, items, can_fix, can_skip, error);

    assert_eq!(result.can_skip(), false);
}
