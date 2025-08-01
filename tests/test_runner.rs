use std::borrow::Cow;

use openchecks::{
    async_auto_fix, async_run, auto_fix, run, AsyncCheck, Check, CheckHint, CheckMetadata,
    CheckResult, Error, Item, Status,
};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
struct TestItem {
    value: u8,
}

impl std::fmt::Display for TestItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Item for TestItem {
    type Value<'a>
        = u8
    where
        Self: 'a;

    fn value(&self) -> Self::Value<'_> {
        self.value
    }
}

struct TestCheckNoAutoFix {
    value: u8,
}

impl CheckMetadata for TestCheckNoAutoFix {
    fn title(&self) -> Cow<str> {
        "TestCheckNoAutoFix".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::NONE
    }
}

impl Check for TestCheckNoAutoFix {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }
}

struct TestCheckAutoFix {
    value: u8,
}

impl CheckMetadata for TestCheckAutoFix {
    fn title(&self) -> Cow<str> {
        "TestCheckAutoFix".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

impl Check for TestCheckAutoFix {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    fn auto_fix(&mut self) -> Result<(), openchecks::Error> {
        self.value = 0;
        Ok(())
    }
}

struct TestCheckAutoFixNoFix {
    value: u8,
}

impl CheckMetadata for TestCheckAutoFixNoFix {
    fn title(&self) -> Cow<str> {
        "TestCheckAutoFixNoFix".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

impl Check for TestCheckAutoFixNoFix {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    fn auto_fix(&mut self) -> Result<(), openchecks::Error> {
        Ok(())
    }
}

struct TestCheckAutoFixError {
    value: u8,
}

impl CheckMetadata for TestCheckAutoFixError {
    fn title(&self) -> Cow<str> {
        "TestCheckAutoFixError".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

impl Check for TestCheckAutoFixError {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    fn auto_fix(&mut self) -> Result<(), openchecks::Error> {
        Err(Error::new("test"))
    }
}

struct TestCheckAutoFixNotImplemented {
    value: u8,
}

impl CheckMetadata for TestCheckAutoFixNotImplemented {
    fn title(&self) -> Cow<str> {
        "TestCheckAutoFixNotImplemented".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

impl Check for TestCheckAutoFixNotImplemented {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }
}

struct TestCheckAutoFixNoneHint {
    value: u8,
}

impl CheckMetadata for TestCheckAutoFixNoneHint {
    fn title(&self) -> Cow<str> {
        "TestCheckAutoFixNoneHint".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::NONE
    }
}

impl Check for TestCheckAutoFixNoneHint {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    fn auto_fix(&mut self) -> Result<(), openchecks::Error> {
        Ok(())
    }
}

struct AsyncTestCheckNoAutoFix {
    value: u8,
}

impl CheckMetadata for AsyncTestCheckNoAutoFix {
    fn title(&self) -> Cow<str> {
        "AsyncTestCheckNoAutoFix".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::NONE
    }
}

#[async_trait::async_trait]
impl AsyncCheck for AsyncTestCheckNoAutoFix {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }
}

struct AsyncTestCheckAutoFix {
    value: u8,
}

impl CheckMetadata for AsyncTestCheckAutoFix {
    fn title(&self) -> Cow<str> {
        "AsyncTestCheckAutoFix".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

#[async_trait::async_trait]
impl AsyncCheck for AsyncTestCheckAutoFix {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    async fn async_auto_fix(&mut self) -> Result<(), openchecks::Error> {
        self.value = 0;
        Ok(())
    }
}

struct AsyncTestCheckAutoFixNoFix {
    value: u8,
}

impl CheckMetadata for AsyncTestCheckAutoFixNoFix {
    fn title(&self) -> Cow<str> {
        "AsyncTestCheckAutoFixNoFix".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

#[async_trait::async_trait]
impl AsyncCheck for AsyncTestCheckAutoFixNoFix {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    async fn async_auto_fix(&mut self) -> Result<(), openchecks::Error> {
        Ok(())
    }
}

struct AsyncTestCheckAutoFixError {
    value: u8,
}

impl CheckMetadata for AsyncTestCheckAutoFixError {
    fn title(&self) -> Cow<str> {
        "AsyncTestCheckAutoFixError".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

#[async_trait::async_trait]
impl AsyncCheck for AsyncTestCheckAutoFixError {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    async fn async_auto_fix(&mut self) -> Result<(), openchecks::Error> {
        Err(Error::new("test"))
    }
}

struct AsyncTestCheckAutoFixNotImplemented {
    value: u8,
}

impl CheckMetadata for AsyncTestCheckAutoFixNotImplemented {
    fn title(&self) -> Cow<str> {
        "AsyncTestCheckAutoFixNotImplemented".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::AUTO_FIX
    }
}

#[async_trait::async_trait]
impl AsyncCheck for AsyncTestCheckAutoFixNotImplemented {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }
}

struct AsyncTestCheckAutoFixNoneHint {
    value: u8,
}

impl CheckMetadata for AsyncTestCheckAutoFixNoneHint {
    fn title(&self) -> Cow<str> {
        "AsyncTestCheckAutoFixNoneHint".into()
    }

    fn description(&self) -> Cow<str> {
        "description".into()
    }

    fn hint(&self) -> CheckHint {
        CheckHint::NONE
    }
}

#[async_trait::async_trait]
impl AsyncCheck for AsyncTestCheckAutoFixNoneHint {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        if self.value != 0 {
            CheckResult::new_failed(
                "Value is not 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        } else {
            CheckResult::new_passed(
                "Value is 0",
                Some(vec![TestItem { value: self.value }]),
                true,
                false,
            )
        }
    }

    async fn async_auto_fix(&mut self) -> Result<(), openchecks::Error> {
        Ok(())
    }
}

#[test]
fn test_check_passed() {
    let check = TestCheckNoAutoFix { value: 0 };
    let result = run(&check);

    assert_eq!(result.status(), &Status::Passed);
}

#[test]
fn test_check_failed() {
    let check = TestCheckNoAutoFix { value: 1 };
    let result = run(&check);

    assert_eq!(result.status(), &Status::Failed);
}

#[test]
fn test_auto_fix_success() {
    let mut check = TestCheckAutoFix { value: 1 };
    let result = run(&check);

    assert_eq!(result.status(), &Status::Failed);

    let result = auto_fix(&mut check);

    assert_eq!(result.status(), &Status::Passed);
}

#[test]
fn test_auto_fix_failed_no_fix() {
    let mut check = TestCheckAutoFixNoFix { value: 1 };
    let result = run(&check);

    assert_eq!(result.status(), &Status::Failed);

    let result = auto_fix(&mut check);

    assert_eq!(result.status(), &Status::Failed);
}

#[test]
fn test_auto_fix_failed_error() {
    let mut check = TestCheckAutoFixError { value: 1 };
    let result = run(&check);

    assert_eq!(result.status(), &Status::Failed);

    let result = auto_fix(&mut check);

    assert_eq!(result.status(), &Status::SystemError);
    assert_eq!(format!("{}", result.error().as_ref().unwrap()), "test");
}

#[test]
fn test_auto_fix_failed_not_implemented() {
    let mut check = TestCheckAutoFixNotImplemented { value: 1 };
    let result = run(&check);

    assert_eq!(result.status(), &Status::Failed);

    let result = auto_fix(&mut check);

    assert_eq!(result.status(), &Status::SystemError);
    assert_eq!(
        format!("{}", result.error().as_ref().unwrap()),
        "Auto fix is not implemented."
    );
}

#[test]
fn test_auto_fix_failed_none_hint() {
    let mut check = TestCheckAutoFixNoneHint { value: 1 };
    let result = run(&check);

    assert_eq!(result.status(), &Status::Failed);

    let result = auto_fix(&mut check);

    assert_eq!(result.status(), &Status::SystemError);
    assert_eq!(result.message(), "Check does not implement auto fix.");
    assert!(result.error().is_none());
}

#[tokio::test]
async fn test_async_check_passed() {
    let check = AsyncTestCheckNoAutoFix { value: 0 };
    let result = async_run(&check).await;

    assert_eq!(result.status(), &Status::Passed);
}

#[tokio::test]
async fn test_async_check_failed() {
    let check = AsyncTestCheckNoAutoFix { value: 1 };
    let result = async_run(&check).await;

    assert_eq!(result.status(), &Status::Failed);
}

#[tokio::test]
async fn test_async_auto_fix_success() {
    let mut check = AsyncTestCheckAutoFix { value: 1 };
    let result = async_run(&check).await;

    assert_eq!(result.status(), &Status::Failed);

    let result = async_auto_fix(&mut check).await;

    assert_eq!(result.status(), &Status::Passed);
}

#[tokio::test]
async fn test_async_auto_fix_failed_no_fix() {
    let mut check = AsyncTestCheckAutoFixNoFix { value: 1 };
    let result = async_run(&check).await;

    assert_eq!(result.status(), &Status::Failed);

    let result = async_auto_fix(&mut check).await;

    assert_eq!(result.status(), &Status::Failed);
}

#[tokio::test]
async fn test_async_auto_fix_failed_error() {
    let mut check = AsyncTestCheckAutoFixError { value: 1 };
    let result = async_run(&check).await;

    assert_eq!(result.status(), &Status::Failed);

    let result = async_auto_fix(&mut check).await;

    assert_eq!(result.status(), &Status::SystemError);
    assert_eq!(format!("{}", result.error().as_ref().unwrap()), "test");
}

#[tokio::test]
async fn test_async_auto_fix_failed_not_implemented() {
    let mut check = AsyncTestCheckAutoFixNotImplemented { value: 1 };
    let result = async_run(&check).await;

    assert_eq!(result.status(), &Status::Failed);

    let result = async_auto_fix(&mut check).await;

    assert_eq!(result.status(), &Status::SystemError);
    assert_eq!(
        format!("{}", result.error().as_ref().unwrap()),
        "Auto fix is not implemented."
    );
}

#[tokio::test]
async fn test_async_auto_fix_failed_none_hint() {
    let mut check = AsyncTestCheckAutoFixNoneHint { value: 1 };
    let result = async_run(&check).await;

    assert_eq!(result.status(), &Status::Failed);

    let result = async_auto_fix(&mut check).await;

    assert_eq!(result.status(), &Status::SystemError);
    assert_eq!(result.message(), "Check does not implement auto fix.");
    assert!(result.error().is_none());
}
