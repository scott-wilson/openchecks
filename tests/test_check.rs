use std::borrow::Cow;

use checks::{AsyncCheck, Check, CheckHint, CheckMetadata, CheckResult, Item};

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
    type Value = u8;

    fn value(&self) -> Self::Value {
        self.value
    }
}

#[test]
fn test_check_metadata_hint_success() {
    struct TestCheck {
        value: u8,
    }

    impl CheckMetadata for TestCheck {
        fn title(&self) -> Cow<str> {
            "TestCheck".into()
        }

        fn description(&self) -> Cow<str> {
            "Description".into()
        }
    }

    let check = TestCheck { value: 1 };

    assert_eq!(check.hint(), CheckHint::all());
}

#[test]
fn test_check_auto_fix_failed_not_implemented() {
    struct TestCheck {
        value: u8,
    }

    impl CheckMetadata for TestCheck {
        fn title(&self) -> Cow<str> {
            "TestCheck".into()
        }

        fn description(&self) -> Cow<str> {
            "Description".into()
        }

        fn hint(&self) -> CheckHint {
            CheckHint::NONE
        }
    }

    impl Check for TestCheck {
        type Item = TestItem;
        type Items = Vec<Self::Item>;

        fn check(&self) -> checks::CheckResult<Self::Item, Self::Items> {
            CheckResult::new_failed("Test", None, true, false)
        }
    }

    let mut check = TestCheck { value: 1 };

    assert!(check.auto_fix().is_err());
}

#[tokio::test]
async fn test_async_check_async_auto_fix_failed_not_implemented() {
    struct TestCheck {
        value: u8,
    }

    impl CheckMetadata for TestCheck {
        fn title(&self) -> Cow<str> {
            "TestCheck".into()
        }

        fn description(&self) -> Cow<str> {
            "Description".into()
        }

        fn hint(&self) -> CheckHint {
            CheckHint::NONE
        }
    }

    #[async_trait::async_trait]
    impl AsyncCheck for TestCheck {
        type Item = TestItem;
        type Items = Vec<Self::Item>;

        async fn async_check(&self) -> checks::CheckResult<Self::Item, Self::Items> {
            CheckResult::new_failed("Test", None, true, false)
        }
    }

    let mut check = TestCheck { value: 1 };

    assert!(check.async_auto_fix().await.is_err());
}
