#[cfg(feature = "async-tokio-scheduler")]
mod tests {
    use std::borrow::Cow;

    use openchecks::{
        scheduler::{AsyncScheduler, AsyncTokioScheduler},
        AsyncCheck, CheckHint, CheckMetadata, CheckResult, Item,
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

    struct TestCheck;

    impl CheckMetadata for TestCheck {
        fn title(&self) -> Cow<str> {
            "TestCheck".into()
        }

        fn description(&self) -> Cow<str> {
            "Description".into()
        }

        fn hint(&self) -> CheckHint {
            CheckHint::AUTO_FIX
        }
    }

    #[async_trait::async_trait]
    impl AsyncCheck for TestCheck {
        type Item = TestItem;
        type Items = Vec<Self::Item>;

        async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
            CheckResult::new_passed("message", None, false, false)
        }

        async fn async_auto_fix(&mut self) -> Result<(), openchecks::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_run_success() {
        let scheduler = AsyncTokioScheduler::new();

        let checks: Vec<Box<dyn AsyncCheck<Item = _, Items = _> + Send + Sync + 'static>> =
            vec![Box::new(TestCheck)];
        let result = scheduler.async_run(checks).await;

        assert_eq!(result.len(), 1);
        assert!(result[0].1.status().has_passed());
    }

    #[tokio::test]
    async fn test_auto_fix_success() {
        let scheduler = AsyncTokioScheduler::new();

        let checks: Vec<Box<dyn AsyncCheck<Item = _, Items = _> + Send + Sync + 'static>> =
            vec![Box::new(TestCheck)];
        let result = scheduler.async_auto_fix(checks).await;

        assert_eq!(result.len(), 1);
        assert!(result[0].1.status().has_passed());
    }
}
