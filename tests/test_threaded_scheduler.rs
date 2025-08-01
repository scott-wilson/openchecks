#[cfg(feature = "threaded-scheduler")]
mod tests {
    use std::borrow::Cow;

    use openchecks::{
        scheduler::{Scheduler, ThreadedScheduler},
        Check, CheckHint, CheckMetadata, CheckResult, Item,
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

    impl Check for TestCheck {
        type Item = TestItem;
        type Items = Vec<Self::Item>;

        fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
            CheckResult::new_passed("message", None, false, false)
        }

        fn auto_fix(&mut self) -> Result<(), openchecks::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_run_success() {
        let scheduler = ThreadedScheduler::new();

        let checks: Vec<Box<dyn Check<Item = _, Items = _> + Send + 'static>> =
            vec![Box::new(TestCheck)];
        let result = scheduler.run(checks);

        assert_eq!(result.len(), 1);
        assert!(result[0].1.status().has_passed());
    }

    #[test]
    fn test_auto_fix_success() {
        let scheduler = ThreadedScheduler::new();

        let checks: Vec<Box<dyn Check<Item = _, Items = _> + Send + 'static>> =
            vec![Box::new(TestCheck)];
        let result = scheduler.auto_fix(checks);

        assert_eq!(result.len(), 1);
        assert!(result[0].1.status().has_passed());
    }
}
