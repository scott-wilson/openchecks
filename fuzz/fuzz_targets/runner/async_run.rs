#![no_main]

use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use openchecks::CheckMetadata;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Arbitrary)]
struct Item {
    value: u32,
}

impl std::fmt::Display for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl openchecks::Item for Item {
    type Value = u32;

    fn value(&self) -> Self::Value {
        self.value
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct Check {
    pub title: String,
    pub description: String,
    pub hint: openchecks::CheckHint,
    pub status: openchecks::Status,
    pub fix_status: openchecks::Status,
    pub message: String,
    pub items: Option<Vec<Item>>,
    pub can_fix: bool,
    pub can_skip: bool,
    pub error: Option<openchecks::Error>,
}

impl openchecks::CheckMetadata for Check {
    fn title(&self) -> std::borrow::Cow<str> {
        std::borrow::Cow::Borrowed(&self.title)
    }

    fn description(&self) -> std::borrow::Cow<str> {
        std::borrow::Cow::Borrowed(&self.description)
    }

    fn hint(&self) -> openchecks::CheckHint {
        self.hint
    }
}

#[async_trait::async_trait]
impl openchecks::AsyncCheck for Check {
    type Item = Item;
    type Items = Vec<Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        openchecks::CheckResult::new(
            self.status,
            &self.message,
            self.items.clone(),
            self.can_fix,
            self.can_skip,
            self.error.clone(),
        )
    }

    async fn async_auto_fix(&mut self) -> Result<(), openchecks::Error> {
        match &self.error {
            Some(error) => Err(error.clone()),
            None => {
                self.status = self.fix_status;
                Ok(())
            }
        }
    }
}

fuzz_target!(|check: Check| {
    let mut check = check;
    assert_eq!(check.title().as_ref(), &check.title);
    assert_eq!(check.description().as_ref(), &check.description);
    assert_eq!(check.hint(), check.hint);

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let result = rt.block_on(async { openchecks::async_run(&check).await });

    assert_eq!(result.status(), &check.status);
    assert_eq!(result.message(), &check.message);
    assert_eq!(result.items(), &check.items);
    assert_eq!(result.error(), &check.error);

    if result.status() == &openchecks::Status::SystemError {
        assert!(!result.can_fix());
        assert!(!result.can_skip());
    } else {
        assert_eq!(result.can_fix(), check.can_fix);
        assert_eq!(result.can_skip(), check.can_skip);
    }

    if result.status().has_failed() && result.can_fix() {
        let fix_result = rt.block_on(async { openchecks::async_auto_fix(&mut check).await });

        if !check.hint().contains(openchecks::CheckHint::AUTO_FIX) {
            assert_eq!(fix_result.status(), &openchecks::Status::SystemError);
            assert_eq!(fix_result.message(), "Check does not implement auto fix.");
            assert_eq!(fix_result.items(), &None);
            assert_eq!(fix_result.error(), &None);
        } else if fix_result.error().is_some() {
            assert_eq!(fix_result.status(), &openchecks::Status::SystemError);
            assert_eq!(fix_result.message(), "Error in auto fix.");
            assert_eq!(fix_result.items(), &None);
            assert_eq!(fix_result.error(), &check.error);
        } else {
            assert_eq!(fix_result.status(), &check.fix_status);
            assert_eq!(fix_result.message(), &check.message);
            assert_eq!(fix_result.items(), &check.items);
            assert_eq!(fix_result.error(), &check.error);
        }

        if fix_result.status() == &openchecks::Status::SystemError {
            assert!(!fix_result.can_fix());
            assert!(!fix_result.can_skip());
        } else {
            assert_eq!(fix_result.can_fix(), check.can_fix);
            assert_eq!(fix_result.can_skip(), check.can_skip);
        }
    }
});
