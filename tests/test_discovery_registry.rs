use std::borrow::Cow;

use openchecks::{
    AsyncCheck, Check, CheckHint, CheckMetadata, CheckResult, DiscoveryRegistry, Item,
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
        CheckHint::NONE
    }
}

impl Check for TestCheck {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        CheckResult::new_passed("message", None, false, false)
    }
}

#[async_trait::async_trait]
impl AsyncCheck for TestCheck {
    type Item = TestItem;
    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        CheckResult::new_passed("message", None, false, false)
    }
}

#[test]
fn test_discovery_registry_register_and_gather_success() {
    let mut registry = DiscoveryRegistry::new();
    registry.register(|_ctx: &()| true, |_ctx| vec![Box::new(TestCheck)]);
    let result = registry.gather(&());

    assert!(result.is_some());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn test_discovery_registry_gather_empty_plugins_success() {
    let registry: DiscoveryRegistry<(), TestItem, Vec<_>> = DiscoveryRegistry::new();
    let result = registry.gather(&());

    assert!(result.is_none());
}

#[test]
fn test_discovery_registry_query_context_gather_return_some_success() {
    let mut registry = DiscoveryRegistry::new();
    registry.register(|_ctx: &()| true, |_ctx| vec![Box::new(TestCheck)]);
    let result = registry.gather(&());

    assert!(result.is_some());
}

#[test]
fn test_discovery_registry_query_context_gather_return_none_success() {
    let mut registry = DiscoveryRegistry::new();
    registry.register(|_ctx: &()| false, |_ctx| vec![Box::new(TestCheck)]);
    let result = registry.gather(&());

    assert!(result.is_none());
}

#[test]
fn test_discovery_registry_register_and_gather_async_success() {
    let mut registry = DiscoveryRegistry::new();
    registry.register_async(|_ctx: &()| true, |_ctx| vec![Box::new(TestCheck)]);
    let result = registry.gather_async(&());

    assert!(result.is_some());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn test_discovery_registry_gather_async_empty_plugins_success() {
    let registry: DiscoveryRegistry<(), TestItem, Vec<_>> = DiscoveryRegistry::new();
    let result = registry.gather_async(&());

    assert!(result.is_none());
}

#[test]
fn test_discovery_registry_query_context_gather_async_return_some_success() {
    let mut registry = DiscoveryRegistry::new();
    registry.register_async(|_ctx: &()| true, |_ctx| vec![Box::new(TestCheck)]);
    let result = registry.gather_async(&());

    assert!(result.is_some());
}

#[test]
fn test_discovery_registry_query_context_gather_async_return_none_success() {
    let mut registry = DiscoveryRegistry::new();
    registry.register_async(|_ctx: &()| false, |_ctx| vec![Box::new(TestCheck)]);
    let result = registry.gather_async(&());

    assert!(result.is_none());
}
