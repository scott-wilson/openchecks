use crate::{AsyncCheck, Check};

type QueryFn<Ctx> = Box<dyn Fn(&Ctx) -> bool>;
type GeneratorFn<Ctx, Item, Items> =
    Box<dyn Fn(&Ctx) -> Vec<Box<dyn Check<Item = Item, Items = Items>>>>;
type AsyncGeneratorFn<Ctx, Item, Items> =
    Box<dyn Fn(&Ctx) -> Vec<Box<dyn AsyncCheck<Item = Item, Items = Items>>>>;

/// The discovery registry allows checks to be discovered based on the input
/// context.
///
/// The registry accepts two functions. The query function that is responsible
/// for querying if the context is valid, and the generate function that will
/// take the context and transform it into checks to be validated against.
///
/// # Examples
///
/// ```rust
/// # use openchecks::{
/// #     run, AsyncCheck, Check, CheckHint, CheckMetadata, CheckResult, DiscoveryRegistry, Item,
/// # };
/// #
/// # #[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
/// # struct MyItem {
/// #     value: u8,
/// # }
/// #
/// # impl std::fmt::Display for MyItem {
/// #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
/// #         write!(f, "{}", self.value)
/// #     }
/// # }
/// #
/// # impl Item for MyItem {
/// #     type Value<'a>
/// #             = u8
/// #         where
/// #             Self: 'a;
/// #
/// #     fn value(&self) -> Self::Value<'_> {
/// #         self.value
/// #     }
/// # }
/// #
/// # struct MyCheck;
/// #
/// # impl CheckMetadata for MyCheck {
/// #     fn title(&self) -> std::borrow::Cow<str> {
/// #         "MyCheck".into()
/// #     }
/// #
/// #     fn description(&self) -> std::borrow::Cow<str> {
/// #         "Description".into()
/// #     }
/// #
/// #     fn hint(&self) -> CheckHint {
/// #         CheckHint::NONE
/// #     }
/// # }
/// #
/// # impl Check for MyCheck {
/// #     type Item = MyItem;
/// #     type Items = Vec<Self::Item>;
/// #
/// #     fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
/// #         CheckResult::new_passed("message", None, false, false)
/// #     }
/// # }
/// #
/// # #[async_trait::async_trait]
/// # impl AsyncCheck for MyCheck {
/// #     type Item = MyItem;
/// #     type Items = Vec<Self::Item>;
/// #
/// #     async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
/// #         CheckResult::new_passed("message", None, false, false)
/// #     }
/// # }
/// #
/// # #[derive(Debug)]
/// # struct SceneNode {
/// #     name: String,
/// # }
/// #
/// # impl SceneNode {
/// #     fn new<T: AsRef<str>>(name: T) -> Self {
/// #         Self {
/// #             name: name.as_ref().to_string(),
/// #         }
/// #     }
/// #
/// #     fn name(&self) -> &str {
/// #         &self.name
/// #     }
/// # }
/// let mut registry = DiscoveryRegistry::new();
///
/// registry.register(
///     |ctx: &SceneNode| ctx.name() == "test",
///     |_ctx| vec![Box::new(MyCheck)],
/// );
///
/// if let Some(checks) = registry.gather(&SceneNode::new("test")) {
///     for check in checks {
///         let _result = run(check.as_ref());
///     }
/// }
/// ```
pub struct DiscoveryRegistry<Ctx, Item, Items>
where
    Item: crate::Item,
    Items: IntoIterator<Item = Item>,
{
    plugins: Vec<(QueryFn<Ctx>, GeneratorFn<Ctx, Item, Items>)>,
    async_plugins: Vec<(QueryFn<Ctx>, AsyncGeneratorFn<Ctx, Item, Items>)>,
}

impl<Ctx, Item, Items> Default for DiscoveryRegistry<Ctx, Item, Items>
where
    Item: crate::Item,
    Items: IntoIterator<Item = Item>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Ctx, Item, Items> DiscoveryRegistry<Ctx, Item, Items>
where
    Item: crate::Item,
    Items: IntoIterator<Item = Item>,
{
    /// Create a new instance of the discovery registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            async_plugins: Vec::new(),
        }
    }

    /// Register the functions that will find the checks to be run.
    ///
    /// The query function is responsible for querying if the gather method for
    /// the registry will return the contents of the generator function. The
    /// generator function is responsible for returning a list of checks for the
    /// given context.
    pub fn register<
        Query: Fn(&Ctx) -> bool + 'static,
        Generator: Fn(&Ctx) -> Vec<Box<dyn Check<Item = Item, Items = Items>>> + 'static,
    >(
        &mut self,
        query: Query,
        generator: Generator,
    ) {
        self.plugins.push((Box::new(query), Box::new(generator)));
    }

    /// Register the functions that will find the checks to be run in async.
    ///
    /// The query function is responsible for querying if the gather method for
    /// the registry will return the contents of the generator function. The
    /// generator function is responsible for returning a list of checks for the
    /// given context.
    pub fn register_async<
        Query: Fn(&Ctx) -> bool + 'static,
        Generator: Fn(&Ctx) -> Vec<Box<dyn AsyncCheck<Item = Item, Items = Items>>> + 'static,
    >(
        &mut self,
        query: Query,
        generator: Generator,
    ) {
        self.async_plugins
            .push((Box::new(query), Box::new(generator)));
    }

    /// Return the checks that should be run for the given context.
    ///
    /// If the result is `None`, then nothing was found that will return valid
    /// checks.
    ///
    /// If two query functions were to return a valid set of checks, then the
    /// first one that was registered will return the associated checks.
    pub fn gather(&self, context: &Ctx) -> Option<Vec<Box<dyn Check<Item = Item, Items = Items>>>> {
        for (query, generator) in &self.plugins {
            if query(context) {
                return Some(generator(context));
            }
        }

        None
    }

    /// Return the async checks that should be run for the given context.
    ///
    /// If the result is `None`, then nothing was found that will return valid
    /// checks.
    ///
    /// If two query functions were to return a valid set of checks, then the
    /// first one that was registered will return the associated checks.
    pub fn gather_async(
        &self,
        context: &Ctx,
    ) -> Option<Vec<Box<dyn AsyncCheck<Item = Item, Items = Items>>>> {
        for (query, generator) in &self.async_plugins {
            if query(context) {
                return Some(generator(context));
            }
        }

        None
    }
}
