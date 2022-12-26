/// The item is a wrapper to make a result item more user interface friendly.
///
/// Result items represent the objects that caused a result. For example, if a
/// check failed because the bones in a character rig are not properly named,
/// then the items would contain the bones that are named incorrectly.
///
/// The item wrapper makes the use of items user interface friendly because it
/// implements item sorting and a string representation of the item.
///
/// # Examples
/// ```rust
/// # use checks::Item;
/// #
/// # #[derive(Debug)]
/// # struct SceneNode {
/// #     name: String,
/// # }
/// #
/// # impl SceneNode {
/// #     fn new<T: AsRef<str>>(name: T) -> Self {
/// #         Self { name: name.as_ref().to_string() }
/// #     }
/// #
/// #     fn name(&self) -> &str { &self.name }
/// # }
/// #[derive(Debug)]
/// struct SceneItem {
///     // The implementation of the scene node for this example doesn't matter.
///     scene_node: SceneNode,
/// }
///
/// impl std::cmp::PartialEq<SceneItem> for SceneItem {
///     fn eq(&self, other: &SceneItem) -> bool {
///         self.scene_node.name() == other.scene_node.name()
///     }
/// }
///
/// impl std::cmp::PartialOrd<SceneItem> for SceneItem {
///     fn partial_cmp(&self, other: &SceneItem) -> Option<std::cmp::Ordering> {
///         self.scene_node.name().partial_cmp(other.scene_node.name())
///     }
/// }
///
/// impl std::fmt::Display for SceneItem {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         self.scene_node.name().fmt(f)
///     }
/// }
///
/// impl<'a> Item for &'a SceneItem {
///     type Value = &'a SceneNode;
///
///     fn value(&self) -> Self::Value {
///         &self.scene_node
///     }
/// }
///
/// let a = SceneItem{ scene_node: SceneNode::new("a") };
/// let b = SceneItem{ scene_node: SceneNode::new("b") };
///
/// assert_ne!(a, b);
/// assert!(a < b);
/// assert_eq!(&format!("{}", a), "a");
/// ```
pub trait Item:
    std::cmp::PartialEq + std::cmp::PartialOrd + std::fmt::Display + std::fmt::Debug
{
    /// The value that is wrapped.
    type Value;

    /// The wrapped value.
    fn value(&self) -> Self::Value;

    /// A type hint can be used to add a hint to a system that the given type
    /// represents something else. For example, the value could be a string, but
    /// this is a scene path.
    ///
    /// A user interface could use this hint to select the item in the
    /// application.
    fn type_hint(&self) -> Option<&'static str> {
        None
    }
}
