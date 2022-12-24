#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Skipped,
    Passed,
    Warning,
    Failed,
    SystemError,
}

impl Status {
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    pub fn has_passed(&self) -> bool {
        matches!(self, Self::Passed | Self::Skipped | Self::Warning)
    }

    pub fn has_failed(&self) -> bool {
        matches!(self, Self::Failed | Self::SystemError)
    }
}
