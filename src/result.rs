#[derive(Debug)]
pub struct CheckResult<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>> {
    status: crate::Status,
    message: String,
    items: Option<Items>,
    can_fix: bool,
    can_skip: bool,
    error: Option<crate::Error>,
    check_duration: std::time::Duration,
    fix_duration: std::time::Duration,
}

impl<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>> CheckResult<Item, Items> {
    pub fn new<M: AsRef<str>>(
        status: crate::Status,
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
        error: Option<crate::Error>,
    ) -> Self {
        Self {
            status,
            message: message.as_ref().to_string(),
            items,
            can_fix,
            can_skip,
            error,
            check_duration: std::time::Duration::ZERO,
            fix_duration: std::time::Duration::ZERO,
        }
    }

    pub fn new_passed<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Passed,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    pub fn new_skipped<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Skipped,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    pub fn new_warning<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Warning,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    pub fn new_failed<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Failed,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    pub fn status(&self) -> &crate::Status {
        &self.status
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn items(&self) -> &Option<Items> {
        &self.items
    }

    pub fn can_fix(&self) -> bool {
        if self.status == crate::Status::SystemError {
            false
        } else {
            self.can_fix
        }
    }

    pub fn can_skip(&self) -> bool {
        if self.status == crate::Status::SystemError {
            false
        } else {
            self.can_skip
        }
    }

    pub fn error(&self) -> &Option<crate::Error> {
        &self.error
    }

    pub fn check_duration(&self) -> std::time::Duration {
        self.check_duration
    }

    pub(crate) fn set_check_duration(&mut self, duration: std::time::Duration) {
        self.check_duration = duration
    }

    pub fn fix_duration(&self) -> std::time::Duration {
        self.fix_duration
    }

    pub(crate) fn set_fix_duration(&mut self, duration: std::time::Duration) {
        self.fix_duration = duration
    }
}
