//! Closed, privacy preserving error DTOs. No environment error strings are carried.
use crate::{DecimalU64, Method, OperationLookup};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    None,
    Committed,
    Partial,
    Unknown,
}
macro_rules! codes {
    ($($variant:ident => ($wire:literal, $message:literal, $status:literal)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        pub enum ErrorCode { $(#[serde(rename = $wire)] $variant),+ }
        impl ErrorCode {
            pub fn message(self) -> &'static str { match self { $(Self::$variant => $message),+ } }
            pub fn http_status(self) -> u16 { match self { $(Self::$variant => $status),+ } }
        }
    }
}
codes! {
    InvalidArgument => ("INVALID_ARGUMENT", "Invalid request.", 400),
    AuthRequired => ("AUTH_REQUIRED", "Authentication required.", 401),
    ScopeDenied => ("SCOPE_DENIED", "Access denied.", 403),
    WorkspaceUnshared => ("WORKSPACE_UNSHARED", "Workspace unavailable.", 403),
    RepositoryExecutionRequired => ("REPOSITORY_EXECUTION_REQUIRED", "Repository execution consent required.", 403),
    ProtectedPath => ("PROTECTED_PATH", "Protected resource.", 403),
    ResourceNotFound => ("RESOURCE_NOT_FOUND", "Resource unavailable.", 404),
    OperationNotFound => ("OPERATION_NOT_FOUND", "Operation unavailable.", 404),
    StaleEpoch => ("STALE_EPOCH", "Session context changed.", 409),
    RevisionConflict => ("REVISION_CONFLICT", "Workspace state changed.", 409),
    FileChanged => ("FILE_CHANGED", "File changed.", 409),
    IdempotencyConflict => ("IDEMPOTENCY_CONFLICT", "Operation parameters conflict.", 409),
    HostBusy => ("HOST_BUSY", "Host busy.", 409),
    ControlRequired => ("CONTROL_REQUIRED", "Terminal control required.", 409),
    ControlRevoked => ("CONTROL_REVOKED", "Terminal control revoked.", 409),
    SessionExited => ("SESSION_EXITED", "Terminal session exited.", 409),
    ResyncRequired => ("RESYNC_REQUIRED", "State synchronization required.", 409),
    DirectoryNotEmpty => ("DIRECTORY_NOT_EMPTY", "Directory is not empty.", 409),
    CredentialsRequired => ("CREDENTIALS_REQUIRED", "Configure credentials on the host.", 403),
    GitIdentityRequired => ("GIT_IDENTITY_REQUIRED", "Configure a Git author on the host.", 403),
    UnsupportedCapability => ("UNSUPPORTED_CAPABILITY", "Capability unavailable.", 400),
    OutcomeUnknown => ("OUTCOME_UNKNOWN", "Operation outcome is unknown.", 409),
    OperationExpired => ("OPERATION_EXPIRED", "Operation receipt expired; inspect resource state.", 410),
    UpdateRequired => ("UPDATE_REQUIRED", "Client update required.", 426),
    ResourceExhausted => ("RESOURCE_EXHAUSTED", "Resource budget exceeded.", 429),
    FreshnessRequired => ("FRESHNESS_REQUIRED", "Authority confirmation required.", 503),
    ServiceUnavailable => ("SERVICE_UNAVAILABLE", "Service unavailable.", 503),
    DeadlineExceeded => ("DEADLINE_EXCEEDED", "Request deadline exceeded.", 504)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmptyErrorDetails {}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionErrorDetails {
    pub expected_revision: DecimalU64,
    pub actual_revision: DecimalU64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ErrorDetails {
    Revision(RevisionErrorDetails),
    Empty(EmptyErrorDetails),
}
impl ErrorDetails {
    pub fn empty() -> Self {
        Self::Empty(EmptyErrorDetails {})
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorWire {
    code: ErrorCode,
    message: String,
    retryable: bool,
    effect: Effect,
    details: ErrorDetails,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation: Option<OperationLookup>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "ErrorWire", into = "ErrorWire")]
pub struct RemoteError(ErrorWire);
impl TryFrom<ErrorWire> for RemoteError {
    type Error = &'static str;
    fn try_from(wire: ErrorWire) -> Result<Self, Self::Error> {
        if wire.message != wire.code.message() {
            return Err("noncanonical safe error message");
        }
        if matches!(wire.code, ErrorCode::RevisionConflict)
            != matches!(wire.details, ErrorDetails::Revision(_))
        {
            return Err("details do not match error code");
        }
        // Ephemeral input/resize have session-bound RAM receipts, not a durable
        // operation ID. Method-specific validation below admits only their
        // explicit unknown outcome without inventing a status lookup.
        if wire.effect != Effect::None
            && wire.operation.is_none()
            && !(wire.code == ErrorCode::OutcomeUnknown && wire.effect == Effect::Unknown)
        {
            return Err("effect requires operation status binding");
        }
        if wire.code == ErrorCode::OutcomeUnknown && wire.effect != Effect::Unknown {
            return Err("unknown outcome requires unknown effect");
        }
        if wire.retryable
            && !matches!(
                wire.code,
                ErrorCode::ResourceExhausted
                    | ErrorCode::HostBusy
                    | ErrorCode::FreshnessRequired
                    | ErrorCode::ServiceUnavailable
                    | ErrorCode::DeadlineExceeded
                    | ErrorCode::ResyncRequired
            )
        {
            return Err("code is not retryable");
        }
        Ok(Self(wire))
    }
}
impl From<RemoteError> for ErrorWire {
    fn from(value: RemoteError) -> Self {
        value.0
    }
}
impl RemoteError {
    pub fn new(
        code: ErrorCode,
        retryable: bool,
        effect: Effect,
        details: ErrorDetails,
        operation: Option<OperationLookup>,
    ) -> Result<Self, &'static str> {
        ErrorWire {
            code,
            message: code.message().to_owned(),
            retryable,
            effect,
            details,
            operation,
        }
        .try_into()
    }
    pub fn code(&self) -> ErrorCode {
        self.0.code
    }
    pub fn effect(&self) -> Effect {
        self.0.effect
    }
    pub fn message(&self) -> &str {
        &self.0.message
    }
    pub fn retryable(&self) -> bool {
        self.0.retryable
    }
    pub fn operation(&self) -> Option<&OperationLookup> {
        self.0.operation.as_ref()
    }
    pub fn http_status(&self) -> u16 {
        self.0.code.http_status()
    }
    /// Request context is required: a standalone wire DTO cannot know its method.
    pub fn validate_for_method(&self, method: Method) -> Result<(), &'static str> {
        if self.effect() == Effect::None {
            return Ok(());
        }
        if crate::is_durable_mutation(method) {
            if self.operation().is_none() {
                return Err("durable effect requires operation status binding");
            }
            return Ok(());
        }
        if matches!(method, Method::TerminalInput | Method::TerminalResize)
            && self.code() == ErrorCode::OutcomeUnknown
            && self.effect() == Effect::Unknown
            && self.operation().is_none()
        {
            return Ok(());
        }
        Err("method cannot claim this effect or operation binding")
    }
}
