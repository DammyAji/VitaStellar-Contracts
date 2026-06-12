use soroban_sdk::{contracterror, symbol_short, Symbol};

/// Error codes for the Healthcare Payment contract.
///
/// Error Ranges:
/// - 100-199: Access Control
/// - 200-299: Input Validation
/// - 300-399: Lifecycle & State
/// - 400-499: Entity Existence
/// - 500-599: Financial & Resource
/// - 700-799: Cross-Chain
/// - 800-899: Reentrancy Protection
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    // --- Access Control (100-199) ---
    /// Caller is not authorized to perform this action
    Unauthorized = 100,
    /// Caller is not authorized for this specific operation
    UnauthorizedCaller = 101,
    /// Caller is not an authorized pauser for emergency circuit breaker
    NotAuthorizedPauser = 102,

    // --- Input Validation (200-299) ---
    /// Amount must be positive (> 0)
    InvalidAmount = 205,
    /// Invalid cryptographic signature
    InvalidSignature = 207,
    /// Invalid coverage or insurance data
    InvalidCoverage = 280,
    /// Policy ID does not match the claim's policy
    PolicyMismatch = 281,

    // --- Lifecycle & State (300-399) ---
    /// Contract has not been initialized
    NotInitialized = 300,
    /// Contract has already been initialized
    AlreadyInitialized = 301,
    /// Contract is paused
    ContractPaused = 302,
    /// Circuit breaker is open; operations suspended
    CircuitOpen = 303,
    /// Entity is not in the required state for this operation
    InvalidStatus = 304,
    /// Circuit breaker is already in the requested state
    AlreadyInState = 305,
    /// Operation deadline exceeded
    DeadlineExceeded = 306,

    // --- Entity Existence (400-499) ---
    /// Claim not found for the given ID
    ClaimNotFound = 480,
    /// Pre-authorization not found
    PreAuthNotFound = 481,
    /// Payment plan not found
    PaymentPlanNotFound = 482,
    /// Insurance provider not found
    InsuranceProviderNotFound = 483,
    /// Coverage policy not found
    CoveragePolicyNotFound = 484,
    /// Eligibility check not found
    EligibilityCheckNotFound = 485,
    /// Claim submission not found
    ClaimSubmissionNotFound = 486,
    /// Explanation of Benefits not found
    EobNotFound = 487,

    // --- Financial & Resource (500-599) ---
    /// Insufficient funds for the operation
    InsufficientFunds = 500,
    /// Storage is full
    StorageFull = 502,
    /// Fraud detected on this claim
    FraudDetected = 580,
    /// Escrow creation failed
    EscrowFailed = 581,
    /// Transaction format not supported
    UnsupportedTransaction = 582,

    // --- Cross-Chain (700-799) ---
    /// Cross-chain operation timed out
    CrossChainTimeout = 702,

    // --- Reentrancy Protection (800-899) ---
    /// Reentrant call detected; operation blocked
    Reentrancy = 800,
}

pub fn get_suggestion(error: Error) -> Symbol {
    match error {
        Error::Unauthorized => symbol_short!("CHK_AUTH"),
        Error::NotInitialized => symbol_short!("INIT_CTR"),
        Error::AlreadyInitialized => symbol_short!("ALREADY"),
        Error::ContractPaused | Error::DeadlineExceeded | Error::CrossChainTimeout => {
            symbol_short!("RE_TRY_L")
        },
        Error::InsufficientFunds => symbol_short!("ADD_FUND"),
        Error::StorageFull => symbol_short!("CLN_OLD"),
        Error::ClaimNotFound
        | Error::PreAuthNotFound
        | Error::PaymentPlanNotFound
        | Error::InsuranceProviderNotFound => symbol_short!("CHK_ID"),
        _ => symbol_short!("CONTACT"),
    }
}
