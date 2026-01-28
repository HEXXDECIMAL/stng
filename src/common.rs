//! Common types and utilities for language-aware string extraction.
//!
//! This module re-exports all public items from the types, extraction, and validation modules
//! for backward compatibility.

// Re-export all types
pub use crate::types::{
    BinaryInfo, ExtractedString, OverlayInfo, Severity, StringKind, StringMethod, StringStruct,
};

// Re-export extraction functions
pub use crate::extraction::{extract_from_structures, find_string_structures};

// Re-export validation functions
pub use crate::validation::is_garbage;
