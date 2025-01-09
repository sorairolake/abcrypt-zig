// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for this package.

const std = @import("std");

const crypto = std.crypto;
const posix = std.posix;

/// An error occurs during decryption operations.
pub const DecryptError = error{
    /// The encrypted data was shorter than 164 bytes.
    InvalidLength,

    /// The magic number (file signature) was invalid.
    InvalidMagicNumber,

    /// The version was the unsupported abcrypt version number.
    UnsupportedVersion,

    /// The version was the unrecognized abcrypt version number.
    UnknownVersion,

    /// The Argon2 type were invalid.
    InvalidArgon2Type,

    /// The Argon2 version were invalid.
    InvalidArgon2Version,

    /// The MAC (authentication tag) of the header was invalid.
    InvalidHeaderMac,
} || crypto.errors.AuthenticationError || crypto.pwhash.KdfError;

/// An error occurs during encryption operations.
pub const EncryptError = crypto.pwhash.KdfError || posix.GetRandomError;
