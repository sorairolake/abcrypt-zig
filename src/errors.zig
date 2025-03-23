// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for this package.

const std = @import("std");

const AuthenticationError = std.crypto.errors.AuthenticationError;
const KdfError = std.crypto.pwhash.KdfError;
const GetRandomError = std.posix.GetRandomError;

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
} || AuthenticationError || KdfError;

/// An error occurs during encryption operations.
pub const EncryptError = KdfError || GetRandomError;
