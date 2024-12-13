// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt` package is an implementation of the [abcrypt encrypted data
//! format](https://sorairolake.github.io/abcrypt/book/format.html).
//!
//! This package supports the abcrypt version 1 file format.

const decrypt = @import("decrypt.zig");
const encrypt = @import("encrypt.zig");
const errors = @import("errors.zig");
const format = @import("format.zig");
const params = @import("params.zig");

pub const Decryptor = decrypt.Decryptor;
pub const Encryptor = encrypt.Encryptor;
pub const DecryptError = errors.DecryptError;
pub const EncryptError = errors.EncryptError;
pub const header_length = format.Header.length;
pub const tag_length = format.tag_length;
pub const Params = params.Params;

test {
    const std = @import("std");

    const testing = std.testing;

    testing.refAllDeclsRecursive(@This());
    _ = @import("tests/root.zig");
}
