// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt` package is an implementation of the
//! [abcrypt encrypted data format](https://sorairolake.github.io/abcrypt/book/format.html).
//!
//! This package supports version 1 of the abcrypt format.

const errors = @import("errors.zig");
const format = @import("format.zig");

pub const Decryptor = @import("decrypt.zig").Decryptor;
pub const Encryptor = @import("encrypt.zig").Encryptor;
pub const DecryptError = errors.DecryptError;
pub const EncryptError = errors.EncryptError;
pub const header_length = format.Header.length;
pub const tag_length = format.tag_length;
pub const Params = @import("params.zig").Params;

test {
    const testing = @import("std").testing;

    _ = @import("tests/root.zig");

    testing.refAllDeclsRecursive(@This());
}
