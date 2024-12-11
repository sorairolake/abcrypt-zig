// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt` package is an implementation of the [abcrypt encrypted data
//! format](https://sorairolake.github.io/abcrypt/book/format.html).
//!
//! This package supports the abcrypt version 1 file format.

const std = @import("std");
const testing = std.testing;

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
