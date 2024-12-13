// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const format = @import("../format.zig");
const root = @import("../root.zig");

const crypto = std.crypto;
const testing = std.testing;

test "header length" {
    try testing.expectEqual(148, root.header_length);
    try testing.expectEqual(format.Header.length, root.header_length);
}

test "tag length" {
    try testing.expectEqual(16, root.tag_length);
    try testing.expectEqual(
        crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length,
        root.tag_length,
    );
}
