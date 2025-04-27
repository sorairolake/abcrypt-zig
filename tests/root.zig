// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const abcrypt = @import("abcrypt");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const testing = std.testing;

test {
    _ = @import("decrypt.zig");
    _ = @import("encrypt.zig");
    _ = @import("params.zig");

    testing.refAllDeclsRecursive(@This());
}

test "header length" {
    try testing.expectEqual(148, abcrypt.header_length);
}

test "tag length" {
    try testing.expectEqual(16, abcrypt.tag_length);
    try testing.expectEqual(XChaCha20Poly1305.tag_length, abcrypt.tag_length);
}
