// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const root = @import("../root.zig");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const testing = std.testing;

const Header = @import("../format.zig").Header;

test "header length" {
    try testing.expectEqual(148, root.header_length);
    try testing.expectEqual(Header.length, root.header_length);
}

test "tag length" {
    try testing.expectEqual(16, root.tag_length);
    try testing.expectEqual(XChaCha20Poly1305.tag_length, root.tag_length);
}
