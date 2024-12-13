// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the abcrypt encrypted data format.

const std = @import("std");

const errors = @import("errors.zig");
const format = @import("format.zig");

const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;

/// Decryptor for the abcrypt encrypted data format.
pub const Decryptor = struct {
    header: format.Header,
    dk: format.DerivedKey,
    ciphertext: []const u8,
    tag: [crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length]u8,

    const Self = @This();

    /// Creates a new `Decryptor`.
    pub fn init(
        allocator: mem.Allocator,
        ciphertext: []const u8,
        passphrase: []const u8,
    ) errors.DecryptError!Self {
        var header = try format.Header.parse(ciphertext);
        debug.assert(header.argon2_version == 0x13);

        // The derived key size is 96 bytes. The first 256 bits are for
        // XChaCha20-Poly1305 key, and the last 512 bits are for
        // BLAKE2b-512-MAC key.
        var keys: [format.DerivedKey.length]u8 = undefined;
        try crypto.pwhash.argon2.kdf(
            allocator,
            &keys,
            passphrase,
            &header.salt,
            header.params,
            header.argon2_type,
        );
        const dk = format.DerivedKey.init(keys);

        try header.verify_mac(dk.mac, ciphertext[84..format.Header.length].*);
        const body = ciphertext[format.Header.length..(ciphertext.len - format.tag_length)];
        var tag: [crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length]u8 = undefined;
        @memcpy(&tag, ciphertext[(ciphertext.len - format.tag_length)..]);
        return .{ .header = header, .dk = dk, .ciphertext = body, .tag = tag };
    }

    /// Decrypts the ciphertext into `buf`.
    pub fn decrypt(
        self: Self,
        buf: []u8,
    ) crypto.errors.AuthenticationError!void {
        debug.assert(buf.len == self.outLen());

        const aad = "";
        return crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(
            buf,
            self.ciphertext,
            self.tag,
            aad,
            self.header.nonce,
            self.dk.encrypt,
        );
    }

    /// Returns the number of output bytes of the decrypted data.
    pub fn outLen(self: Self) usize {
        return self.ciphertext.len;
    }
};

test "decrypt" {
    _ = @import("tests/decrypt.zig");
}
