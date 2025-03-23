// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the abcrypt encrypted data format.

const std = @import("std");

const format = @import("format.zig");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const AuthenticationError = std.crypto.errors.AuthenticationError;
const argon2 = std.crypto.pwhash.argon2;
const debug = std.debug;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const DecryptError = @import("errors.zig").DecryptError;
const DerivedKey = format.DerivedKey;
const Header = format.Header;

/// Decryptor for the abcrypt encrypted data format.
pub const Decryptor = struct {
    header: Header,
    dk: DerivedKey,
    ciphertext: []const u8,
    tag: [XChaCha20Poly1305.tag_length]u8,

    const Self = @This();

    /// Creates a new `Decryptor`.
    pub fn init(
        allocator: Allocator,
        ciphertext: []const u8,
        passphrase: []const u8,
    ) DecryptError!Self {
        var header = try Header.parse(ciphertext);
        debug.assert(header.argon2_version == 0x13);

        // The derived key size is 96 bytes. The first 256 bits are for
        // XChaCha20-Poly1305 key, and the last 512 bits are for
        // BLAKE2b-512-MAC key.
        var keys: [DerivedKey.length]u8 = undefined;
        try argon2.kdf(
            allocator,
            &keys,
            passphrase,
            &header.salt,
            header.params,
            header.argon2_type,
        );
        const dk = DerivedKey.init(keys);

        try header.verify_mac(dk.mac, ciphertext[84..Header.length].*);
        const body = ciphertext[Header.length..(ciphertext.len - format.tag_length)];
        var tag: [XChaCha20Poly1305.tag_length]u8 = undefined;
        @memcpy(&tag, ciphertext[(ciphertext.len - format.tag_length)..]);
        return .{ .header = header, .dk = dk, .ciphertext = body, .tag = tag };
    }

    test init {
        const ciphertext = @embedFile("tests/data/v1/argon2id/v0x13/data.txt.abcrypt");
        const passphrase = "passphrase";

        _ = try Decryptor.init(testing.allocator, ciphertext, passphrase);
    }

    /// Decrypts the ciphertext into `buf`.
    pub fn decrypt(self: Self, buf: []u8) AuthenticationError!void {
        debug.assert(buf.len == self.outLen());

        const aad = "";
        return XChaCha20Poly1305.decrypt(
            buf,
            self.ciphertext,
            self.tag,
            aad,
            self.header.nonce,
            self.dk.encrypt,
        );
    }

    test decrypt {
        const data = "Hello, world!\n";
        const ciphertext = @embedFile("tests/data/v1/argon2id/v0x13/data.txt.abcrypt");
        const passphrase = "passphrase";

        const cipher = try Decryptor.init(testing.allocator, ciphertext, passphrase);
        var buf: [14]u8 = undefined;
        try cipher.decrypt(&buf);
        try testing.expectEqualStrings(data, &buf);
    }

    /// Returns the number of output bytes of the decrypted data.
    pub fn outLen(self: Self) usize {
        return self.ciphertext.len;
    }

    test outLen {
        const ciphertext = @embedFile("tests/data/v1/argon2id/v0x13/data.txt.abcrypt");
        const passphrase = "passphrase";

        const cipher = try Decryptor.init(testing.allocator, ciphertext, passphrase);
        try testing.expectEqual(14, cipher.outLen());
    }
};

test {
    _ = @import("tests/decrypt.zig");
}
