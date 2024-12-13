// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

const std = @import("std");

const errors = @import("errors.zig");
const format = @import("format.zig");

const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;

/// Encryptor for the abcrypt encrypted data format.
pub const Encryptor = struct {
    header: format.Header,
    dk: format.DerivedKey,
    plaintext: []const u8,

    const Self = @This();

    /// Creates a new `Encryptor`.
    ///
    /// This uses the recommended Argon2 parameters according to the [OWASP
    /// Password Storage Cheat Sheet]. This also uses Argon2id as the Argon2
    /// type and version 0x13 as the Argon2 version.
    ///
    /// [OWASP Password Storage Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
    pub fn init(
        allocator: mem.Allocator,
        plaintext: []const u8,
        passphrase: []const u8,
    ) errors.EncryptError!Self {
        const owasp_2id = crypto.pwhash.argon2.Params{
            .t = 2,
            .m = 19 * 1024,
            .p = 1,
        };
        return initWithParams(allocator, plaintext, passphrase, owasp_2id);
    }

    /// Creates a new `Encryptor` with the specified
    /// `crypto.pwhash.argon2.Params`.
    ///
    /// This uses Argon2id as the Argon2 type and version 0x13 as the Argon2
    /// version.
    pub fn initWithParams(
        allocator: mem.Allocator,
        plaintext: []const u8,
        passphrase: []const u8,
        params: crypto.pwhash.argon2.Params,
    ) errors.EncryptError!Self {
        return initWithContext(
            allocator,
            plaintext,
            passphrase,
            crypto.pwhash.argon2.Mode.argon2id,
            params,
        );
    }

    /// Creates a new `Encryptor` with the specified
    /// `crypto.pwhash.argon2.Mode` and `crypto.pwhash.argon2.Params`.
    ///
    /// This uses version 0x13 as the Argon2 version.
    pub fn initWithContext(
        allocator: mem.Allocator,
        plaintext: []const u8,
        passphrase: []const u8,
        argon2_type: crypto.pwhash.argon2.Mode,
        params: crypto.pwhash.argon2.Params,
    ) errors.EncryptError!Self {
        var header = try format.Header.init(argon2_type, params);

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

        header.compute_mac(dk.mac);
        return .{ .header = header, .dk = dk, .plaintext = plaintext };
    }

    /// Encrypts the plaintext into `buf`.
    pub fn encrypt(self: Self, buf: []u8) void {
        debug.assert(buf.len == self.outLen());

        buf[0..format.Header.length].* = self.header.asBytes();

        var tag: [crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length]u8 = undefined;
        const aad = "";
        crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(
            buf[format.Header.length..(self.outLen() - format.tag_length)],
            &tag,
            self.plaintext,
            aad,
            self.header.nonce,
            self.dk.encrypt,
        );
        @memcpy(buf[(self.outLen() - format.tag_length)..], &tag);
    }

    /// Returns the number of output bytes of the encrypted data.
    pub fn outLen(self: Self) usize {
        debug.assert(
            self.plaintext.len <= (math.maxInt(usize) - format.Header.length - format.tag_length),
        );
        return format.Header.length + self.plaintext.len + format.tag_length;
    }
};

test "encrypt" {
    _ = @import("tests/encrypt.zig");
}
