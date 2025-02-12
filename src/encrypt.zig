// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

const std = @import("std");

const format = @import("format.zig");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const argon2 = std.crypto.pwhash.argon2;
const Mode = argon2.Mode;
const Params = argon2.Params;
const debug = std.debug;
const math = std.math;
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const EncryptError = @import("errors.zig").EncryptError;
const DerivedKey = format.DerivedKey;
const Header = format.Header;

/// Encryptor for the abcrypt encrypted data format.
pub const Encryptor = struct {
    header: Header,
    dk: DerivedKey,
    plaintext: []const u8,

    const Self = @This();

    /// Creates a new `Encryptor`.
    ///
    /// This uses the recommended Argon2 parameters according to the
    /// [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id).
    /// This also uses Argon2id as the Argon2 type and version 0x13 as the
    /// Argon2 version.
    pub fn init(
        allocator: Allocator,
        plaintext: []const u8,
        passphrase: []const u8,
    ) EncryptError!Self {
        const owasp_2id = Params{ .t = 2, .m = 19 * 1024, .p = 1 };
        return initWithParams(allocator, plaintext, passphrase, owasp_2id);
    }

    test init {
        const data = "Hello, world!\n";
        const passphrase = "passphrase";

        _ = try Encryptor.init(testing.allocator, data, passphrase);
    }

    /// Creates a new `Encryptor` with the specified `Params`.
    ///
    /// This uses Argon2id as the Argon2 type and version 0x13 as the Argon2
    /// version.
    pub fn initWithParams(
        allocator: Allocator,
        plaintext: []const u8,
        passphrase: []const u8,
        params: Params,
    ) EncryptError!Self {
        return initWithContext(allocator, plaintext, passphrase, Mode.argon2id, params);
    }

    test initWithParams {
        const data = "Hello, world!\n";
        const passphrase = "passphrase";

        const params = Params{ .t = 3, .m = 32, .p = 4 };
        _ = try Encryptor.initWithParams(testing.allocator, data, passphrase, params);
    }

    /// Creates a new `Encryptor` with the specified `Mode` and `Params`.
    ///
    /// This uses version 0x13 as the Argon2 version.
    pub fn initWithContext(
        allocator: Allocator,
        plaintext: []const u8,
        passphrase: []const u8,
        argon2_type: Mode,
        params: Params,
    ) EncryptError!Self {
        var header = try Header.init(argon2_type, params);

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

        header.compute_mac(dk.mac);
        return .{ .header = header, .dk = dk, .plaintext = plaintext };
    }

    test initWithContext {
        const data = "Hello, world!\n";
        const passphrase = "passphrase";

        const mode = Mode.argon2i;
        const params = Params{ .t = 3, .m = 32, .p = 4 };
        _ = try Encryptor.initWithContext(testing.allocator, data, passphrase, mode, params);
    }

    /// Encrypts the plaintext into `buf`.
    pub fn encrypt(self: Self, buf: []u8) void {
        debug.assert(buf.len == self.outLen());

        buf[0..Header.length].* = self.header.asBytes();

        var tag: [XChaCha20Poly1305.tag_length]u8 = undefined;
        const start_tag = self.outLen() - format.tag_length;
        const aad = "";
        XChaCha20Poly1305.encrypt(
            buf[Header.length..start_tag],
            &tag,
            self.plaintext,
            aad,
            self.header.nonce,
            self.dk.encrypt,
        );
        @memcpy(buf[start_tag..], &tag);
    }

    test encrypt {
        const data = "Hello, world!\n";
        const passphrase = "passphrase";

        const params = Params{ .t = 3, .m = 32, .p = 4 };
        const cipher = try Encryptor.initWithParams(testing.allocator, data, passphrase, params);
        var buf: [178]u8 = undefined;
        cipher.encrypt(&buf);
        try testing.expect(!mem.eql(u8, &buf, data));
    }

    /// Returns the number of output bytes of the encrypted data.
    pub fn outLen(self: Self) usize {
        const max_plaintext_len = math.maxInt(usize) - Header.length - format.tag_length;
        debug.assert(self.plaintext.len <= max_plaintext_len);
        return Header.length + self.plaintext.len + format.tag_length;
    }

    test outLen {
        const data = "Hello, world!\n";
        const passphrase = "passphrase";

        const params = Params{ .t = 3, .m = 32, .p = 4 };
        const cipher = try Encryptor.initWithParams(testing.allocator, data, passphrase, params);
        try testing.expectEqual(178, cipher.outLen());
    }
};

test {
    _ = @import("tests/encrypt.zig");
}
