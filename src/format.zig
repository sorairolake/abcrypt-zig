// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Specifications of the abcrypt encrypted data format.

const std = @import("std");

const DefaultCsprng = std.Random.DefaultCsprng;
const Endian = std.builtin.Endian;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;
const Mode = std.crypto.pwhash.argon2.Mode;
const Params = std.crypto.pwhash.argon2.Params;
const debug = std.debug;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const GetRandomError = std.posix.GetRandomError;
const testing = std.testing;

const DecryptError = @import("errors.zig").DecryptError;

/// The number of bytes of the MAC (authentication tag) of the ciphertext.
pub const tag_length = XChaCha20Poly1305.tag_length;

/// Version of the abcrypt encrypted data format.
pub const Version = enum {
    /// Version 0.
    v0,

    /// Version 1.
    v1,
};

/// Header of the abcrypt encrypted data format.
pub const Header = struct {
    magic_number: [7]u8 = magic_number,
    version: Version = .v1,
    argon2_type: Mode,
    argon2_version: u32 = 0x13,
    params: Params,
    salt: [32]u8,
    nonce: [XChaCha20Poly1305.nonce_length]u8,
    mac: [Blake2b512.digest_length]u8,

    const Self = @This();

    /// Magic number of the abcrypt encrypted data format.
    ///
    /// This is the ASCII code for "abcrypt".
    const magic_number = "abcrypt".*;

    /// The number of bytes of the header.
    pub const length = 148;

    pub fn init(argon2_type: Mode, params: Params) GetRandomError!Self {
        debug.assert(params.secret == null);
        debug.assert(params.ad == null);

        var seed: [DefaultCsprng.secret_seed_length]u8 = undefined;
        try posix.getrandom(&seed);
        var rng = DefaultCsprng.init(seed);
        var salt: [32]u8 = undefined;
        rng.fill(&salt);
        var nonce: [XChaCha20Poly1305.nonce_length]u8 = undefined;
        rng.fill(&nonce);
        return .{
            .argon2_type = argon2_type,
            .params = params,
            .salt = salt,
            .nonce = nonce,
            .mac = undefined,
        };
    }

    pub fn parse(data: []const u8) DecryptError!Self {
        if (data.len < length + tag_length) {
            return error.InvalidLength;
        }

        if (!mem.startsWith(u8, data, &magic_number)) {
            return error.InvalidMagicNumber;
        }
        const version = meta.intToEnum(Version, data[7]) catch return error.UnknownVersion;
        if (version != Version.v1) {
            return error.UnsupportedVersion;
        }
        const argon2_type = meta.intToEnum(
            Mode,
            mem.readInt(u32, data[8..12], Endian.little),
        ) catch return error.InvalidArgon2Type;
        const argon2_version = mem.readInt(u32, data[12..16], Endian.little);
        switch (argon2_version) {
            0x10, 0x13 => {},
            else => return error.InvalidArgon2Version,
        }
        const memory_cost = mem.readInt(u32, data[16..20], Endian.little);
        const time_cost = mem.readInt(u32, data[20..24], Endian.little);
        const parallelism: u24 = @intCast(mem.readInt(u32, data[24..28], Endian.little));
        const params = Params{ .t = time_cost, .m = memory_cost, .p = parallelism };
        const salt = data[28..60].*;
        const nonce = data[60..84].*;
        return .{
            .argon2_type = argon2_type,
            .params = params,
            .salt = salt,
            .nonce = nonce,
            .mac = undefined,
        };
    }

    pub fn compute_mac(self: *Self, key: [Blake2b512.key_length_max]u8) void {
        const options = Blake2b512.Options{ .key = &key };
        Blake2b512.hash(self.asBytes()[0..84], &self.mac, options);
    }

    pub fn verify_mac(
        self: *Self,
        key: [Blake2b512.key_length_max]u8,
        tag: [Blake2b512.digest_length]u8,
    ) DecryptError!void {
        var mac: [Blake2b512.digest_length]u8 = undefined;
        const options = Blake2b512.Options{ .key = &key };
        Blake2b512.hash(self.asBytes()[0..84], &mac, options);
        if (!mem.eql(u8, &mac, &tag)) {
            return error.InvalidHeaderMac;
        }
        self.mac = mac;
    }

    pub fn asBytes(self: Self) [length]u8 {
        var header: [length]u8 = undefined;
        header[0..7].* = self.magic_number;
        header[7] = @intFromEnum(self.version);
        var argon2_type: [4]u8 = undefined;
        mem.writeInt(u32, &argon2_type, @intFromEnum(self.argon2_type), Endian.little);
        header[8..12].* = argon2_type;
        var argon2_version: [4]u8 = undefined;
        mem.writeInt(u32, &argon2_version, self.argon2_version, Endian.little);
        header[12..16].* = argon2_version;
        var memory_cost: [4]u8 = undefined;
        mem.writeInt(u32, &memory_cost, self.params.m, Endian.little);
        header[16..20].* = memory_cost;
        var time_cost: [4]u8 = undefined;
        mem.writeInt(u32, &time_cost, self.params.t, Endian.little);
        header[20..24].* = time_cost;
        var parallelism: [4]u8 = undefined;
        mem.writeInt(u32, &parallelism, self.params.p, Endian.little);
        header[24..28].* = parallelism;
        header[28..60].* = self.salt;
        header[60..84].* = self.nonce;
        header[84..].* = self.mac;
        return header;
    }
};

/// Derived key.
pub const DerivedKey = struct {
    encrypt: [XChaCha20Poly1305.key_length]u8,
    mac: [Blake2b512.key_length_max]u8,

    const Self = @This();

    pub const length = @sizeOf(Self);

    pub fn init(derived_key: [length]u8) Self {
        const encrypt = derived_key[0..32].*;
        const mac = derived_key[32..].*;
        return .{ .encrypt = encrypt, .mac = mac };
    }
};

test "header length" {
    try testing.expectEqual(148, Header.length);
}

test "tag length" {
    try testing.expectEqual(16, tag_length);
    try testing.expectEqual(XChaCha20Poly1305.tag_length, tag_length);
}

test "Version to integer" {
    try testing.expectEqual(0, @intFromEnum(Version.v0));
    try testing.expectEqual(1, @intFromEnum(Version.v1));
}

test "magic number" {
    try testing.expectEqualStrings("abcrypt", &Header.magic_number);
}

test "derived key length" {
    try testing.expectEqual(96, DerivedKey.length);
}
