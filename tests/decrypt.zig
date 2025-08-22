// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const abcrypt = @import("abcrypt");

const Endian = std.builtin.Endian;
const mem = std.mem;
const testing = std.testing;

const DecryptError = abcrypt.DecryptError;
const Decryptor = abcrypt.Decryptor;

const passphrase = "passphrase";
const test_data = @embedFile("data/data.txt");
const test_data_enc = @embedFile("data/v1/argon2id/v0x13/data.txt.abcrypt");

test "decrypt" {
    {
        const decryptor = try Decryptor.init(
            testing.allocator,
            @embedFile("data/v1/argon2d/v0x13/data.txt.abcrypt"),
            passphrase,
        );
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualStrings(test_data, &plaintext);
    }
    {
        const decryptor = try Decryptor.init(
            testing.allocator,
            @embedFile("data/v1/argon2i/v0x13/data.txt.abcrypt"),
            passphrase,
        );
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualStrings(test_data, &plaintext);
    }
    {
        const decryptor = try Decryptor.init(testing.allocator, test_data_enc, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualStrings(test_data, &plaintext);
    }
}

test "decrypt from incorrect passphrase" {
    const decryptor = Decryptor.init(testing.allocator, test_data_enc, "password");
    try testing.expectError(DecryptError.InvalidHeaderMac, decryptor);
}

test "decrypt from invalid input length" {
    {
        const data = [_]u8{0x00} ** ((abcrypt.header_length + abcrypt.tag_length) - 1);
        const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(DecryptError.InvalidLength, decryptor);
    }

    {
        const data = [_]u8{0x00} ** (abcrypt.header_length + abcrypt.tag_length);
        const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(DecryptError.InvalidMagicNumber, decryptor);
    }
}

test "decrypt from invalid magic number" {
    var data = test_data_enc.*;
    data[0] = 'b';
    const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
    try testing.expectError(DecryptError.InvalidMagicNumber, decryptor);
}

test "decrypt from unsupported version" {
    const data = @embedFile("data/v0/data.txt.abcrypt");
    const decryptor = Decryptor.init(testing.allocator, data, passphrase);
    try testing.expectError(DecryptError.UnsupportedVersion, decryptor);
}

test "decrypt from unknown version" {
    var data = test_data_enc.*;
    data[7] = 2;
    const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
    try testing.expectError(DecryptError.UnknownVersion, decryptor);
}

test "decrypt from invalid params" {
    var data = test_data_enc.*;

    {
        var memory_cost: [4]u8 = undefined;
        mem.writeInt(u32, &memory_cost, 7, Endian.little);
        data[16..20].* = memory_cost;
        const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(DecryptError.WeakParameters, decryptor);
    }

    {
        var time_cost: [4]u8 = undefined;
        mem.writeInt(u32, &time_cost, 0, Endian.little);
        data[20..24].* = time_cost;
        const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(DecryptError.WeakParameters, decryptor);
    }

    {
        var parallelism: [4]u8 = undefined;
        mem.writeInt(u32, &parallelism, 0, Endian.little);
        data[24..28].* = parallelism;
        const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(DecryptError.WeakParameters, decryptor);
    }
}

test "decrypt from invalid header mac" {
    var data = test_data_enc.*;
    mem.reverse(u8, data[84..148]);
    const decryptor = Decryptor.init(testing.allocator, &data, passphrase);
    try testing.expectError(DecryptError.InvalidHeaderMac, decryptor);
}

test "decrypt from invalid mac" {
    var data = test_data_enc.*;
    mem.reverse(u8, data[(data.len - abcrypt.tag_length)..]);
    const decryptor = try Decryptor.init(testing.allocator, &data, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    const result = decryptor.decrypt(&plaintext);
    try testing.expectError(DecryptError.AuthenticationFailed, result);
}

test "get output length" {
    const decryptor = try Decryptor.init(testing.allocator, test_data_enc, passphrase);
    try testing.expectEqual(test_data.len, decryptor.outLen());
}
