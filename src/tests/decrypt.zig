// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const root = @import("../root.zig");

const builtin = std.builtin;
const mem = std.mem;
const testing = std.testing;

const passphrase = "passphrase";
const test_data = @embedFile("data/data.txt");
const test_data_enc = @embedFile("data/v1/data.txt.abcrypt");

test "decrypt" {
    const decryptor = try root.Decryptor.init(testing.allocator, test_data_enc, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    try decryptor.decrypt(&plaintext);
    try testing.expectEqualSlices(u8, test_data, &plaintext);
}

test "decrypt from incorrect passphrase" {
    const decryptor = root.Decryptor.init(testing.allocator, test_data_enc, "password");
    try testing.expectError(root.DecryptError.InvalidHeaderMac, decryptor);
}

test "decrypt from invalid input length" {
    {
        const data = [_]u8{0} ** ((root.header_length + root.tag_length) - 1);
        const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(root.DecryptError.InvalidLength, decryptor);
    }

    {
        const data = [_]u8{0} ** (root.header_length + root.tag_length);
        const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(root.DecryptError.InvalidMagicNumber, decryptor);
    }
}

test "decrypt from invalid magic number" {
    var data = test_data_enc.*;
    data[0] = 'b';
    const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
    try testing.expectError(root.DecryptError.InvalidMagicNumber, decryptor);
}

test "decrypt from unsupported version" {
    const data = @embedFile("data/v0/data.txt.abcrypt");
    const decryptor = root.Decryptor.init(testing.allocator, data, passphrase);
    try testing.expectError(root.DecryptError.UnsupportedVersion, decryptor);
}

test "decrypt from unknown version" {
    var data = test_data_enc.*;
    data[7] = 2;
    const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
    try testing.expectError(root.DecryptError.UnknownVersion, decryptor);
}

test "decrypt from invalid params" {
    var data = test_data_enc.*;

    {
        var memory_cost: [4]u8 = undefined;
        mem.writeInt(u32, &memory_cost, 7, builtin.Endian.little);
        data[16..20].* = memory_cost;
        const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(root.DecryptError.InvalidHeaderMac, decryptor);
    }

    {
        var time_cost: [4]u8 = undefined;
        mem.writeInt(u32, &time_cost, 0, builtin.Endian.little);
        data[20..24].* = time_cost;
        const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(root.DecryptError.WeakParameters, decryptor);
    }

    {
        var parallelism: [4]u8 = undefined;
        mem.writeInt(u32, &parallelism, 0, builtin.Endian.little);
        data[24..28].* = parallelism;
        const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
        try testing.expectError(root.DecryptError.WeakParameters, decryptor);
    }
}

test "decrypt from invalid header mac" {
    var data = test_data_enc.*;
    mem.reverse(u8, data[84..148]);
    const decryptor = root.Decryptor.init(testing.allocator, &data, passphrase);
    try testing.expectError(root.DecryptError.InvalidHeaderMac, decryptor);
}

test "decrypt from invalid mac" {
    var data = test_data_enc.*;
    mem.reverse(u8, data[(data.len - root.tag_length)..]);
    const decryptor = try root.Decryptor.init(testing.allocator, &data, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    const result = decryptor.decrypt(&plaintext);
    try testing.expectError(root.DecryptError.AuthenticationFailed, result);
}

test "get output length" {
    const decryptor = try root.Decryptor.init(testing.allocator, test_data_enc, passphrase);
    try testing.expectEqual(test_data.len, decryptor.outLen());
}
