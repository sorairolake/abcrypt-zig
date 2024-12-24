// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const format = @import("../format.zig");
const root = @import("../root.zig");

const builtin = std.builtin;
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;

const passphrase = "passphrase";
const test_data = @embedFile("data/data.txt");

test "encrypt" {
    const encryptor = try root.Encryptor.init(testing.allocator, test_data, passphrase);
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expect(!mem.eql(u8, &ciphertext, test_data));

    const header = try format.Header.parse(&ciphertext);
    try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2id, header.argon2_type);
    try testing.expectEqual(0x13, header.argon2_version);

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(19456, parameters.memory_cost);
    try testing.expectEqual(2, parameters.time_cost);
    try testing.expectEqual(1, parameters.parallelism);

    const decryptor = try root.Decryptor.init(testing.allocator, &ciphertext, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    try decryptor.decrypt(&plaintext);
    try testing.expectEqualSlices(u8, test_data, &plaintext);
}

test "encrypt with params" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expect(!mem.eql(u8, &ciphertext, test_data));

    const header = try format.Header.parse(&ciphertext);
    try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2id, header.argon2_type);
    try testing.expectEqual(0x13, header.argon2_version);

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(32, parameters.memory_cost);
    try testing.expectEqual(3, parameters.time_cost);
    try testing.expectEqual(4, parameters.parallelism);

    const decryptor = try root.Decryptor.init(testing.allocator, &ciphertext, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    try decryptor.decrypt(&plaintext);
    try testing.expectEqualSlices(u8, test_data, &plaintext);
}

test "encrypt with context" {
    {
        const params = crypto.pwhash.argon2.Params{ .t = 2, .m = 19456, .p = 1 };
        const encryptor = try root.Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            crypto.pwhash.argon2.Mode.argon2d,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const header = try format.Header.parse(&ciphertext);
        try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2d, header.argon2_type);
        try testing.expectEqual(0x13, header.argon2_version);

        const parameters = try root.Params.init(&ciphertext);
        try testing.expectEqual(19456, parameters.memory_cost);
        try testing.expectEqual(2, parameters.time_cost);
        try testing.expectEqual(1, parameters.parallelism);

        const decryptor = try root.Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualSlices(u8, test_data, &plaintext);
    }
    {
        const params = crypto.pwhash.argon2.Params{ .t = 4, .m = 9216, .p = 1 };
        const encryptor = try root.Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            crypto.pwhash.argon2.Mode.argon2i,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const header = try format.Header.parse(&ciphertext);
        try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2i, header.argon2_type);
        try testing.expectEqual(0x13, header.argon2_version);

        const parameters = try root.Params.init(&ciphertext);
        try testing.expectEqual(9216, parameters.memory_cost);
        try testing.expectEqual(4, parameters.time_cost);
        try testing.expectEqual(1, parameters.parallelism);

        const decryptor = try root.Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualSlices(u8, test_data, &plaintext);
    }
    {
        const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
        const encryptor = try root.Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            crypto.pwhash.argon2.Mode.argon2id,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const header = try format.Header.parse(&ciphertext);
        try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2id, header.argon2_type);
        try testing.expectEqual(0x13, header.argon2_version);

        const parameters = try root.Params.init(&ciphertext);
        try testing.expectEqual(32, parameters.memory_cost);
        try testing.expectEqual(3, parameters.time_cost);
        try testing.expectEqual(4, parameters.parallelism);

        const decryptor = try root.Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualSlices(u8, test_data, &plaintext);
    }
}

test "encrypt with invalid Argon2 parameters" {
    const params = crypto.pwhash.argon2.Params{ .t = 0, .m = 0, .p = 0 };
    const encryptor = root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    try testing.expectError(root.DecryptError.WeakParameters, encryptor);
}

test "encrypt to minimum output length" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(testing.allocator, "", passphrase, params);
    try testing.expectEqual(root.header_length + root.tag_length, encryptor.outLen());
    var ciphertext: [root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
}

test "extract magic number" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqualStrings("abcrypt", ciphertext[0..7]);
}

test "extract version" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(1, ciphertext[7]);
}

test "extract Argon2 type" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };

    {
        const encryptor = try root.Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            crypto.pwhash.argon2.Mode.argon2d,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(0, mem.readInt(u32, ciphertext[8..12], builtin.Endian.little));

        const header = try format.Header.parse(&ciphertext);
        try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2d, header.argon2_type);
    }
    {
        const encryptor = try root.Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            crypto.pwhash.argon2.Mode.argon2i,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(1, mem.readInt(u32, ciphertext[8..12], builtin.Endian.little));

        const header = try format.Header.parse(&ciphertext);
        try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2i, header.argon2_type);
    }
    {
        const encryptor = try root.Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            crypto.pwhash.argon2.Mode.argon2id,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(2, mem.readInt(u32, ciphertext[8..12], builtin.Endian.little));

        const header = try format.Header.parse(&ciphertext);
        try testing.expectEqual(crypto.pwhash.argon2.Mode.argon2id, header.argon2_type);
    }
}

test "extract Argon2 version" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithContext(
        testing.allocator,
        test_data,
        passphrase,
        crypto.pwhash.argon2.Mode.argon2id,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(0x13, mem.readInt(u32, ciphertext[12..16], builtin.Endian.little));

    const header = try format.Header.parse(&ciphertext);
    try testing.expectEqual(0x13, header.argon2_version);
}

test "extract memory cost" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(32, mem.readInt(u32, ciphertext[16..20], builtin.Endian.little));

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(32, parameters.memory_cost);
}

test "extract time cost" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(3, mem.readInt(u32, ciphertext[20..24], builtin.Endian.little));

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(3, parameters.time_cost);
}

test "extract parallelism" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(4, mem.readInt(u32, ciphertext[24..28], builtin.Endian.little));

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(4, parameters.parallelism);
}

test "get output length" {
    const params = crypto.pwhash.argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try root.Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    try testing.expectEqual(
        test_data.len + root.header_length + root.tag_length,
        encryptor.outLen(),
    );
}
