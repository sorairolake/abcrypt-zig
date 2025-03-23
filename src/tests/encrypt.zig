// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const root = @import("../root.zig");

const Endian = std.builtin.Endian;
const argon2 = std.crypto.pwhash.argon2;
const Mode = argon2.Mode;
const mem = std.mem;
const testing = std.testing;

const Header = @import("../format.zig").Header;
const Decryptor = root.Decryptor;
const EncryptError = root.EncryptError;
const Encryptor = root.Encryptor;

const passphrase = "passphrase";
const test_data = @embedFile("data/data.txt");

test "encrypt" {
    const encryptor = try Encryptor.init(testing.allocator, test_data, passphrase);
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expect(!mem.eql(u8, &ciphertext, test_data));

    const header = try Header.parse(&ciphertext);
    try testing.expectEqual(Mode.argon2id, header.argon2_type);
    try testing.expectEqual(0x13, header.argon2_version);

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(19456, parameters.memory_cost);
    try testing.expectEqual(2, parameters.time_cost);
    try testing.expectEqual(1, parameters.parallelism);

    const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    try decryptor.decrypt(&plaintext);
    try testing.expectEqualSlices(u8, test_data, &plaintext);
}

test "encrypt with params" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expect(!mem.eql(u8, &ciphertext, test_data));

    const header = try Header.parse(&ciphertext);
    try testing.expectEqual(Mode.argon2id, header.argon2_type);
    try testing.expectEqual(0x13, header.argon2_version);

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(32, parameters.memory_cost);
    try testing.expectEqual(3, parameters.time_cost);
    try testing.expectEqual(4, parameters.parallelism);

    const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    try decryptor.decrypt(&plaintext);
    try testing.expectEqualSlices(u8, test_data, &plaintext);
}

test "encrypt with context" {
    {
        const params = argon2.Params{ .t = 2, .m = 19456, .p = 1 };
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2d,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const header = try Header.parse(&ciphertext);
        try testing.expectEqual(Mode.argon2d, header.argon2_type);
        try testing.expectEqual(0x13, header.argon2_version);

        const parameters = try root.Params.init(&ciphertext);
        try testing.expectEqual(19456, parameters.memory_cost);
        try testing.expectEqual(2, parameters.time_cost);
        try testing.expectEqual(1, parameters.parallelism);

        const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualSlices(u8, test_data, &plaintext);
    }
    {
        const params = argon2.Params{ .t = 4, .m = 9216, .p = 1 };
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2i,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const header = try Header.parse(&ciphertext);
        try testing.expectEqual(Mode.argon2i, header.argon2_type);
        try testing.expectEqual(0x13, header.argon2_version);

        const parameters = try root.Params.init(&ciphertext);
        try testing.expectEqual(9216, parameters.memory_cost);
        try testing.expectEqual(4, parameters.time_cost);
        try testing.expectEqual(1, parameters.parallelism);

        const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualSlices(u8, test_data, &plaintext);
    }
    {
        const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2id,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const header = try Header.parse(&ciphertext);
        try testing.expectEqual(Mode.argon2id, header.argon2_type);
        try testing.expectEqual(0x13, header.argon2_version);

        const parameters = try root.Params.init(&ciphertext);
        try testing.expectEqual(32, parameters.memory_cost);
        try testing.expectEqual(3, parameters.time_cost);
        try testing.expectEqual(4, parameters.parallelism);

        const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqualSlices(u8, test_data, &plaintext);
    }
}

test "encrypt with invalid Argon2 parameters" {
    const params = argon2.Params{ .t = 0, .m = 0, .p = 0 };
    const encryptor = Encryptor.initWithParams(testing.allocator, test_data, passphrase, params);
    try testing.expectError(EncryptError.WeakParameters, encryptor);
}

test "encrypt to minimum output length" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(testing.allocator, "", passphrase, params);
    try testing.expectEqual(root.header_length + root.tag_length, encryptor.outLen());
    var ciphertext: [root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
}

test "extract magic number" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
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
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
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
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };

    {
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2d,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(0, mem.readInt(u32, ciphertext[8..12], Endian.little));

        const header = try Header.parse(&ciphertext);
        try testing.expectEqual(Mode.argon2d, header.argon2_type);
    }
    {
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2i,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(1, mem.readInt(u32, ciphertext[8..12], Endian.little));

        const header = try Header.parse(&ciphertext);
        try testing.expectEqual(Mode.argon2i, header.argon2_type);
    }
    {
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2id,
            params,
        );
        var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(2, mem.readInt(u32, ciphertext[8..12], Endian.little));

        const header = try Header.parse(&ciphertext);
        try testing.expectEqual(Mode.argon2id, header.argon2_type);
    }
}

test "extract Argon2 version" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithContext(
        testing.allocator,
        test_data,
        passphrase,
        Mode.argon2id,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(0x13, mem.readInt(u32, ciphertext[12..16], Endian.little));

    const header = try Header.parse(&ciphertext);
    try testing.expectEqual(0x13, header.argon2_version);
}

test "extract memory cost" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(32, mem.readInt(u32, ciphertext[16..20], Endian.little));

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(32, parameters.memory_cost);
}

test "extract time cost" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(3, mem.readInt(u32, ciphertext[20..24], Endian.little));

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(3, parameters.time_cost);
}

test "extract parallelism" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + root.header_length + root.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(4, mem.readInt(u32, ciphertext[24..28], Endian.little));

    const parameters = try root.Params.init(&ciphertext);
    try testing.expectEqual(4, parameters.parallelism);
}

test "get output length" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
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
