// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const abcrypt = @import("abcrypt");

const Endian = std.builtin.Endian;
const argon2 = std.crypto.pwhash.argon2;
const Mode = argon2.Mode;
const mem = std.mem;
const meta = std.meta;
const testing = std.testing;

const Decryptor = abcrypt.Decryptor;
const EncryptError = abcrypt.EncryptError;
const Encryptor = abcrypt.Encryptor;

const passphrase = "passphrase";
const test_data = @embedFile("data/data.txt");

test "encrypt" {
    const encryptor = try Encryptor.init(testing.allocator, test_data, passphrase);
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expect(!mem.eql(u8, &ciphertext, test_data));

    const argon2_type = try meta.intToEnum(
        Mode,
        mem.readInt(u32, ciphertext[8..12], Endian.little),
    );
    try testing.expectEqual(Mode.argon2id, argon2_type);
    const argon2_version = mem.readInt(u32, ciphertext[12..16], Endian.little);
    try testing.expectEqual(0x13, argon2_version);

    const parameters = try abcrypt.Params.init(&ciphertext);
    try testing.expectEqual(19456, parameters.memory_cost);
    try testing.expectEqual(2, parameters.time_cost);
    try testing.expectEqual(1, parameters.parallelism);

    const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    try decryptor.decrypt(&plaintext);
    try testing.expectEqual(test_data.*, plaintext);
}

test "encrypt with params" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expect(!mem.eql(u8, &ciphertext, test_data));

    const argon2_type = try meta.intToEnum(
        Mode,
        mem.readInt(u32, ciphertext[8..12], Endian.little),
    );
    try testing.expectEqual(Mode.argon2id, argon2_type);
    const argon2_version = mem.readInt(u32, ciphertext[12..16], Endian.little);
    try testing.expectEqual(0x13, argon2_version);

    const parameters = try abcrypt.Params.init(&ciphertext);
    try testing.expectEqual(32, parameters.memory_cost);
    try testing.expectEqual(3, parameters.time_cost);
    try testing.expectEqual(4, parameters.parallelism);

    const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
    var plaintext: [test_data.len]u8 = undefined;
    try decryptor.decrypt(&plaintext);
    try testing.expectEqual(test_data.*, plaintext);
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
        var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const argon2_type = try meta.intToEnum(
            Mode,
            mem.readInt(u32, ciphertext[8..12], Endian.little),
        );
        try testing.expectEqual(Mode.argon2d, argon2_type);
        const argon2_version = mem.readInt(u32, ciphertext[12..16], Endian.little);
        try testing.expectEqual(0x13, argon2_version);

        const parameters = try abcrypt.Params.init(&ciphertext);
        try testing.expectEqual(19456, parameters.memory_cost);
        try testing.expectEqual(2, parameters.time_cost);
        try testing.expectEqual(1, parameters.parallelism);

        const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqual(test_data.*, plaintext);
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
        var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const argon2_type = try meta.intToEnum(
            Mode,
            mem.readInt(u32, ciphertext[8..12], Endian.little),
        );
        try testing.expectEqual(Mode.argon2i, argon2_type);
        const argon2_version = mem.readInt(u32, ciphertext[12..16], Endian.little);
        try testing.expectEqual(0x13, argon2_version);

        const parameters = try abcrypt.Params.init(&ciphertext);
        try testing.expectEqual(9216, parameters.memory_cost);
        try testing.expectEqual(4, parameters.time_cost);
        try testing.expectEqual(1, parameters.parallelism);

        const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqual(test_data.*, plaintext);
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
        var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expect(!mem.eql(u8, &ciphertext, test_data));

        const argon2_type = try meta.intToEnum(
            Mode,
            mem.readInt(u32, ciphertext[8..12], Endian.little),
        );
        try testing.expectEqual(Mode.argon2id, argon2_type);
        const argon2_version = mem.readInt(u32, ciphertext[12..16], Endian.little);
        try testing.expectEqual(0x13, argon2_version);

        const parameters = try abcrypt.Params.init(&ciphertext);
        try testing.expectEqual(32, parameters.memory_cost);
        try testing.expectEqual(3, parameters.time_cost);
        try testing.expectEqual(4, parameters.parallelism);

        const decryptor = try Decryptor.init(testing.allocator, &ciphertext, passphrase);
        var plaintext: [test_data.len]u8 = undefined;
        try decryptor.decrypt(&plaintext);
        try testing.expectEqual(test_data.*, plaintext);
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
    try testing.expectEqual(abcrypt.header_length + abcrypt.tag_length, encryptor.outLen());
    var ciphertext: [abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
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
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
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
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
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
        var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(0, mem.readInt(u32, ciphertext[8..12], Endian.little));

        const argon2_type = try meta.intToEnum(
            Mode,
            mem.readInt(u32, ciphertext[8..12], Endian.little),
        );
        try testing.expectEqual(Mode.argon2d, argon2_type);
    }
    {
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2i,
            params,
        );
        var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(1, mem.readInt(u32, ciphertext[8..12], Endian.little));

        const argon2_type = try meta.intToEnum(
            Mode,
            mem.readInt(u32, ciphertext[8..12], Endian.little),
        );
        try testing.expectEqual(Mode.argon2i, argon2_type);
    }
    {
        const encryptor = try Encryptor.initWithContext(
            testing.allocator,
            test_data,
            passphrase,
            Mode.argon2id,
            params,
        );
        var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
        encryptor.encrypt(&ciphertext);
        try testing.expectEqual(2, mem.readInt(u32, ciphertext[8..12], Endian.little));

        const argon2_type = try meta.intToEnum(
            Mode,
            mem.readInt(u32, ciphertext[8..12], Endian.little),
        );
        try testing.expectEqual(Mode.argon2id, argon2_type);
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
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(0x13, mem.readInt(u32, ciphertext[12..16], Endian.little));

    const argon2_version = mem.readInt(u32, ciphertext[12..16], Endian.little);
    try testing.expectEqual(0x13, argon2_version);
}

test "extract memory cost" {
    const params = argon2.Params{ .t = 3, .m = 32, .p = 4 };
    const encryptor = try Encryptor.initWithParams(
        testing.allocator,
        test_data,
        passphrase,
        params,
    );
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(32, mem.readInt(u32, ciphertext[16..20], Endian.little));

    const parameters = try abcrypt.Params.init(&ciphertext);
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
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(3, mem.readInt(u32, ciphertext[20..24], Endian.little));

    const parameters = try abcrypt.Params.init(&ciphertext);
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
    var ciphertext: [test_data.len + abcrypt.header_length + abcrypt.tag_length]u8 = undefined;
    encryptor.encrypt(&ciphertext);
    try testing.expectEqual(4, mem.readInt(u32, ciphertext[24..28], Endian.little));

    const parameters = try abcrypt.Params.init(&ciphertext);
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
        test_data.len + abcrypt.header_length + abcrypt.tag_length,
        encryptor.outLen(),
    );
}
