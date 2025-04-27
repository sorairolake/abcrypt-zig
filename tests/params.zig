// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const testing = @import("std").testing;

const Params = @import("abcrypt").Params;

const test_data_enc = @embedFile("data/v1/argon2id/v0x13/data.txt.abcrypt");

test "get Argon2 parameters" {
    {
        const params = try Params.init(@embedFile("data/v1/argon2d/v0x10/data.txt.abcrypt"));
        try testing.expectEqual(47104, params.memory_cost);
        try testing.expectEqual(1, params.time_cost);
        try testing.expectEqual(1, params.parallelism);
    }
    {
        const params = try Params.init(@embedFile("data/v1/argon2d/v0x13/data.txt.abcrypt"));
        try testing.expectEqual(19456, params.memory_cost);
        try testing.expectEqual(2, params.time_cost);
        try testing.expectEqual(1, params.parallelism);
    }
    {
        const params = try Params.init(@embedFile("data/v1/argon2i/v0x10/data.txt.abcrypt"));
        try testing.expectEqual(12288, params.memory_cost);
        try testing.expectEqual(3, params.time_cost);
        try testing.expectEqual(1, params.parallelism);
    }
    {
        const params = try Params.init(@embedFile("data/v1/argon2i/v0x13/data.txt.abcrypt"));
        try testing.expectEqual(9216, params.memory_cost);
        try testing.expectEqual(4, params.time_cost);
        try testing.expectEqual(1, params.parallelism);
    }
    {
        const params = try Params.init(@embedFile("data/v1/argon2id/v0x10/data.txt.abcrypt"));
        try testing.expectEqual(7168, params.memory_cost);
        try testing.expectEqual(5, params.time_cost);
        try testing.expectEqual(1, params.parallelism);
    }
    {
        const params = try Params.init(test_data_enc);
        try testing.expectEqual(32, params.memory_cost);
        try testing.expectEqual(3, params.time_cost);
        try testing.expectEqual(4, params.parallelism);
    }
}
