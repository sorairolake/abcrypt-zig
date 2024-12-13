// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const root = @import("../root.zig");

const testing = std.testing;

const test_data_enc = @embedFile("data/v1/data.txt.abcrypt");

test "get Argon2 parameters" {
    const params = try root.Params.init(test_data_enc);
    try testing.expectEqual(32, params.memory_cost);
    try testing.expectEqual(3, params.time_cost);
    try testing.expectEqual(4, params.parallelism);
}
