// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

const std = @import("std");

const errors = @import("errors.zig");
const format = @import("format.zig");

const testing = std.testing;

/// The Argon2 parameters used for the encrypted data.
pub const Params = struct {
    /// Memory size in KiB.
    memory_cost: u32,

    /// The number of iterations.
    time_cost: u32,

    /// The degree of parallelism.
    parallelism: u24,

    const Self = @This();

    /// Creates a new instance of the Argon2 parameters from `ciphertext`.
    pub fn init(ciphertext: []const u8) errors.DecryptError!Self {
        const header = try format.Header.parse(ciphertext);
        return .{
            .memory_cost = header.params.m,
            .time_cost = header.params.t,
            .parallelism = header.params.p,
        };
    }

    test init {
        const ciphertext = @embedFile("tests/data/v1/data.txt.abcrypt");

        const params = try Params.init(ciphertext);
        try testing.expectEqual(32, params.memory_cost);
        try testing.expectEqual(3, params.time_cost);
        try testing.expectEqual(4, params.parallelism);
    }
};

test "params" {
    _ = @import("tests/params.zig");
}
