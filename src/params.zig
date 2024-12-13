// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

const errors = @import("errors.zig");
const format = @import("format.zig");

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
};

test "params" {
    _ = @import("tests/params.zig");
}
