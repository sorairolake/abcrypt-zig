// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("abcrypt", .{ .root_source_file = b.path("src/root.zig") });

    const unit_test_step = b.step("unit-test", "Run only the unit tests");
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    unit_test_step.dependOn(&run_unit_tests.step);

    const integration_test_step = b.step("integration-test", "Run only the integration tests");
    const integration_tests = b.addTest(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_tests.root_module.addImport("abcrypt", lib_mod);
    const run_integration_tests = b.addRunArtifact(integration_tests);
    integration_test_step.dependOn(&run_integration_tests.step);

    const test_step = b.step("test", "Run the tests");
    test_step.dependOn(unit_test_step);
    test_step.dependOn(integration_test_step);

    const doc_step = b.step("doc", "Build the package documentation");
    const doc_obj = b.addObject(.{
        .name = "abcrypt",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const install_doc = b.addInstallDirectory(.{
        .source_dir = doc_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "doc/abcrypt",
    });
    doc_step.dependOn(&install_doc.step);
}
