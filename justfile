# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

alias all := default

# Run default recipe
default: build

# Build a project
@build:
    zig build --summary all

# Run tests
@test:
    zig build test --summary all

# Run the formatter
@fmt:
    zig fmt .

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
@fmt-readme:
    npx prettier -w README.md

# Increment the version
@bump part:
    bump-my-version bump {{part}}
