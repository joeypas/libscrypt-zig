const std = @import("std");
const builtin = @import("builtin");

fn compileScrypt(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, scrypt: *std.Build.Dependency) !*std.Build.Step.Compile {
    const libscrypt = b.addSharedLibrary(.{
        .name = "scrypt",
        .target = target,
        .optimize = optimize,
    });
    libscrypt.linkLibC();
    libscrypt.linkSystemLibrary("m");

    libscrypt.addCSourceFiles(.{ .root = scrypt.path(""), .files = &[_][]const u8{
        "crypto_scrypt-nosse.c",
        "sha256.c",
        "crypto-mcf.c",
        "b64.c",
        "crypto-scrypt-saltgen.c",
        "crypto_scrypt-check.c",
        "crypto_scrypt-hash.c",
        "slowequals.c",
    }, .flags = &[_][]const u8{ "-D_FORTIFY_SOURCE=2", "-Wl,-rpath=.", "-O2", "-Wall", "-g", "-fstack-protector" } });

    return libscrypt;
}

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const dep_scrypt = b.dependency("libscrypt", .{
        .target = target,
        .optimize = optimize,
    });

    const scrypt_zig = b.addModule("scrypt", .{
        .root_source_file = b.path("src/scrypt.zig"),
    });

    const lib = try compileScrypt(b, target, optimize, dep_scrypt);

    scrypt_zig.addIncludePath(dep_scrypt.path(""));
    scrypt_zig.linkLibrary(lib);

    b.default_step.dependOn(&lib.step);

    const example_step = b.step("examples", "Builds examples");

    const example = b.addExecutable(.{
        .name = "basic_example",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    example.root_module.addImport("scrypt", scrypt_zig);

    const run_cmd = b.addRunArtifact(example);

    const run_step = b.step("basic", "basic example");
    run_step.dependOn(&run_cmd.step);
    example_step.dependOn(&example.step);
}
