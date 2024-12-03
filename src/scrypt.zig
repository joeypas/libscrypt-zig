const assert = @import("std").debug.assert;
const math = @import("std").math;
const print = @import("std").debug.print;
/// Backend
/// *ONLY USE IF YOU KNOW WHAT YOU'RE DOING*
pub const c = @cImport({
    @cInclude("libscrypt.h");
});

// Error Type
pub const ScryptError = error{
    HashFailure,
    CheckFailure,
    GenFailure,
    ScryptFailure,
};

// Constants
pub const MCF_LEN = @as(usize, c.SCRYPT_MCF_LEN);
pub const HASH_LEN = @as(usize, c.SCRYPT_HASH_LEN);
pub const SALT_LEN = @as(usize, c.SCRYPT_SALT_LEN);
pub const N = @as(comptime_int, c.SCRYPT_N);
pub const R = @as(comptime_int, c.SCRYPT_r);
pub const P = @as(comptime_int, c.SCRYPT_p);

// Function Wrappers

/// Creates a hash of a passphrase using a randomly generated salt
/// Uses sane constants for `n`, `r`, and `p`
/// asserts that `dest.len >= MCF_LEN`
pub fn hashSimple(dest: []u8, passphrase: []const u8) ScryptError!void {
    assert(dest.len >= MCF_LEN);
    const ok = c.libscrypt_hash(dest.ptr, passphrase.ptr, c.SCRYPT_N, c.SCRYPT_r, c.SCRYPT_p);

    if (ok == 0) return ScryptError.HashFailure;
}

/// Creates a hash of a passphrase using a randomly generated salt
/// asserts that `dest.len >= MCF_LEN`
pub fn hash(dest: []u8, passphrase: []const u8, n: u32, r: u8, p: u8) ScryptError!void {
    assert(dest.len >= MCF_LEN);
    const ok = c.libscrypt_hash(dest.ptr, passphrase.ptr, n, r, p);

    if (ok == 0) return ScryptError.HashFailure;
}

/// Checks a given MCF against a password
/// asserts that `mcf.len >= MCF_LEN`
pub fn check(mcf: []u8, password: []const u8) ScryptError!bool {
    assert(mcf.len >= MCF_LEN);
    const ok = c.libscrypt_check(mcf.ptr, password.ptr);

    if (ok < 0) {
        return ScryptError.CheckFailure;
    } else if (ok == 0) {
        return false;
    } else {
        return true;
    }
}

/// Generates a salt. Uses /dev/urandom
/// asserts that `out.len >= SALT_LEN`
pub fn saltGen(out: []u8, len: usize) ScryptError!void {
    assert(out.len >= SALT_LEN);
    const ok = c.libscrypt_salt_gen(out.ptr, len);

    if (ok != 0) return ScryptError.GenFailure;
}

/// Compute scrypt and write result into `out`
/// asserts `r * p < 2^30` and `buflen <= (2^32 - 1) * 32`
/// n must be a power of 2 and greater than 1
pub fn cryptoScrypt(passwd: []const u8, salt: []const u8, n: u64, r: u32, p: u32, out: []u8) ScryptError!void {
    assert(r * p < math.pow(usize, 2, 30));
    assert(out.len <= (math.pow(usize, 2, 32) - 1) * 32);
    const ok = c.libscrypt_scrypt(passwd.ptr, passwd.len, salt.ptr, salt.len, n, r, p, out.ptr, out.len);

    if (ok == -1) return ScryptError.ScryptFailure;
}

/// Converts a series of input parameters to a MCF form for storage
pub fn cryptoMcf(n: u32, r: u32, p: u32, salt: []const u8, _hash: []const u8, mcf: []u8) !void {
    assert(mcf.len >= MCF_LEN);

    const ok = c.libscrypt_mcf(n, r, p, salt.ptr, _hash.ptr, mcf.ptr);

    if (ok != 1) return ScryptError.GenFailure;
}
