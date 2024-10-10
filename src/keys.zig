const std = @import("std");
pub const ssl = @cImport({
    @cInclude("bearssl/bearssl_ssl.h");
    @cInclude("bearssl/bearssl_pem.h");
});

pub const PrivateKeyType = enum { rsa, ec };

const EcKey = struct { key: *const ssl.br_ec_private_key, key_type: c_int };

pub const PrivateKey = union(PrivateKeyType) {
    rsa: *const ssl.br_rsa_private_key,
    ec: EcKey,
};

pub const Keys = struct {
    certs: [][]u8,
    private_key: PrivateKey,
};
