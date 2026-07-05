use crate::Digestible;
use crate::define_algo;

define_algo!(
    /// Compute the MD5 digest of `src`.
    ///
    /// **MD5 is cryptographically broken**; use it only for checksums and
    /// interop with legacy systems, never for security.
    md5,
    /// A 16-byte MD5 digest.
    Md5Digest,
    md5::Md5,
    16
);

define_algo!(
    /// Compute the SHA-1 digest of `src`.
    ///
    /// **SHA-1 is cryptographically broken** for collision resistance; prefer
    /// SHA-256 for new work.
    sha1,
    /// A 20-byte SHA-1 digest.
    Sha1Digest,
    sha1::Sha1,
    20
);

define_algo!(
    /// Compute the SHA-224 digest of `src`.
    sha224,
    /// A 28-byte SHA-224 digest.
    Sha224Digest,
    sha2::Sha224,
    28
);

define_algo!(
    /// Compute the SHA-256 digest of `src`.
    sha256,
    /// A 32-byte SHA-256 digest.
    Sha256Digest,
    sha2::Sha256,
    32
);

define_algo!(
    /// Compute the SHA-384 digest of `src`.
    sha384,
    /// A 48-byte SHA-384 digest.
    Sha384Digest,
    sha2::Sha384,
    48
);

define_algo!(
    /// Compute the SHA-512 digest of `src`.
    sha512,
    /// A 64-byte SHA-512 digest.
    Sha512Digest,
    sha2::Sha512,
    64
);
