//! Ergonomic helpers for the common cryptographic hash functions, in the spirit
//! of Apache Commons Codec's `DigestUtils` - but Rust-flavoured.
//!
//! # Quick start
//!
//! ```
//! use digest_utils::sha256;
//!
//! // Infallible source (bytes / string) -> plain digest.
//! let d = sha256("abc");
//! assert_eq!(
//!     d.to_hex(),
//!     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
//! );
//!
//! // Round-trip through hex, and convert into the raw bytes.
//! let same = digest_utils::Sha256Digest::from_hex(d.to_hex()).unwrap();
//! assert_eq!(d, same);
//! let bytes: [u8; 32] = d.into();
//! # let _ = bytes;
//! ```
//!
//! # Fallible vs. infallible sources
//!
//! `sha256(x)` (and friends) return a *plain* digest when the
//! source cannot fail, but a [`std::io::Result`] when it can.
//!
//! ```no_run
//! use std::path::Path;
//! use digest_utils::sha256;
//!
//! let a: digest_utils::Sha256Digest = sha256(b"in memory, cannot fail".as_slice());
//! let b: std::io::Result<digest_utils::Sha256Digest> = sha256(Path::new("/etc/hosts"));
//! # let _ = (a, b);
//! ```
//!
//! This works because [`Digestible::Output`] is a *wrapper*: it is `T` (the
//! identity wrapper) for in-memory sources and `io::Result<T>` for sources that
//! perform I/O. See the [`Digestible`] trait for details.

mod algos;
pub(crate) mod define_algo;
mod digestable;

pub use algos::*;
pub use digestable::Digestible;
pub use digestable::Reader;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digestable::Reader;

    #[test]
    fn known_vectors() {
        assert_eq!(md5("").to_hex(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5("abc").to_hex(), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            sha1("abc").to_hex(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            sha256("").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256("abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha512("abc").to_hex(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d3\
             9a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn accepts_various_byte_sources() {
        let expected = sha256("abc");
        assert_eq!(sha256(b"abc".as_slice()), expected);
        assert_eq!(sha256(String::from("abc")), expected);
        assert_eq!(sha256(&String::from("abc")), expected);
        assert_eq!(sha256(vec![b'a', b'b', b'c']), expected);
        assert_eq!(sha256(&vec![b'a', b'b', b'c']), expected);
    }

    #[test]
    fn hex_round_trip() {
        let d = sha256("hello world");
        let parsed = Sha256Digest::from_hex(d.to_hex()).unwrap();
        assert_eq!(d, parsed);
        assert_eq!(d, d.to_hex().parse().unwrap());
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert!(Sha256Digest::from_hex("xyz").is_err()); // not hex
        assert!(Sha256Digest::from_hex("abcd").is_err()); // wrong length
    }

    #[test]
    fn conversions() {
        let d = sha256("abc");
        let arr: [u8; 32] = d.into();
        assert_eq!(Sha256Digest::from(arr), d);
        let v: Vec<u8> = d.into();
        assert_eq!(v.as_slice(), d.as_ref());
        assert_eq!(Sha256Digest::try_from(v.as_slice()).unwrap(), d);
    }

    #[test]
    fn fallible_source_reads_file() {
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push("digest_utils_test_file.txt");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"abc")
            .unwrap();

        // A `&Path` source yields `io::Result<_>`.
        let d: std::io::Result<Sha256Digest> = sha256(path.as_path());
        assert_eq!(d.unwrap(), sha256("abc"));

        // A `Reader` over any `Read`er also yields `io::Result<_>`.
        let streamed = sha256(Reader(std::io::Cursor::new(b"abc"))).unwrap();
        assert_eq!(streamed, sha256("abc"));

        std::fs::remove_file(&path).ok();
    }
}
