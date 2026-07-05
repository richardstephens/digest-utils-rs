use digest::{Digest, Output};
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Something that can be fed to a hash function.
///
/// This is the crate's central abstraction. It is implemented for in-memory
/// byte sources (`&[u8]`, `&str`, `String`, `Vec<u8>`) and for sources that
/// read from the outside world (`&Path`, `PathBuf`, `File`, [`Reader`]).
///
/// * in-memory sources set `Output<T> = T` - the identity wrapper, so
///   `sha256(&[u8])` returns a bare [`Sha256Digest`];
/// * I/O sources set `Output<T> = io::Result<T>`, so `sha256(&Path)` returns
///   `io::Result<Sha256Digest>`.
pub trait Digestible {
    /// Wrapper applied to the digest value: `T` for infallible sources,
    /// `io::Result<T>` for fallible ones.
    type Output<T>;

    /// Feed this source into hasher `D`, then map the raw output with `finish`.
    ///
    /// Implementors that cannot fail call `finish` and return the value as-is;
    /// implementors that read I/O return `Ok(finish(..))` or propagate the
    /// error.
    fn digest<D, T, F>(self, finish: F) -> Self::Output<T>
    where
        D: Digest,
        F: FnOnce(Output<D>) -> T;
}

/// Adapter that hashes any [`Read`]er (e.g. a socket, a decompressor).
///
/// ```no_run
/// use std::io::Cursor;
/// use digest_utils::{sha256, Reader};
///
/// let d = sha256(Reader(Cursor::new(b"streamed"))).unwrap();
/// # let _ = d;
/// ```
pub struct Reader<R>(pub R);

impl<R: Read> Digestible for Reader<R> {
    type Output<T> = io::Result<T>;

    fn digest<D, T, F>(self, finish: F) -> io::Result<T>
    where
        D: Digest,
        F: FnOnce(Output<D>) -> T,
    {
        let raw = hash_reader::<D, _>(self.0)?;
        Ok(finish(raw))
    }
}

/// Read `reader` to EOF, feeding it into hasher `D` in bounded chunks.
fn hash_reader<D: Digest, R: Read>(mut reader: R) -> io::Result<Output<D>> {
    let mut hasher = D::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

/// Infallible, in-memory sources: `Output<T> = T`.
macro_rules! byte_source {
    ($t:ty, |$s:ident| $bytes:expr) => {
        impl Digestible for $t {
            type Output<T> = T;

            fn digest<D, T, F>(self, finish: F) -> T
            where
                D: Digest,
                F: FnOnce(Output<D>) -> T,
            {
                let $s = self;
                let mut hasher = D::new();
                hasher.update($bytes);
                finish(hasher.finalize())
            }
        }
    };
}

byte_source!(&[u8], |s| s);
byte_source!(&str, |s| s.as_bytes());
byte_source!(String, |s| s.as_bytes());
byte_source!(&String, |s| s.as_bytes());
byte_source!(Vec<u8>, |s| s.as_slice());
byte_source!(&Vec<u8>, |s| s.as_slice());

/// Fallible, I/O-backed sources: `Output<T> = io::Result<T>`.
macro_rules! read_source {
    ($t:ty, |$s:ident| $reader:expr) => {
        impl Digestible for $t {
            type Output<T> = io::Result<T>;

            fn digest<D, T, F>(self, finish: F) -> io::Result<T>
            where
                D: Digest,
                F: FnOnce(Output<D>) -> T,
            {
                let $s = self;
                let raw = hash_reader::<D, _>($reader)?;
                Ok(finish(raw))
            }
        }
    };
}

// Note: `&str`/`String` deliberately hash their *bytes*, not the file at that
// path. To hash a file you must pass a `Path`/`PathBuf`/`File`, which removes
// the classic "is this a filename or a string?" ambiguity.
read_source!(&Path, |p| File::open(p)?);
read_source!(&PathBuf, |p| File::open(p)?);
read_source!(PathBuf, |p| File::open(&p)?);
read_source!(File, |f| f);
read_source!(&File, |f| f);
