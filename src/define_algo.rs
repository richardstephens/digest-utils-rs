/// Defines a strongly-typed digest newtype plus its free function.
#[macro_export]
macro_rules! define_algo {
    (
        $(#[$fn_doc:meta])*
        $fn_name:ident,
        $(#[$ty_doc:meta])*
        $struct:ident,
        $algo:ty,
        $len:expr
    ) => {
        $(#[$ty_doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $struct([u8; $len]);

        impl $struct {
            /// Length of this digest in bytes.
            pub const LEN: usize = $len;

            /// Wrap raw digest bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw digest bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Lower-case hex encoding of the digest.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse a digest from its hex encoding.
            ///
            /// Errors if `s` is not valid hex or not exactly the right length.
            pub fn from_hex(s: impl AsRef<[u8]>) -> Result<Self, hex::FromHexError> {
                let mut out = [0u8; $len];
                hex::decode_to_slice(s.as_ref(), &mut out)?;
                Ok(Self(out))
            }
        }

        impl From<$struct> for [u8; $len] {
            fn from(d: $struct) -> Self {
                d.0
            }
        }

        impl From<$struct> for Vec<u8> {
            fn from(d: $struct) -> Self {
                d.0.to_vec()
            }
        }

        impl From<[u8; $len]> for $struct {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl AsRef<[u8]> for $struct {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $struct {
            type Error = core::array::TryFromSliceError;
            fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(s.try_into()?))
            }
        }

        impl std::fmt::Display for $struct {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for byte in &self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl std::fmt::Debug for $struct {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($struct), self)
            }
        }

        impl std::str::FromStr for $struct {
            type Err = hex::FromHexError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_hex(s)
            }
        }

        $(#[$fn_doc])*
        pub fn $fn_name<S: Digestible>(src: S) -> S::Output<$struct> {
            src.digest::<$algo, _, _>(|raw| {
                let mut bytes = [0u8; $len];
                bytes.copy_from_slice(&raw);
                $struct(bytes)
            })
        }
    };
}
