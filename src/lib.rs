//! Encoding and decoding for the bencode format.

extern crate sha1;

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::mem::transmute;
use std::ops::Deref;
use std::rc::Rc;
use std::str::{from_utf8, FromStr};
use std::sync::Arc;

use sha1::Sha1;

/// Decodes a value from a stream of bytes.
pub fn decode<T: Decodable>(data: &[u8]) -> Result<T, DecodeError> {
    let mut d = Decoder::new(data);
    let res = try!(Decodable::decode(&mut d));
    try!(d.finish());
    Ok(res)
}

/// Encodes a value into a stream of bytes.
pub fn encode<T: ?Sized + Encodable>(t: &T) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new();
    try!(t.encode(&mut e));
    Ok(e.into_bytes())
}

/// Decodes values from a stream of bytes.
#[derive(Clone)]
pub struct Decoder<'a> {
    data: Cursor<&'a [u8]>,
}

impl<'a> Decoder<'a> {
    /// Constructs a new `Decoder`, reading from the given byte string.
    pub fn new(data: &[u8]) -> Decoder {
        Decoder{data: Cursor::new(data)}
    }

    /// Returns the number of bytes remaining in the stream.
    pub fn remaining(&self) -> usize {
        self.data.get_ref().len() - self.data.position() as usize
    }

    /// Returns the current position of the cursor.
    pub fn position(&self) -> u64 {
        self.data.position()
    }

    /// Sets the current position of the cursor.
    pub fn set_position(&mut self, pos: u64) {
        self.data.set_position(pos);
    }

    /// Returns an error if there is data remaining in the stream.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::ExtraneousData)
        }
    }

    /// Reads a series of bytes from the stream equal to `buf.len()`.
    /// If fewer bytes are available to read, an error is returned.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
        match self.data.read(buf) {
            Ok(n) if n == buf.len() => Ok(()),
            _ => Err(DecodeError::Eof)
        }
    }

    /// Reads a single byte from the stream. If no bytes are available to read,
    /// an error is returned.
    pub fn read_byte(&mut self) -> Result<u8, DecodeError> {
        let mut b = [0];
        try!(self.read(&mut b));
        Ok(b[0])
    }

    /// Reads a single byte from the stream without advancing the cursor.
    pub fn peek_byte(&self) -> Result<u8, DecodeError> {
        let n = self.data.position() as usize;
        let data = self.data.get_ref();
        if data.len() > n {
            Ok(data[n])
        } else {
            Err(DecodeError::Eof)
        }
    }

    /// Returns a slice of bytes without advancing the cursor.
    /// If fewer than `n` bytes are available, an error is returned.
    pub fn peek_bytes(&self, n: usize) -> Result<&[u8], DecodeError> {
        let pos = self.data.position() as usize;
        let buf = self.data.get_ref();

        if buf.len() < pos + n {
            Err(DecodeError::Eof)
        } else {
            Ok(&buf[pos..pos + n])
        }
    }

    /// Reads an integer value from the stream.
    pub fn read_integer<T: Integer>(&mut self) -> Result<T, DecodeError> {
        try!(self.expect(b'i'));
        let n = try!(self.read_number());
        try!(self.expect(b'e'));
        Ok(n)
    }

    /// Reads a number from the stream.
    /// This does not include the `i` prefix and `e` suffix.
    pub fn read_number<T: Integer>(&mut self) -> Result<T, DecodeError> {
        let buf = try!(self.read_while(is_number));
        if buf.is_empty() ||
                (buf.len() > 1 && buf[0] == b'0') ||
                buf == b"-0" {
            return Err(DecodeError::InvalidNumber);
        }
        String::from_utf8(buf).ok().and_then(|s| s.parse().ok())
            .ok_or(DecodeError::InvalidNumber)
    }

    /// Reads a byte string from the stream.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n: usize = try!(self.read_number());
        try!(self.expect(b':'));
        if self.remaining() < n {
            return Err(DecodeError::Eof);
        }
        let mut buf = vec![0; n];
        try!(self.read(&mut buf));
        Ok(buf)
    }

    /// Reads a UTF-8 encoded string from the stream.
    pub fn read_str(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(try!(self.read_bytes()))
            .map_err(|_| DecodeError::InvalidUtf8)
    }

    /// Reads a key value mapping from the stream.
    pub fn read_dict<T: Decodable>(&mut self)
            -> Result<BTreeMap<String, T>, DecodeError> {
        try!(self.expect(b'd'));
        let mut res = BTreeMap::new();

        while try!(self.peek_byte()) != b'e' {
            let k = try!(self.read_str());

            // Ensure that this key is greater than the greatest existing key
            if !res.is_empty() {
                let last: &String = res.keys().next_back().unwrap();
                if k.as_bytes() <= last.as_bytes() {
                    return Err(DecodeError::InvalidDict);
                }
            }

            let v = try!(Decodable::decode(self));
            res.insert(k, v);
        }

        try!(self.expect(b'e'));
        Ok(res)
    }

    /// Reads a series of values from the stream.
    pub fn read_list<T: Decodable>(&mut self) -> Result<Vec<T>, DecodeError> {
        try!(self.expect(b'l'));
        let mut res = Vec::new();

        while try!(self.peek_byte()) != b'e' {
            res.push(try!(Decodable::decode(self)));
        }

        try!(self.expect(b'e'));
        Ok(res)
    }

    /// Reads a key value mapping from the stream as a `struct`.
    ///
    /// The given callable is expected to call `read_field` for each field
    /// and `read_option` for any optional fields, in lexicographical order.
    pub fn read_struct<T, F>(&mut self, f: F) -> Result<T, DecodeError>
            where F: FnOnce(&mut Self) -> Result<T, DecodeError> {
        try!(self.expect(b'd'));
        let res = try!(f(self));

        // Skip any additional fields
        while try!(self.peek_byte()) != b'e' {
            try!(self.skip_item());
            try!(self.skip_item());
        }

        try!(self.expect(b'e'));
        Ok(res)
    }

    /// Reads a single field from the stream.
    pub fn read_field<T: Decodable>(&mut self, name: &str) -> Result<T, DecodeError> {
        let pos = self.data.position();

        while try!(self.peek_byte()) != b'e' {
            let key = try!(self.read_str());

            if name == key {
                return Decodable::decode(self);
            } else if &key[..] < name {
                // This key is less than name. name may be found later.
                try!(self.skip_item());
            } else {
                // This key is greater than name.
                // We won't find name, so bail out now.
                break;
            }
        }

        self.data.set_position(pos);
        Err(DecodeError::MissingField)
    }

    /// Reads an optional field from the stream.
    pub fn read_option<T: Decodable>(&mut self, name: &str)
            -> Result<Option<T>, DecodeError> {
        match self.read_field(name) {
            Ok(t) => Ok(Some(t)),
            Err(DecodeError::MissingField) => Ok(None),
            Err(e) => Err(e)
        }
    }

    /// Advances the cursor beyond the current value.
    pub fn skip_item(&mut self) -> Result<(), DecodeError> {
        match try!(self.peek_byte()) {
            b'd' => {
                try!(self.read_byte());
                while try!(self.peek_byte()) != b'e' {
                    try!(self.skip_item());
                    try!(self.skip_item());
                }
                self.expect(b'e')
            }
            b'i' => {
                try!(self.expect(b'i'));
                try!(self.skip_while(is_number));
                self.expect(b'e')
            }
            b'l' => {
                try!(self.read_byte());
                while try!(self.peek_byte()) != b'e' {
                    try!(self.skip_item());
                }
                self.expect(b'e')
            }
            b'0' ... b'9' => {
                let n = try!(self.read_number());
                try!(self.expect(b':'));
                try!(self.skip(n));
                Ok(())
            }
            b => Err(DecodeError::InvalidByte(b))
        }
    }

    /// Advances the cursor `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<(), DecodeError> {
        let pos = self.data.position();
        if self.data.get_ref().len() < pos as usize + n {
            Err(DecodeError::Eof)
        } else {
            self.data.set_position(pos + n as u64);
            Ok(())
        }
    }

    /// Advance bytes in the stream until `predicate` returns `false`.
    pub fn skip_while<P>(&mut self, mut predicate: P) -> Result<(), DecodeError>
            where P: FnMut(u8) -> bool {
        while predicate(try!(self.peek_byte())) {
            try!(self.read_byte());
        }
        Ok(())
    }

    /// Reads bytes from the stream until `predicate` returns `false`.
    pub fn read_while<P>(&mut self, mut predicate: P) -> Result<Vec<u8>, DecodeError>
            where P: FnMut(u8) -> bool {
        let mut res = Vec::new();

        loop {
            let b = try!(self.peek_byte());
            if !predicate(b) { break; }
            res.push(try!(self.read_byte()));
        }

        Ok(res)
    }

    /// Returns an error if the next byte is not `byte`.
    pub fn expect(&mut self, byte: u8) -> Result<(), DecodeError> {
        let b = try!(self.read_byte());
        if b == byte {
            Ok(())
        } else {
            Err(DecodeError::UnexpectedByte{expected: byte, found: b})
        }
    }
}

/// Represents an error in a decoding operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// End of bytes reached before expected
    Eof,
    /// Extraneous data at the end of the stream
    ExtraneousData,
    /// Unexpected byte
    InvalidByte(u8),
    /// Duplicate or out-of-order key in a dict
    InvalidDict,
    /// Invalid formatted number
    InvalidNumber,
    /// Invalid UTF-8 in a string
    InvalidUtf8,
    /// Field not found while decoding `struct`
    MissingField,
    /// Unexpected byte encountered
    UnexpectedByte{
        /// Byte expected
        expected: u8,
        /// Byte found
        found: u8
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::Eof => f.write_str("unexpected end-of-file"),
            DecodeError::ExtraneousData => f.write_str("extraneous data"),
            DecodeError::InvalidByte(b) => write!(f, "invalid byte {:?}", b),
            DecodeError::InvalidDict => f.write_str("invalid dict"),
            DecodeError::InvalidNumber => f.write_str("invalid number"),
            DecodeError::InvalidUtf8 => f.write_str("invalid utf-8"),
            DecodeError::MissingField => f.write_str("missing field"),
            DecodeError::UnexpectedByte{expected, found} =>
                write!(f, "expected byte {:?}, found {:?}", expected, found),
        }
    }
}

/// Encodes values into a stream of bytes.
#[derive(Clone)]
pub struct Encoder {
    data: Vec<u8>,
}

impl Encoder {
    /// Constructs a new `Encoder`.
    pub fn new() -> Encoder {
        Encoder{data: Vec::new()}
    }

    /// Consumes the `Encoder` and returns the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Writes a single byte to the stream.
    pub fn write_byte(&mut self, b: u8) -> Result<(), EncodeError> {
        self.data.push(b);
        Ok(())
    }

    /// Writes a series of bytes to the stream.
    pub fn write(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        self.data.write(b).unwrap();
        Ok(())
    }

    /// Writes an integer value to the stream.
    pub fn write_integer<T: Integer>(&mut self, t: T) -> Result<(), EncodeError> {
        try!(self.write_byte(b'i'));
        try!(self.write(format!("{}", t).as_bytes()));
        self.write_byte(b'e')
    }

    /// Writes a number to the stream.
    /// This does not include `i` prefix and `e` suffix.
    pub fn write_number<T: Integer>(&mut self, t: T) -> Result<(), EncodeError> {
        self.write(format!("{}", t).as_bytes())
    }

    /// Writes a byte string to the stream.
    pub fn write_bytes(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        try!(self.write_number(b.len()));
        try!(self.write_byte(b':'));
        self.write(b)
    }

    /// Writes a UTF-8 encoded string to the stream.
    pub fn write_str(&mut self, s: &str) -> Result<(), EncodeError> {
        self.write_bytes(s.as_bytes())
    }

    /// Writes a key value mapping to the stream.
    pub fn write_dict<K, V>(&mut self, map: &BTreeMap<K, V>)
            -> Result<(), EncodeError>
            where K: Ord + AsRef<str>, V: Encodable {
        try!(self.write_byte(b'd'));

        for (k, v) in map.iter() {
            try!(self.write_str(k.as_ref()));
            try!(v.encode(self));
        }

        self.write_byte(b'e')
    }

    pub fn write_list<T: Encodable>(&mut self, t: &[T]) -> Result<(), EncodeError> {
        try!(self.write_byte(b'l'));

        for v in t {
            try!(v.encode(self));
        }

        self.write_byte(b'e')
    }

    /// Writes a key value mapping from a `struct` to the stream.
    ///
    /// The given callable is expected to call `write_field` for each field
    /// and `write_option` for any optional fields, in lexicographical order.
    pub fn write_struct<F>(&mut self, f: F) -> Result<(), EncodeError>
            where F: FnOnce(&mut Self) -> Result<(), EncodeError> {
        try!(self.write_byte(b'd'));
        try!(f(self));
        self.write_byte(b'e')
    }

    /// Writes a single field to the stream.
    pub fn write_field<T: ?Sized + Encodable>(&mut self, name: &str, t: &T)
            -> Result<(), EncodeError> {
        try!(self.write_str(name));
        t.encode(self)
    }

    /// Writes an optional field to the stream.
    pub fn write_option<T: Encodable>(&mut self, name: &str, t: &Option<T>)
            -> Result<(), EncodeError> {
        if let Some(ref t) = *t {
            try!(self.write_field(name, t));
        }
        Ok(())
    }
}

/// Returns whether the given byte may appear in a number.
fn is_number(b: u8) -> bool {
    match b {
        b'-' | b'0' ... b'9' => true,
        _ => false
    }
}

/// Represents an error in an encoding operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    // There are no encoding errors, but this exists in case we ever have any.
}

/// Represents a value decodable from a bencoded stream.
pub trait Decodable: Sized {
    fn decode(d: &mut Decoder) -> Result<Self, DecodeError>;
}

/// Represents a value encodable to a bencoded stream.
pub trait Encodable {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError>;
}

/// An integer type that can be encoded and decoded.
pub unsafe trait Integer: Copy + fmt::Display + FromStr {}

macro_rules! impl_integer {
    ( $( $ty:ident )* ) => {
        $( unsafe impl Integer for $ty {} )*
    }
}

impl_integer!{ u8 u16 u32 u64 usize i8 i16 i32 i64 isize }

/// A borrowed byte string.
///
/// This wrapper is necessary for a byte string to be encoded as a string
/// in the bencode format rather than as a list.
pub struct ByteStr {
    inner: [u8],
}

impl ByteStr {
    /// Returns a byte slice as a `&ByteStr`.
    pub fn from_bytes(b: &[u8]) -> &ByteStr {
        unsafe { transmute(b) }
    }

    /// Returns the byte string as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the byte string as a `&str`, if it contains only valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        from_utf8(self.as_bytes()).ok()
    }
}

impl fmt::Debug for ByteStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ByteStr({:?})", self.as_bytes())
    }
}

/// An owned byte string.
///
/// This wrapper is necessary for a byte string to be decoded or encoded
/// as a string in the bencode format rather than as a list.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ByteString(pub Vec<u8>);

impl AsRef<ByteStr> for ByteString {
    fn as_ref(&self) -> &ByteStr {
        ByteStr::from_bytes(&self.0)
    }
}

impl Deref for ByteString {
    type Target = ByteStr;

    fn deref(&self) -> &ByteStr {
        ByteStr::from_bytes(&self.0)
    }
}

/// Contains the SHA1 hash of the decoded value.
pub struct Hash(pub [u8; 20]);

impl Hash {
    /// Returns the SHA1 hash as a string of hexadecimal digits.
    pub fn to_hex(&self) -> String {
        static HEX_CHARS: &'static [u8; 16] = b"0123456789abcdef";
        let mut buf = [0; 40];

        for (i, &b) in self.0.iter().enumerate() {
            buf[i * 2    ] = HEX_CHARS[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX_CHARS[(b & 0xf) as usize];
        }

        unsafe { String::from_utf8_unchecked(buf.to_vec()) }
    }
}

impl Decodable for Hash {
    fn decode(d: &mut Decoder) -> Result<Hash, DecodeError> {
        let mut hash = Hash([0; 20]);
        let start = d.position();
        try!(d.skip_item());
        let end = d.position();
        let len = (end - start) as usize;

        d.set_position(start);
        let mut sha1 = Sha1::new();
        sha1.update(try!(d.peek_bytes(len)));
        sha1.output(&mut hash.0);
        d.set_position(end);

        Ok(hash)
    }
}

/// Contains any valid bencode value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// Integer value
    Integer(i64),
    /// Byte string value
    Bytes(Vec<u8>),
    /// UTF-8 string value
    String(String),
    /// List value
    List(Vec<Value>),
    /// Dictionary value
    Dict(BTreeMap<String, Value>),
}

impl Value {
    /// Converts a `Bytes` or `String` value into `Vec<u8>`.
    /// Otherwise, returns `Err(self)`.
    pub fn into_bytes(self) -> Result<Vec<u8>, Value> {
        match self {
            Value::Bytes(v) => Ok(v),
            Value::String(s) => Ok(s.into_bytes()),
            v => Err(v)
        }
    }
}

impl Decodable for Value {
    fn decode(d: &mut Decoder) -> Result<Value, DecodeError> {
        match try!(d.peek_byte()) {
            b'd' => Ok(Value::Dict(try!(d.read_dict()))),
            b'i' => Ok(Value::Integer(try!(d.read_integer()))),
            b'l' => Ok(Value::List(try!(d.read_list()))),
            b'0' ... b'9' => match String::from_utf8(try!(d.read_bytes())) {
                Ok(s) => Ok(Value::String(s)),
                Err(e) => Ok(Value::Bytes(e.into_bytes()))
            },
            b => Err(DecodeError::InvalidByte(b))
        }
    }
}

impl Decodable for ByteString {
    fn decode(d: &mut Decoder) -> Result<ByteString, DecodeError> {
        d.read_bytes().map(ByteString)
    }
}

macro_rules! impl_decodable_integer {
    ( $( $ty:ident )* ) => {
        $(
            impl Decodable for $ty {
                fn decode(d: &mut Decoder) -> Result<$ty, DecodeError> {
                    d.read_integer()
                }
            }
        )*
    }
}

impl_decodable_integer!{ u8 u16 u32 u64 usize i8 i16 i32 i64 isize }

impl<T: Decodable> Decodable for Box<T> {
    fn decode(d: &mut Decoder) -> Result<Box<T>, DecodeError> {
        Decodable::decode(d).map(Box::new)
    }
}

impl<T: Decodable> Decodable for Rc<T> {
    fn decode(d: &mut Decoder) -> Result<Rc<T>, DecodeError> {
        Decodable::decode(d).map(Rc::new)
    }
}

impl<T: Decodable + Send + Sync> Decodable for Arc<T> {
    fn decode(d: &mut Decoder) -> Result<Arc<T>, DecodeError> {
        Decodable::decode(d).map(Arc::new)
    }
}

impl<T: Decodable> Decodable for Vec<T> {
    fn decode(d: &mut Decoder) -> Result<Vec<T>, DecodeError> {
        d.read_list()
    }
}

impl Decodable for String {
    fn decode(d: &mut Decoder) -> Result<String, DecodeError> {
        d.read_str()
    }
}

impl<T: Decodable> Decodable for BTreeMap<String, T> {
    fn decode(d: &mut Decoder) -> Result<BTreeMap<String, T>, DecodeError> {
        d.read_dict()
    }
}

impl Encodable for Value {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        match *self {
            Value::Integer(i) => e.write_integer(i),
            Value::Bytes(ref b) => e.write_bytes(b),
            Value::String(ref s) => e.write_str(s),
            Value::List(ref l) => e.write_list(l),
            Value::Dict(ref d) => e.write_dict(d),
        }
    }
}

impl Encodable for ByteStr {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_bytes(self.as_bytes())
    }
}

impl Encodable for ByteString {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_bytes(&self.0)
    }
}

macro_rules! impl_encodable_integer {
    ( $( $ty:ident )* ) => {
        $(
            impl Encodable for $ty {
                fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
                    e.write_integer(*self)
                }
            }
        )*
    }
}

impl_encodable_integer!{ u8 u16 u32 u64 usize i8 i16 i32 i64 isize }

impl<T: Encodable> Encodable for Box<T> {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (**self).encode(e)
    }
}

impl<T: Encodable> Encodable for Rc<T> {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (**self).encode(e)
    }
}

impl<T: Encodable + Send + Sync> Encodable for Arc<T> {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (**self).encode(e)
    }
}

impl<T: Encodable> Encodable for [T] {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_list(self)
    }
}

impl<T: Encodable> Encodable for Vec<T> {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_list(self)
    }
}

impl<'a, T: ?Sized + Encodable> Encodable for &'a T {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (**self).encode(e)
    }
}

impl Encodable for str {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_str(self)
    }
}

impl Encodable for String {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_str(self)
    }
}

impl<K: Ord + AsRef<str>, V: Encodable> Encodable for BTreeMap<K, V> {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_dict(self)
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use super::{decode, encode, Decoder, Encoder};
    use super::{ByteStr, ByteString, Hash, Value};
    use super::{Decodable, Encodable, DecodeError, EncodeError};

    #[test]
    fn test_decoder() {
        let mut d = Decoder::new(b"\
            4:spam\
            4:eggs\
            i123e\
            li1ei2ei3ee\
            d3:foo3:bare");

        assert_eq!(d.read_str(), Ok("spam".to_string()));
        assert_eq!(d.read_bytes(), Ok(b"eggs".to_vec()));
        assert_eq!(d.read_integer(), Ok(123));
        assert_eq!(d.read_list(), Ok(vec![1,2,3]));
        let mut m = BTreeMap::new();
        m.insert("foo".to_string(), "bar".to_string());
        assert_eq!(d.read_dict(), Ok(m));
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn test_encoder() {
        let mut e = Encoder::new();

        e.write_str("spam").unwrap();
        e.write_bytes(b"eggs").unwrap();
        e.write_integer(123).unwrap();
        e.write_list(&[1, 2, 3][..]).unwrap();
        let mut m = BTreeMap::new();
        m.insert("foo", "bar");
        e.write_dict(&m).unwrap();

        assert_eq!(e.into_bytes(), &b"\
            4:spam\
            4:eggs\
            i123e\
            li1ei2ei3ee\
            d3:foo3:bare"[..]);
    }

    #[test]
    fn test_encode() {
        let mut e = Encoder::new();

        "foo".encode(&mut e).unwrap();
        ByteStr::from_bytes(b"bar").encode(&mut e).unwrap();
        [1, 2, 3].encode(&mut e).unwrap();

        assert_eq!(e.into_bytes(), &b"\
            3:foo\
            3:bar\
            li1ei2ei3ee\
            "[..]);
    }

    #[test]
    fn test_errors() {
        assert_eq!(decode::<String>(b"10:foo"), Err(DecodeError::Eof));
        assert_eq!(decode::<BTreeMap<String, String>>(b"d3:foo"),
            Err(DecodeError::Eof));
        assert_eq!(decode::<i32>(b"i-0e"), Err(DecodeError::InvalidNumber));
        assert_eq!(decode::<i32>(b"i01e"), Err(DecodeError::InvalidNumber));
        assert_eq!(decode::<BTreeMap<String, i32>>(
            b"d3:fooi0e3:fooi0ee"), Err(DecodeError::InvalidDict));
        assert_eq!(decode::<BTreeMap<String, i32>>(
            b"d3:fooi0e3:bari0ee"), Err(DecodeError::InvalidDict));
    }

    #[test]
    fn test_hash() {
        let mut d = Decoder::new(&b"d3:foo3:bare"[..]);

        let hash = Hash::decode(&mut d).unwrap();
        assert_eq!(d.finish(), Ok(()));
        assert_eq!(hash.to_hex(), "6d2262126feb6ec7bd3464935025c8c609c0119d");
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Test {
        alpha: String,
        bravo: u32,
        charlie: Option<u32>,
        delta: Vec<i32>,
        echo: ByteString,
    }

    impl Decodable for Test {
        fn decode(d: &mut Decoder) -> Result<Test, DecodeError> {
            d.read_struct(|d| {
                Ok(Test{
                    alpha: try!(d.read_field("alpha")),
                    bravo: try!(d.read_field("bravo")),
                    charlie: try!(d.read_option("charlie")),
                    delta: try!(d.read_field("delta")),
                    echo: try!(d.read_field("echo")),
                })
            })
        }
    }

    impl Encodable for Test {
        fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
            e.write_struct(|e| {
                try!(e.write_field("alpha", &self.alpha));
                try!(e.write_field("bravo", &self.bravo));
                try!(e.write_option("charlie", &self.charlie));
                try!(e.write_field("delta", &self.delta));
                try!(e.write_field("echo", &self.echo));
                Ok(())
            })
        }
    }

    #[test]
    fn test_struct() {
        let a = Test{
            alpha: "foo".to_string(),
            bravo: 8675309,
            charlie: Some(99),
            delta: vec![0, -1, 1],
            echo: ByteString([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff].to_vec()),
        };

        let bytes = encode(&a).unwrap();

        assert_eq!(bytes, &b"d\
            5:alpha3:foo\
            5:bravoi8675309e\
            7:charliei99e\
            5:deltali0ei-1ei1ee\
            4:echo6:\xaa\xbb\xcc\xdd\xee\xff\
            e"[..]);

        let b = decode(&bytes).unwrap();

        assert_eq!(a, b);
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Test2 {
        bar: Option<i32>,
        foo: i32,
    }

    impl Decodable for Test2 {
        fn decode(d: &mut Decoder) -> Result<Test2, DecodeError> {
            d.read_struct(|d| {
                Ok(Test2{
                    bar: try!(d.read_option("bar")),
                    foo: try!(d.read_field("foo")),
                })
            })
        }
    }

    impl Encodable for Test2 {
        fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
            e.write_struct(|e| {
                try!(e.write_option("bar", &self.bar));
                try!(e.write_field("foo", &self.foo));
                Ok(())
            })
        }
    }

    #[test]
    fn test_struct_fields() {
        let mut d = Decoder::new(&b"\
            d\
            1:a6:lalala\
            3:bari999e\
            6:dadadai1e\
            3:fooi111e\
            2:zzi1e\
            e"[..]);

        assert_eq!(Test2::decode(&mut d),
            Ok(Test2{bar: Some(999), foo: 111}));

        let mut d = Decoder::new(&b"\
            d\
            1:a6:lalala\
            6:dadadai1e\
            3:fooi111e\
            2:zzi1e\
            e"[..]);

        assert_eq!(Test2::decode(&mut d),
            Ok(Test2{bar: None, foo: 111}));
    }

    #[test]
    fn test_value() {
        let mut d = Decoder::new(&b"\
            d\
            5:alphai123e\
            4:beta3:\xaa\xbb\xcc\
            5:gamma4:ohai\
            6:lambdali1e1:2e\
            e"[..]);

        let v = Value::decode(&mut d).unwrap();

        assert_eq!(v, Value::Dict(
            vec![
                ("alpha".to_string(), Value::Integer(123)),
                ("beta".to_string(), Value::Bytes(b"\xaa\xbb\xcc".to_vec())),
                ("gamma".to_string(), Value::String("ohai".to_string())),
                ("lambda".to_string(), Value::List(vec![
                    Value::Integer(1),
                    Value::String("2".to_string()),
                ])),
            ]
            .into_iter().collect::<BTreeMap<_, _>>()));
    }
}
