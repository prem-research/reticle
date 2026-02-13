use std::{borrow::Cow, error::Error, fmt::Display};

use zerocopy::{FromBytes, Immutable, KnownLayout};

pub trait Cursor {
    fn take_slice<'a, const N: usize>(&mut self) -> Option<&'a [u8; N]>
    where
        Self: 'a;

    fn split_off<'a>(&mut self, n: usize) -> Option<&'a [u8]>
    where
        Self: 'a;

    fn remaining(&self) -> usize;
}

impl Cursor for &[u8] {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn take_slice<'a, const N: usize>(&mut self) -> Option<&'a [u8; N]>
    where
        Self: 'a,
    {
        let (split, remaining) = self.split_first_chunk()?;
        *self = remaining;

        Some(split)
    }

    fn split_off<'a>(&mut self, n: usize) -> Option<&'a [u8]>
    where
        Self: 'a,
    {
        let split = self.get(..n)?;
        *self = &self[n..];

        Some(split)
    }
}

impl<C: Cursor> Cursor for &mut C {
    fn take_slice<'a, const N: usize>(&mut self) -> Option<&'a [u8; N]>
    where
        Self: 'a,
    {
        (**self).take_slice()
    }

    fn split_off<'a>(&mut self, n: usize) -> Option<&'a [u8]>
    where
        Self: 'a,
    {
        (**self).split_off(n)
    }

    fn remaining(&self) -> usize {
        (**self).remaining()
    }
}

pub trait CursorExt: Cursor {
    fn take_u8(&mut self) -> Option<u8> {
        self.take_slice::<1>().map(|x| x[0])
    }

    fn take_i8(&mut self) -> Option<i8> {
        self.take_u8().map(|x| x as _)
    }

    fn take_u16(&mut self) -> Option<u16> {
        let x = self.take_slice::<2>()?;
        Some(u16::from_le_bytes(*x))
    }

    fn take_u32(&mut self) -> Option<u32> {
        let x = self.take_slice::<4>()?;
        Some(u32::from_le_bytes(*x))
    }

    fn take_u64(&mut self) -> Option<u64> {
        let x = self.take_slice::<8>()?;
        Some(u64::from_le_bytes(*x))
    }

    fn zerocopy_ref<'b, T: FromBytes + Immutable + KnownLayout>(&mut self) -> Option<&'b T>
    where
        Self: 'b,
    {
        let size = size_of::<T>();
        let source = self.split_off(size)?;
        Some(T::ref_from_bytes(source).unwrap())
    }

    // fn parse<'d, T>(&mut self) -> Result<T, ParseError>
    // where
    //     T: Parse<'d> + Sized,
    //     Self: Sized,
    // {
    //     T::parse(self)
    // }
}

impl<'a, T: Cursor> CursorExt for T {}

#[derive(Debug)]
pub struct ParseError {
    error: Cow<'static, str>,
}

impl From<&'static str> for ParseError {
    fn from(value: &'static str) -> Self {
        ParseError {
            error: value.into(),
        }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.error)
    }
}

impl Error for ParseError {}

pub trait ParseErrorExt<T> {
    fn context<C>(self, context: C) -> Result<T, ParseError>
    where
        C: Into<Cow<'static, str>>;
}

impl<T> ParseErrorExt<T> for Option<T> {
    fn context<C>(self, context: C) -> Result<T, ParseError>
    where
        C: Into<Cow<'static, str>>,
    {
        self.ok_or_else(|| ParseError {
            error: context.into(),
            // location: None,
        })
    }
}

pub trait Parse<'d>: Sized + 'd {
    fn parse(cursor: impl Cursor + 'd) -> Result<Self, ParseError>;
}

#[macro_export]
macro_rules! parse_bail {
    ($msg:expr) => {
        return Err($msg.into())
    };
}
