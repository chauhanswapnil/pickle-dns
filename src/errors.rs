#[derive(Debug)]
pub enum ParseError {
    Header(HeaderParseError),
    Question(QuestionParseError),
    InvalidFormat,
    InvalidByteLength,
    UnexpectedEndOfInput,
}

#[derive(Debug)]
pub enum HeaderParseError {
    InvalidOpcode,
    InvalidRcode,
    InvalidLength,
}

#[derive(Debug)]
pub enum QuestionParseError {
    UnsupportedType,
    UnsupportedClass,
}

impl From<HeaderParseError> for ParseError {
    fn from(error: HeaderParseError) -> Self {
        ParseError::Header(error)
    }
}

impl From<QuestionParseError> for ParseError {
    fn from(error: QuestionParseError) -> Self {
        ParseError::Question(error)
    }
}
