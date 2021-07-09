use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct InvalidData(String);

impl Display for InvalidData {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, self.0)
    }
}
