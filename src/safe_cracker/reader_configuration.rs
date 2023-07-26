pub struct PwListConfiguration<'a> {
    pub path: &'a str,
    pub amount: Option<usize>,
}

impl<'a> PwListConfiguration<'a> {
    pub fn new(path: &'a str, amount: Option<usize>) -> Self {
        PwListConfiguration { path, amount }
    }
}
