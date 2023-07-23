pub enum FieldType<'a> {
    String(&'a str),
    Int(usize),
    Float(f64),
}
