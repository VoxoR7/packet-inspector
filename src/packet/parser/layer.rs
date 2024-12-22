pub trait Layer {
    fn print_layer(&self) -> String;
}

impl std::fmt::Debug for dyn Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.print_layer())
    }
}
