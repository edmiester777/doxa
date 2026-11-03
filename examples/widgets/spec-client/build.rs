fn main() {
    doxa_build::ClientSpec::from_server(widgets_server::__doxa_spec())
        .generate()
        .unwrap_or_else(|e| panic!("{e}"));
}
