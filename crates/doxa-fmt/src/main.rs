fn main() -> std::process::ExitCode {
    doxa_fmt::run(std::env::args().skip(1))
}
