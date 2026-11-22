fn main() {
    doxa_role::Client::new()
        .commands(&["export_widgets"])
        .build()
}
