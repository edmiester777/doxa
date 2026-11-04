//! A declared route nothing implements stops the app, once it implements any of its API crate.

use doxa::__private::contract::Declared;
use doxa::__private::{inventory, Mount, Service};
use doxa::wire::{Method, RouteSpec};

const fn route(method: Method, path: &'static str, operation_id: &'static str) -> RouteSpec {
    RouteSpec {
        method,
        path,
        operation_id,
        entities: &[],
        dry_run: false,
        invalidates: true,
        package: "shop-api",
    }
}

static LIST: RouteSpec = route(Method::Get, "/items", "list_items");
static ADD: RouteSpec = route(Method::Post, "/items", "add_item");

inventory::submit!(Declared(&LIST));
inventory::submit!(Declared(&ADD));
inventory::submit!(Service {
    name: "Shop",
    module: "app_declared",
    layers: None,
});
inventory::submit!(Mount {
    module: "app_declared",
    handler: "list_items",
    declared: Some(&LIST),
    build: |_| None,
    doc: || doxa::Routes::default().into_openapi(),
});

#[test]
#[should_panic(
    expected = "shop-api declares `add_item` (POST /items), which no handler implements"
)]
fn the_unimplemented_route_is_named() {
    doxa::spec();
}
