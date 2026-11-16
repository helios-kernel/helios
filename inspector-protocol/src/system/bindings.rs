wit_bindgen::generate!({
    path: "../wit",
    world: "inspector-system",
    generate_all,
    additional_derives: [serde::Serialize, serde::Deserialize],
});
