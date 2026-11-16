wit_bindgen::generate!({
    path: "../wit",
    world: "inspector-system",
    generate_all,
    additional_derives: [serde::Serialize, serde::Deserialize],
    // These capabilities are local WIT borrows, not inspector RPC values.
    additional_derives_ignore: ["timeline-point", "signal-point", "completion"],
});
