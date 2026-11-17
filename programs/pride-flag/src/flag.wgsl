// A six-stripe pride flag waving in perspective.
//
// The mesh is generated from the vertex index: a grid of `COLUMNS` by
// `ROWS` quads, two triangles each, whose rows split evenly into the six
// stripes. The wave travels away from the hoist (u = 0), where the cloth
// is held still, and grows toward the fly.

struct Frame {
    time: f32,
    aspect: f32,
    padding: vec2<f32>,
}

@group(0) @binding(0) var<uniform> frame: Frame;

const COLUMNS: u32 = 48u;
const ROWS: u32 = 24u;
const STRIPES: u32 = 6u;

// The flag's extent in world units, 3:2 like the printed flag.
const WIDTH: f32 = 1.8;
const HEIGHT: f32 = 1.2;

// The wave: its height, how many radians it spans across the flag and
// along the hoist, and how fast it travels.
const AMPLITUDE: f32 = 0.12;
const WAVES_ALONG: f32 = 6.0;
const WAVES_ACROSS: f32 = 1.5;
const SPEED: f32 = 2.5;

// The camera: a turn to show the flag's depth, the distance it stands
// back, and a vertical field of view of 0.8 rad (about 46 degrees).
const YAW: f32 = -0.45;
const PITCH: f32 = 0.15;
const DISTANCE: f32 = 2.4;
const FOV_Y: f32 = 0.8;
const NEAR: f32 = 0.1;
const FAR: f32 = 10.0;

// The six stripes, top to bottom, as sRGB values written straight into
// the unorm canvas: E40303, FF8C00, FFED00, 008026, 004CFF and 732982.
const COLORS = array<vec3<f32>, 6>(
    vec3<f32>(0.894, 0.012, 0.012),
    vec3<f32>(1.000, 0.549, 0.000),
    vec3<f32>(1.000, 0.929, 0.000),
    vec3<f32>(0.000, 0.502, 0.149),
    vec3<f32>(0.000, 0.298, 1.000),
    vec3<f32>(0.451, 0.161, 0.510),
);

struct Varyings {
    @builtin(position) position: vec4<f32>,
    @location(0) color: vec3<f32>,
    @location(1) normal: vec3<f32>,
}

fn rotate(p: vec3<f32>) -> vec3<f32> {
    let yawed = vec3<f32>(
        cos(YAW) * p.x + sin(YAW) * p.z,
        p.y,
        -sin(YAW) * p.x + cos(YAW) * p.z,
    );
    return vec3<f32>(
        yawed.x,
        cos(PITCH) * yawed.y - sin(PITCH) * yawed.z,
        sin(PITCH) * yawed.y + cos(PITCH) * yawed.z,
    );
}

// WebGPU's clip space: depth in [0, 1], w the distance in front.
fn project(view: vec3<f32>) -> vec4<f32> {
    let focal = 1.0 / tan(0.5 * FOV_Y);
    return vec4<f32>(
        view.x * focal / frame.aspect,
        view.y * focal,
        view.z * FAR / (NEAR - FAR) + NEAR * FAR / (NEAR - FAR),
        -view.z,
    );
}

@vertex
fn vertex(@builtin(vertex_index) index: u32) -> Varyings {
    // The corners of a quad's two triangles, in grid steps.
    var corners = array<vec2<u32>, 6>(
        vec2<u32>(0u, 0u),
        vec2<u32>(1u, 0u),
        vec2<u32>(0u, 1u),
        vec2<u32>(0u, 1u),
        vec2<u32>(1u, 0u),
        vec2<u32>(1u, 1u),
    );
    let quad = index / 6u;
    let column = quad % COLUMNS;
    let row = quad / COLUMNS;
    let corner = corners[index % 6u];
    let u = f32(column + corner.x) / f32(COLUMNS);
    let v = f32(row + corner.y) / f32(ROWS);

    let phase = WAVES_ALONG * u - SPEED * frame.time + WAVES_ACROSS * v;
    let position = vec3<f32>(
        (u - 0.5) * WIDTH,
        (0.5 - v) * HEIGHT,
        AMPLITUDE * u * sin(phase),
    );
    // The surface's tangents along u and v, and the normal between them.
    let along = vec3<f32>(
        WIDTH,
        0.0,
        AMPLITUDE * (sin(phase) + u * WAVES_ALONG * cos(phase)),
    );
    let across = vec3<f32>(0.0, -HEIGHT, AMPLITUDE * u * WAVES_ACROSS * cos(phase));
    let normal = normalize(cross(along, across));

    var view = rotate(position);
    view.z -= DISTANCE;

    var out: Varyings;
    out.position = project(view);
    out.color = COLORS[row / (ROWS / STRIPES)];
    out.normal = rotate(normal);
    return out;
}

// A light above and to the right of the camera.
const LIGHT: vec3<f32> = vec3<f32>(0.4, 0.6, 0.7);
const AMBIENT: f32 = 0.35;

@fragment
fn fragment(in: Varyings) -> @location(0) vec4<f32> {
    // Cloth is lit from either side.
    let diffuse = abs(dot(normalize(in.normal), normalize(LIGHT)));
    return vec4<f32>(in.color * (AMBIENT + (1.0 - AMBIENT) * diffuse), 1.0);
}
