// SHA-1 single-thread driver kernel.
//
// Input layout (storage buffer `blocks`): N * 16 u32 words. Each u32 is one
// 4-byte chunk of the (already-padded) SHA-1 message, interpreted big-endian.
// The host pre-byteswaps via `u32::from_be_bytes`, so the kernel reads each
// word directly with no per-load swap.
//
// Output layout (storage buffer `state`): 5 u32 words = the final 160-bit
// digest, in the same big-endian-as-native-u32 form (host converts back to
// bytes via `to_be_bytes`).

@group(0) @binding(0) var<storage, read> blocks: array<u32>;
@group(0) @binding(1) var<storage, read_write> state_out: array<u32>;

struct Params {
    n_blocks: u32,
}
@group(0) @binding(2) var<uniform> params: Params;

fn rotl(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

fn sha1_compress(state: ptr<function, array<u32, 5>>, block_offset: u32) {
    // Same rolling 16-word window as pbkdf2.wgsl. Perf is irrelevant here
    // (this kernel runs ≤ a few compressions per call and only exists for
    // correctness validation), but keeping the two implementations in sync
    // makes drift bugs impossible.
    var w: array<u32, 16>;

    var a = (*state)[0];
    var b = (*state)[1];
    var c = (*state)[2];
    var d = (*state)[3];
    var e = (*state)[4];

    for (var i: u32 = 0u; i < 80u; i = i + 1u) {
        let idx = i & 15u;
        var word: u32;
        if (i < 16u) {
            word = blocks[block_offset + i];
        } else {
            word = rotl(
                w[(i + 13u) & 15u] ^ w[(i + 8u) & 15u] ^ w[(i + 2u) & 15u] ^ w[idx],
                1u,
            );
        }
        w[idx] = word;

        var f: u32;
        var k: u32;
        if (i < 20u) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40u) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60u) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        let t = rotl(a, 5u) + f + e + k + word;
        e = d;
        d = c;
        c = rotl(b, 30u);
        b = a;
        a = t;
    }

    (*state)[0] = (*state)[0] + a;
    (*state)[1] = (*state)[1] + b;
    (*state)[2] = (*state)[2] + c;
    (*state)[3] = (*state)[3] + d;
    (*state)[4] = (*state)[4] + e;
}

@compute @workgroup_size(1)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x != 0u) {
        return;
    }

    var state: array<u32, 5>;
    state[0] = 0x67452301u;
    state[1] = 0xEFCDAB89u;
    state[2] = 0x98BADCFEu;
    state[3] = 0x10325476u;
    state[4] = 0xC3D2E1F0u;

    for (var b: u32 = 0u; b < params.n_blocks; b = b + 1u) {
        sha1_compress(&state, b * 16u);
    }

    state_out[0] = state[0];
    state_out[1] = state[1];
    state_out[2] = state[2];
    state_out[3] = state[3];
    state_out[4] = state[4];
}
