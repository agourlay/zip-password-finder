// PBKDF2-HMAC-SHA1 kernel. One workgroup-thread per candidate password.
//
// Host responsibilities:
//   - Zero-pad each password to 64 bytes, pack as 16 big-endian u32s.
//     (Passwords > 64 bytes are not supported; HMAC's "hash long key" path
//     would have to be added separately. WinZip-AES passwords are well under
//     this in practice.)
//   - For each output block index i in 1..=n_blocks, build the U_1 message
//     block (salt || i_be32 || 0x80 || zeros || bit_length_be64) padded to
//     64 bytes, packed as 16 big-endian u32s. Upload n_blocks of these.
//
// Standard PBKDF2 micro-optimization: the SHA-1 state after compressing the
// 64-byte ipad block (and likewise opad) depends only on the password, so
// we compute each once at the top and reuse them across all 2 * iterations
// HMAC compressions. ~2x fewer SHA-1 compressions vs naive HMAC.

struct Params {
    n_passwords: u32,
    n_blocks: u32,
    iterations: u32,
    _pad: u32,
}

@group(0) @binding(0) var<storage, read> passwords: array<u32>;
@group(0) @binding(1) var<storage, read> u1_msg_blocks: array<u32>;
@group(0) @binding(2) var<storage, read_write> derived_keys: array<u32>;
@group(0) @binding(3) var<uniform> params: Params;

const SHA1_H0: u32 = 0x67452301u;
const SHA1_H1: u32 = 0xEFCDAB89u;
const SHA1_H2: u32 = 0x98BADCFEu;
const SHA1_H3: u32 = 0x10325476u;
const SHA1_H4: u32 = 0xC3D2E1F0u;

// (64 ipad/opad bytes + 20 inner-hash bytes) * 8 = 672 bits. Constant for
// every HMAC inner/outer compression after the first message-block.
const HMAC_INNER_BIT_LEN: u32 = 672u;

// Naga keeps named struct fields as scalars (SROA), whereas `array<u32, 5>`
// can end up backed by an addressable allocation when ptr<function, _> is
// taken; using a struct here makes the SROA reliable.
struct Sha1State {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

fn rotl(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

fn sha1_compress(state: ptr<function, Sha1State>, block: ptr<function, array<u32, 16>>) {
    // Rolling 16-word window: W[i] depends only on W[i-3], W[i-8], W[i-14],
    // W[i-16], so we keep just 16 slots and index by `i & 15`. Cuts VGPR
    // footprint vs. an explicit `array<u32, 80>`.
    var w: array<u32, 16>;

    var a = (*state).h0;
    var b = (*state).h1;
    var c = (*state).h2;
    var d = (*state).h3;
    var e = (*state).h4;

    for (var i: u32 = 0u; i < 80u; i = i + 1u) {
        let idx = i & 15u;
        var word: u32;
        if (i < 16u) {
            word = (*block)[i];
        } else {
            // The four reads are W[i-3], W[i-8], W[i-14], W[i-16]; the last
            // collides with `idx` (where we'll write) but is read first.
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

    (*state).h0 = (*state).h0 + a;
    (*state).h1 = (*state).h1 + b;
    (*state).h2 = (*state).h2 + c;
    (*state).h3 = (*state).h3 + d;
    (*state).h4 = (*state).h4 + e;
}

// Build the standard 64-byte block that wraps a 20-byte inner hash for HMAC's
// outer compression (or for any subsequent HMAC iteration's inner compression).
fn pack_hash_block(hash: ptr<function, Sha1State>, block: ptr<function, array<u32, 16>>) {
    (*block)[0] = (*hash).h0;
    (*block)[1] = (*hash).h1;
    (*block)[2] = (*hash).h2;
    (*block)[3] = (*hash).h3;
    (*block)[4] = (*hash).h4;
    (*block)[5] = 0x80000000u;
    (*block)[6] = 0u;
    (*block)[7] = 0u;
    (*block)[8] = 0u;
    (*block)[9] = 0u;
    (*block)[10] = 0u;
    (*block)[11] = 0u;
    (*block)[12] = 0u;
    (*block)[13] = 0u;
    (*block)[14] = 0u;
    (*block)[15] = HMAC_INNER_BIT_LEN;
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let pid = gid.x;
    if (pid >= params.n_passwords) {
        return;
    }

    // Two reusable 16-word block buffers. Naming each role separately
    // (ipad, opad, u1_block, outer_block, inner_msg, o_msg) made naga emit
    // six distinct `var<function>` allocations, pushing NVIDIA threads past
    // ~100 registers and capping SM occupancy at ~25%. Live-range analysis
    // shows only two are ever needed at once: block_a holds password- or
    // message-derived input, block_b holds hash-derived input.
    var block_a: array<u32, 16>;
    var block_b: array<u32, 16>;

    // 1. Build ipad and opad blocks (password XOR 0x36.. / 0x5C..).
    let pw_off = pid * 16u;
    for (var w: u32 = 0u; w < 16u; w = w + 1u) {
        let word = passwords[pw_off + w];
        block_a[w] = word ^ 0x36363636u;
        block_b[w] = word ^ 0x5C5C5C5Cu;
    }

    // 2. Precompute SHA-1 state after one ipad / opad compression.
    var ipad_state = Sha1State(SHA1_H0, SHA1_H1, SHA1_H2, SHA1_H3, SHA1_H4);
    sha1_compress(&ipad_state, &block_a);

    var opad_state = Sha1State(SHA1_H0, SHA1_H1, SHA1_H2, SHA1_H3, SHA1_H4);
    sha1_compress(&opad_state, &block_b);

    // 3. For each output block index in 1..=n_blocks: derive T_i and write out.
    for (var blk: u32 = 0u; blk < params.n_blocks; blk = blk + 1u) {
        // U_1: HMAC inner = SHA1(ipad || salt || (blk+1)_be32). The host has
        // pre-built that 64-byte block (after the ipad prefix already absorbed).
        let msg_off = blk * 16u;
        for (var w: u32 = 0u; w < 16u; w = w + 1u) {
            block_a[w] = u1_msg_blocks[msg_off + w];
        }

        var inner: Sha1State = ipad_state;
        sha1_compress(&inner, &block_a);

        pack_hash_block(&inner, &block_b);

        var u_curr: Sha1State = opad_state;
        sha1_compress(&u_curr, &block_b);

        var t: Sha1State = u_curr;

        // Iterations 2..=iterations.
        for (var iter: u32 = 1u; iter < params.iterations; iter = iter + 1u) {
            pack_hash_block(&u_curr, &block_a);

            var i_state: Sha1State = ipad_state;
            sha1_compress(&i_state, &block_a);

            pack_hash_block(&i_state, &block_b);

            u_curr = opad_state;
            sha1_compress(&u_curr, &block_b);

            t.h0 = t.h0 ^ u_curr.h0;
            t.h1 = t.h1 ^ u_curr.h1;
            t.h2 = t.h2 ^ u_curr.h2;
            t.h3 = t.h3 ^ u_curr.h3;
            t.h4 = t.h4 ^ u_curr.h4;
        }

        let dk_off = pid * (params.n_blocks * 5u) + blk * 5u;
        derived_keys[dk_off + 0u] = t.h0;
        derived_keys[dk_off + 1u] = t.h1;
        derived_keys[dk_off + 2u] = t.h2;
        derived_keys[dk_off + 3u] = t.h3;
        derived_keys[dk_off + 4u] = t.h4;
    }
}
