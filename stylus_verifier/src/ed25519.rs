//! Pure-Rust FIPS 180-4 SHA-512 and IETF RFC 8032 Ed25519 Signature Verification & Signing
//! designed for compact WASM compilation on Arbitrum Stylus (`wasm32-unknown-unknown`).

// -----------------------------------------------------------------------------
// FIPS 180-4 SHA-512
// -----------------------------------------------------------------------------
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcBD41FBD4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

pub struct Sha512 {
    state: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            ],
            buf: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u128;
        if self.buf_len > 0 && self.buf_len + data.len() >= 128 {
            let take = 128 - self.buf_len;
            self.buf[self.buf_len..128].copy_from_slice(&data[..take]);
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
            data = &data[take..];
        }
        while data.len() >= 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[..128]);
            self.compress(&block);
            data = &data[128..];
        }
        if !data.is_empty() {
            self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
            self.buf_len += data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len * 8;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 112 {
            for b in &mut self.buf[self.buf_len..128] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf = [0u8; 128];
        } else {
            for b in &mut self.buf[self.buf_len..112] {
                *b = 0;
            }
        }
        self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..(i + 1) * 8]);
            w[i] = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..80 {
            let sigma1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(sigma1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let sigma0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sigma0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// -----------------------------------------------------------------------------
// GF(2^255 - 19) Field Arithmetic (5 x 51-bit limbs)
// -----------------------------------------------------------------------------
const MASK51: u64 = (1u64 << 51) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Self = Self([0, 0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let load8 = |offset: usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(b)
        };
        // Reject if top bit is not cleared by caller or value >= p
        let l0 = load8(0) & MASK51;
        let l1 = (load8(6) >> 3) & MASK51;
        let l2 = (load8(12) >> 6) & MASK51;
        let l3 = (load8(19) >> 1) & MASK51;
        let l4 = (load8(24) >> 12) & MASK51;

        let fe = Self([l0, l1, l2, l3, l4]);
        // Canonical check: re-serialize reduced form and compare exact low 255 bits
        let mut check = *bytes;
        check[31] &= 0x7f;
        if fe.to_bytes() != check {
            return None;
        }
        Some(fe)
    }

    fn to_bytes(self) -> [u8; 32] {
        let t = self.reduce_canonical();
        let mut s = [0u8; 32];
        let (l0, l1, l2, l3, l4) = (t.0[0], t.0[1], t.0[2], t.0[3], t.0[4]);

        s[0] = l0 as u8;
        s[1] = (l0 >> 8) as u8;
        s[2] = (l0 >> 16) as u8;
        s[3] = (l0 >> 24) as u8;
        s[4] = (l0 >> 32) as u8;
        s[5] = (l0 >> 40) as u8;
        s[6] = ((l0 >> 48) | (l1 << 3)) as u8;
        s[7] = (l1 >> 5) as u8;
        s[8] = (l1 >> 13) as u8;
        s[9] = (l1 >> 21) as u8;
        s[10] = (l1 >> 29) as u8;
        s[11] = (l1 >> 37) as u8;
        s[12] = ((l1 >> 45) | (l2 << 6)) as u8;
        s[13] = (l2 >> 2) as u8;
        s[14] = (l2 >> 10) as u8;
        s[15] = (l2 >> 18) as u8;
        s[16] = (l2 >> 26) as u8;
        s[17] = (l2 >> 34) as u8;
        s[18] = (l2 >> 42) as u8;
        s[19] = ((l2 >> 50) | (l3 << 1)) as u8;
        s[20] = (l3 >> 7) as u8;
        s[21] = (l3 >> 15) as u8;
        s[22] = (l3 >> 23) as u8;
        s[23] = (l3 >> 31) as u8;
        s[24] = (l3 >> 39) as u8;
        s[25] = ((l3 >> 47) | (l4 << 4)) as u8;
        s[26] = (l4 >> 4) as u8;
        s[27] = (l4 >> 12) as u8;
        s[28] = (l4 >> 20) as u8;
        s[29] = (l4 >> 28) as u8;
        s[30] = (l4 >> 36) as u8;
        s[31] = (l4 >> 44) as u8;
        s
    }

    fn reduce_canonical(self) -> Self {
        let mut h = self.0;
        for _ in 0..2 {
            let c0 = h[0] >> 51; h[1] += c0; h[0] &= MASK51;
            let c1 = h[1] >> 51; h[2] += c1; h[1] &= MASK51;
            let c2 = h[2] >> 51; h[3] += c2; h[2] &= MASK51;
            let c3 = h[3] >> 51; h[4] += c3; h[3] &= MASK51;
            let c4 = h[4] >> 51; h[0] += c4 * 19; h[4] &= MASK51;
        }
        // Conditional subtraction of p = (2^51 - 19, 2^51 - 1, 2^51 - 1, 2^51 - 1, 2^51 - 1)
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;

        h[0] += 19 * q;
        let c0 = h[0] >> 51; h[0] &= MASK51;
        h[1] += c0;
        let c1 = h[1] >> 51; h[1] &= MASK51;
        h[2] += c1;
        let c2 = h[2] >> 51; h[2] &= MASK51;
        h[3] += c2;
        let c3 = h[3] >> 51; h[3] &= MASK51;
        h[4] = (h[4] + c3) & MASK51;

        Self(h)
    }

    fn add(self, rhs: Self) -> Self {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ]).reduce_weak()
    }

    fn sub(self, rhs: Self) -> Self {
        // Add 2*p to avoid underflow
        const TWO_P0: u64 = 2 * (MASK51 - 18);
        const TWO_P: u64 = 2 * MASK51;
        Self([
            (self.0[0] + TWO_P0) - rhs.0[0],
            (self.0[1] + TWO_P) - rhs.0[1],
            (self.0[2] + TWO_P) - rhs.0[2],
            (self.0[3] + TWO_P) - rhs.0[3],
            (self.0[4] + TWO_P) - rhs.0[4],
        ]).reduce_weak()
    }

    fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    fn reduce_weak(self) -> Self {
        let mut h = self.0;
        let c0 = h[0] >> 51; h[1] += c0; h[0] &= MASK51;
        let c1 = h[1] >> 51; h[2] += c1; h[1] &= MASK51;
        let c2 = h[2] >> 51; h[3] += c2; h[2] &= MASK51;
        let c3 = h[3] >> 51; h[4] += c3; h[3] &= MASK51;
        let c4 = h[4] >> 51; h[0] += c4 * 19; h[4] &= MASK51;
        Self(h)
    }

    fn mul(self, rhs: Self) -> Self {
        let a = [self.0[0] as u128, self.0[1] as u128, self.0[2] as u128, self.0[3] as u128, self.0[4] as u128];
        let b = [rhs.0[0] as u128, rhs.0[1] as u128, rhs.0[2] as u128, rhs.0[3] as u128, rhs.0[4] as u128];
        let b19 = [0, b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];

        let mut c0 = a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1];
        let mut c1 = a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2];
        let mut c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3];
        let mut c3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4];
        let mut c4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];

        let m = MASK51 as u128;
        c1 += c0 >> 51; c0 &= m;
        c2 += c1 >> 51; c1 &= m;
        c3 += c2 >> 51; c2 &= m;
        c4 += c3 >> 51; c3 &= m;
        c0 += (c4 >> 51) * 19; c4 &= m;
        c1 += c0 >> 51; c0 &= m;

        Self([c0 as u64, c1 as u64, c2 as u64, c3 as u64, c4 as u64])
    }

    fn sq(self) -> Self {
        self.mul(self)
    }

    fn pow_u256_bits(self, exp_le: &[u8; 32]) -> Self {
        let mut res = Self::ONE;
        let mut base = self;
        for byte in exp_le.iter() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    res = res.mul(base);
                }
                base = base.sq();
            }
        }
        res
    }

    /// Computes a^(p - 2) mod p where p - 2 = 2^255 - 21.
    fn invert(self) -> Self {
        let mut exp = [0xffu8; 32];
        exp[0] = 0xeb; // 256 - 21 = 235 = 0xeb
        exp[31] = 0x7f;
        self.pow_u256_bits(&exp)
    }

    /// Computes a^((p + 3) / 8) mod p where (p + 3)/8 = 2^252 - 2.
    fn pow_p_plus_3_div_8(self) -> Self {
        let mut exp = [0xffu8; 32];
        exp[0] = 0xfe; // 256 - 2 = 254 = 0xfe
        exp[31] = 0x0f; // 2^252 - 1 has top byte 0x0f
        self.pow_u256_bits(&exp)
    }

    /// Computes sqrt(-1) = 2^((p - 1) / 4) mod p where (p - 1)/4 = 2^253 - 5.
    fn sqrt_m1() -> Self {
        let two = Self([2, 0, 0, 0, 0]);
        let mut exp = [0xffu8; 32];
        exp[0] = 0xfb; // 256 - 5 = 251 = 0xfb
        exp[31] = 0x1f;
        two.pow_u256_bits(&exp)
    }

    fn is_odd(self) -> u8 {
        self.to_bytes()[0] & 1
    }
}

// -----------------------------------------------------------------------------
// Extended Twisted Edwards Coordinates (X : Y : Z : T) where x = X/Z, y = Y/Z, x*y = T/Z
// -----------------------------------------------------------------------------
#[derive(Clone, Copy, Debug)]
struct GePoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl GePoint {
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    fn d_const() -> Fe {
        // d = -121665 / 121666 mod p
        let num = Fe([121665, 0, 0, 0, 0]).neg();
        let den = Fe([121666, 0, 0, 0, 0]).invert();
        num.mul(den)
    }

    fn basepoint() -> Self {
        // B_y = 4 / 5 mod p, sign_bit(B_x) = 0
        let y = Fe([4, 0, 0, 0, 0]).mul(Fe([5, 0, 0, 0, 0]).invert());
        let mut enc = y.to_bytes();
        enc[31] &= 0x7f;
        Self::from_bytes(&enc).expect("canonical Ed25519 basepoint")
    }

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let sign_bit = (bytes[31] >> 7) & 1;
        let y = Fe::from_bytes_canonical(bytes)?;
        let d = Self::d_const();
        let y2 = y.sq();
        let u = y2.sub(Fe::ONE);
        let v = d.mul(y2).add(Fe::ONE);
        let x2 = u.mul(v.invert());

        let mut x = x2.pow_p_plus_3_div_8();
        let check = x.sq().reduce_canonical();
        let target = x2.reduce_canonical();
        if check != target {
            let neg_target = x2.neg().reduce_canonical();
            if check == neg_target {
                x = x.mul(Fe::sqrt_m1());
            } else {
                return None;
            }
        }

        let x_canon = x.reduce_canonical();
        if x_canon == Fe::ZERO && sign_bit == 1 {
            return None;
        }
        if x_canon.is_odd() != sign_bit {
            x = x_canon.neg();
        }

        let t = x.mul(y);
        Some(Self { x, y, z: Fe::ONE, t })
    }

    fn to_bytes(self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(z_inv).reduce_canonical();
        let y = self.y.mul(z_inv).reduce_canonical();
        let mut out = y.to_bytes();
        out[31] |= x.is_odd() << 7;
        out
    }

    fn add(self, rhs: Self) -> Self {
        // Dedicated addition formula for a = -1 on twisted Edwards (Hisil et al. 2008):
        // A = (Y1-X1)*(Y2-X2), B = (Y1+X1)*(Y2+X2), C = T1*2*d*T2, D = Z1*2*Z2
        // E = B-A, F = D-C, G = D+C, H = B+A
        // X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
        let d2 = Self::d_const().add(Self::d_const());
        let a = self.y.sub(self.x).mul(rhs.y.sub(rhs.x));
        let b = self.y.add(self.x).mul(rhs.y.add(rhs.x));
        let c = self.t.mul(d2).mul(rhs.t);
        let d = self.z.add(self.z).mul(rhs.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn double(self) -> Self {
        self.add(self)
    }

    fn mul_by_8(self) -> Self {
        self.double().double().double()
    }

    fn scalar_mul_le(self, scalar_le: &[u8]) -> Self {
        let mut acc = Self::IDENTITY;
        let mut cur = self;
        for byte in scalar_le.iter() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    acc = acc.add(cur);
                }
                cur = cur.double();
            }
        }
        acc
    }

    fn equals_projective(self, rhs: Self) -> bool {
        // X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2  <=>  X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
        let x_eq = self.x.mul(rhs.z).reduce_canonical() == rhs.x.mul(self.z).reduce_canonical();
        let y_eq = self.y.mul(rhs.z).reduce_canonical() == rhs.y.mul(self.z).reduce_canonical();
        x_eq && y_eq
    }
}

// -----------------------------------------------------------------------------
// Subgroup Order L = 2^252 + 27742317777372353535851937790883648493
// -----------------------------------------------------------------------------
const ORDER_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn is_canonical_scalar(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if s[i] < ORDER_L_LE[i] {
            return true;
        }
        if s[i] > ORDER_L_LE[i] {
            return false;
        }
    }
    false // equal to L is non-canonical
}

/// Reduces a 64-byte little-endian integer modulo L (used for deterministic RFC 8032 signing).
pub fn reduce_scalar_mod_l(wide: &[u8; 64]) -> [u8; 32] {
    // Schoolbook division/modulo over 64 bytes in big-endian bit-by-bit shift-subtract
    let mut rem = [0u16; 33];
    for byte_idx in (0..64).rev() {
        let byte = wide[byte_idx];
        for bit in (0..8).rev() {
            // rem = (rem << 1) | bit
            let mut carry = ((byte >> bit) & 1) as u16;
            for r in rem.iter_mut() {
                let v = (*r << 1) | carry;
                *r = v & 0xff;
                carry = v >> 8;
            }
            // Compare rem >= L
            let mut ge = rem[32] > 0;
            if !ge {
                for i in (0..32).rev() {
                    if rem[i] > ORDER_L_LE[i] as u16 {
                        ge = true;
                        break;
                    }
                    if rem[i] < ORDER_L_LE[i] as u16 {
                        break;
                    }
                    if i == 0 {
                        ge = true;
                    }
                }
            }
            if ge {
                let mut borrow = 0i32;
                for i in 0..32 {
                    let diff = (rem[i] as i32) - (ORDER_L_LE[i] as i32) - borrow;
                    if diff < 0 {
                        rem[i] = (diff + 256) as u16;
                        borrow = 1;
                    } else {
                        rem[i] = diff as u16;
                        borrow = 0;
                    }
                }
                rem[32] = ((rem[32] as i32) - borrow) as u16;
            }
        }
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = rem[i] as u8;
    }
    out
}

/// Derives an RFC 8032 Ed25519 32-byte public key from a 32-byte secret seed.
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(seed);
    let mut digest = h.finalize();
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    GePoint::basepoint().scalar_mul_le(&scalar).to_bytes()
}

/// Signs `message` with a 32-byte RFC 8032 Ed25519 secret seed, returning a 64-byte signature `R || S`.
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(seed);
    let mut expanded = h.finalize();
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;

    let mut a_scalar = [0u8; 32];
    a_scalar.copy_from_slice(&expanded[..32]);
    let prefix = &expanded[32..64];
    let pubkey = GePoint::basepoint().scalar_mul_le(&a_scalar).to_bytes();

    let mut hr = Sha512::new();
    hr.update(prefix);
    hr.update(message);
    let r_scalar_wide = hr.finalize();
    let r_scalar = reduce_scalar_mod_l(&r_scalar_wide);
    let r_bytes = GePoint::basepoint().scalar_mul_le(&r_scalar).to_bytes();

    let mut hk = Sha512::new();
    hk.update(&r_bytes);
    hk.update(&pubkey);
    hk.update(message);
    let k_scalar = reduce_scalar_mod_l(&hk.finalize());

    // Compute S = (r + k * a) mod L via 64-byte product
    let mut prod = [0u8; 64];
    for i in 0..32 {
        let mut carry = 0u32;
        for j in 0..32 {
            let v = (prod[i + j] as u32) + (k_scalar[i] as u32) * (a_scalar[j] as u32) + carry;
            prod[i + j] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        prod[i + 32] = carry as u8;
    }
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = (prod[i] as u16) + (r_scalar[i] as u16) + carry;
        prod[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    for i in 32..64 {
        let sum = (prod[i] as u16) + carry;
        prod[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    let s_bytes = reduce_scalar_mod_l(&prod);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..64].copy_from_slice(&s_bytes);
    sig
}

/// Verifies an RFC 8032 Ed25519 signature (`[8][S]B == [8]R + [8][k]A`) with strict canonical `S < L` check.
pub fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    s_bytes.copy_from_slice(&signature[32..64]);

    if !is_canonical_scalar(&s_bytes) {
        return false;
    }

    let a_point = match GePoint::from_bytes(pubkey) {
        Some(p) => p,
        None => return false,
    };
    let r_point = match GePoint::from_bytes(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    let mut hk = Sha512::new();
    hk.update(&r_bytes);
    hk.update(pubkey);
    hk.update(message);
    let k_wide = hk.finalize();

    // Cofactored verification: [8]([S]B) == [8]R + ([k]([8]A))
    // Since #[E(Fp)] = 8*L, [8]A has order dividing L, so [k_wide]([8]A) == [k_wide mod L]([8]A).
    let lhs = GePoint::basepoint().mul_by_8().scalar_mul_le(&s_bytes);
    let rhs = r_point.mul_by_8().add(a_point.mul_by_8().scalar_mul_le(&k_wide));

    lhs.equals_projective(rhs)
}
