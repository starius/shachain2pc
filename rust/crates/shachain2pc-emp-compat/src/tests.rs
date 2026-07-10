use super::*;
use serde_json::Value;
use shachain2pc_circuit::{
    build_chunk_circuit, build_tile_circuit, sha256_compress_gadget, Gate, CACHE_TILE_HEIGHT,
};
use shachain2pc_emp_wire::EmpStream;
use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
#[cfg(feature = "cpp-probes")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "cpp-probes")]
use std::process::{Command, Stdio};
#[cfg(feature = "cpp-probes")]
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

const LIVE_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);
const TRANSPOSE_ROWS: usize = 128;
const LIVE_SOFTSPOKEN_LENGTH: usize = 2051;
const LIVE_AG2PC_DRAW_LENGTH: usize = 257;
#[cfg(feature = "cpp-probes")]
const LIVE_AG2PC_COMPUTE_LENGTH: usize = 35;
#[cfg(feature = "cpp-probes")]
static LIVE_CPP_INTEROP_LOCK: Mutex<()> = Mutex::const_new(());

#[test]
fn transpose_128_rows_matches_bit_reference() {
    for row_bytes in [1usize, 16, 32, 256] {
        let output_len = row_bytes * 8;
        let mut rows = vec![0u8; TRANSPOSE_ROWS * row_bytes];
        for (i, byte) in rows.iter_mut().enumerate() {
            *byte = ((i * 37 + i / 7 + 0x5a) & 0xff) as u8;
        }
        let reference = transpose_128_rows_bit_reference(&rows, row_bytes, output_len);
        // transpose_128_rows is the portable-SIMD path; compare it and the
        // scalar reference against the independent bit reference.
        assert_eq!(transpose_128_rows(&rows, row_bytes, output_len), reference);
        assert_eq!(
            transpose_128_rows_soft(&rows, row_bytes, output_len),
            reference
        );
    }
}

fn transpose_128_rows_bit_reference(
    rows: &[u8],
    row_bytes: usize,
    output_len: usize,
) -> Vec<Block> {
    let mut out = vec![Block::zero(); output_len];
    for (col, out_block) in out.iter_mut().enumerate() {
        let mut bytes = [0u8; BLOCK_BYTES];
        let source_byte = col / 8;
        let source_mask = 1 << (col % 8);
        for row in 0..TRANSPOSE_ROWS {
            if (rows[row * row_bytes + source_byte] & source_mask) != 0 {
                bytes[row / 8] |= 1 << (row % 8);
            }
        }
        *out_block = Block::from_bytes(bytes);
    }
    out
}

#[derive(Clone, Copy, Debug)]
#[cfg(feature = "cpp-probes")]
enum TestTransport {
    Listen,
    Connect,
}

#[derive(Clone, Copy, Debug)]
#[cfg(feature = "cpp-probes")]
enum TestOtRole {
    Send,
    Recv,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

#[cfg(feature = "cpp-probes")]
fn cpp_root() -> PathBuf {
    repo_root().join("cpp")
}

fn fixture_records() -> Vec<Value> {
    let path = repo_root().join("compat/v1/probes/cpp-compat-probe.jsonl");
    let data = std::fs::read_to_string(path).unwrap();
    data.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn hex_decode(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn block_from_hex(input: &str) -> Block {
    let bytes: [u8; 16] = hex_decode(input).try_into().unwrap();
    Block::from_bytes(bytes)
}

fn block_array_from_json(value: &Value) -> Vec<Block> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| block_from_hex(v.as_str().unwrap()))
        .collect()
}

fn block_json(block: Block) -> String {
    hex_encode(block.as_bytes())
}

fn blocks_digest_json(blocks: &[Block]) -> String {
    let mut hasher = Sha256::new();
    for block in blocks {
        hasher.update(block.as_bytes());
    }
    hex_encode(&hasher.finalize())
}

fn assert_block_json_array(fixture: &Value, name: &str, blocks: &[Block]) {
    let expected = fixture[name].as_array().unwrap();
    assert_eq!(expected.len(), blocks.len(), "{name} length mismatch");
    for (i, block) in blocks.iter().enumerate() {
        assert_eq!(
            block_json(*block),
            expected[i].as_str().unwrap(),
            "{name}[{i}]"
        );
    }
}

fn blocks_bytes(blocks: &[Block]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len() * BLOCK_BYTES);
    for block in blocks {
        out.extend_from_slice(block.as_bytes());
    }
    out
}

fn csw_pad(sid: Block, i: usize, point: &[u8]) -> Block {
    EmpRo::new("emp-ot:csw-base-ot:pad", sid)
        .absorb_u64(i as u64)
        .absorb_point(point)
        .squeeze_block()
}

fn csw_short(sid: Block, block: Block) -> Block {
    EmpRo::new("emp-ot:csw-base-ot:short", sid)
        .absorb_block(block)
        .squeeze_block()
}

fn csw_data0(i: usize) -> Block {
    Block::make(0x1000_0000_0000_0000 | i as u64, 0x100 | i as u64)
}

fn csw_data1(i: usize) -> Block {
    Block::make(0x2000_0000_0000_0000 | i as u64, 0x200 | i as u64)
}

fn csw_choice(i: usize) -> bool {
    ((i * 7 + 3) % 11) < 5
}

#[cfg(feature = "cpp-probes")]
fn opposite_role(role: Role) -> Role {
    match role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    }
}

fn ag2pc_test_circuit() -> Circuit {
    Circuit {
        num_wire: 8,
        n1: 3,
        n2: 2,
        n3: 1,
        gates: vec![
            Gate {
                typ: GateType::And,
                in0: 0,
                in1: 3,
                out: 5,
            },
            Gate {
                typ: GateType::Xor,
                in0: 1,
                in1: 4,
                out: 6,
            },
            Gate {
                typ: GateType::And,
                in0: 5,
                in1: 6,
                out: 7,
            },
        ],
    }
}

fn ag2pc_test_input() -> [u8; 5] {
    [1, 0, 1, 1, 1]
}

fn ag2pc_expected_output() -> [u8; 1] {
    [1]
}

#[test]
fn ag2pc_bool_packing_is_compact_lsb_first() {
    for len in 0usize..20 {
        let data: Vec<u8> = (0..len).map(|i| ((i * 5 + 1) & 1) as u8).collect();
        let packed = ag2pc_pack_bools(&data);
        assert_eq!(packed.len(), len.div_ceil(8));
        assert_eq!(ag2pc_unpack_bools(&packed, len), data);
        for i in len..packed.len() * 8 {
            assert_eq!((packed[i / 8] >> (i % 8)) & 1, 0);
        }
    }

    assert_eq!(
        ag2pc_pack_bools(&[1, 0, 1, 1, 0, 0, 1, 0, 1]),
        vec![0x4d, 0x01]
    );
}

#[test]
fn softspoken_helpers_match_cpp_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../compat/ag2pc/softspoken-helper-v1.json"
    ))
    .unwrap();
    let k = fixture["k"].as_u64().unwrap() as usize;
    let bs = fixture["bs"].as_u64().unwrap() as usize;
    let alpha_field = fixture["alpha_field"].as_u64().unwrap() as usize;
    let session_id = fixture["session_id"].as_u64().unwrap();
    let counter_base = fixture["counter_base"].as_u64().unwrap();

    let delta = Block::make(0x0112_2334_4556_6778, 0x899a_abbc_cdde_eff1);
    let root = Block::make(0x0103_0507_090b_0d0f, 0x1113_1517_191b_1d1f);
    let (sender_leaves, k0) = cggm_build_sender(k, delta, root, false);

    let alpha_path = cggm_bit_reverse(alpha_field as u32, k) as usize;
    assert_eq!(alpha_path, fixture["alpha_path"].as_u64().unwrap() as usize);
    let recv_keys: Vec<Block> = (1..=k)
        .map(|level| {
            let alpha_i = ((alpha_path >> (k - level)) & 1) != 0;
            let alpha_bar_i = !alpha_i;
            if alpha_bar_i {
                k0[level - 1].xor(delta)
            } else {
                k0[level - 1]
            }
        })
        .collect();
    let receiver_leaves = cggm_eval_receiver(k, alpha_path, &recv_keys, false);
    let (sfvole_u, sfvole_v) =
        sfvole_sender_butterfly(k, &sender_leaves, counter_base, bs, session_id);
    let sfvole_w = sfvole_receiver_butterfly(
        k,
        alpha_field,
        &receiver_leaves,
        counter_base,
        bs,
        session_id,
    );

    assert_block_json_array(&fixture, "k0", &k0);
    assert_block_json_array(&fixture, "recv_keys", &recv_keys);
    assert_block_json_array(&fixture, "sender_leaves", &sender_leaves);
    assert_block_json_array(&fixture, "receiver_leaves", &receiver_leaves);
    assert_block_json_array(&fixture, "sfvole_u", &sfvole_u);
    assert_block_json_array(&fixture, "sfvole_v", &sfvole_v);
    assert_block_json_array(&fixture, "sfvole_w", &sfvole_w);
}

#[test]
fn csw_helper_transcript_matches_cpp_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../../compat/ag2pc/csw-helper-v1.json")).unwrap();
    let group = P256::new().unwrap();
    let sid = Block::zero();
    let seed = Block::make(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
    let t = EmpRo::new("emp-ot:csw-base-ot:to-curve", sid)
        .absorb_block(seed)
        .squeeze_p256_point()
        .unwrap();
    assert_eq!(hex_encode(&t), fixture["T"].as_str().unwrap());

    let r = 0x12345;
    let z = group.mul_gen(r).unwrap();
    assert_eq!(hex_encode(&z), fixture["z"].as_str().unwrap());
    let t_r_neg = group.point_inv(&group.point_mul(&t, r).unwrap()).unwrap();

    let length = fixture["length"].as_u64().unwrap() as usize;
    let mut b_points = Vec::with_capacity(length);
    let mut p0 = Vec::with_capacity(length);
    let mut p1 = Vec::with_capacity(length);
    let mut h0 = Vec::with_capacity(length);
    let mut chi = Vec::with_capacity(length);
    let mut c0 = Vec::with_capacity(length);
    let mut c1 = Vec::with_capacity(length);
    let mut recovered = Vec::with_capacity(length);

    for i in 0..length {
        let alpha = 0x2000 + i as u64 * 17;
        let mut b = group.mul_gen(alpha).unwrap();
        if csw_choice(i) {
            b = group.point_add(&b, &t).unwrap();
        }
        let rho0 = group.point_mul(&b, r).unwrap();
        let rho1 = group.point_add(&rho0, &t_r_neg).unwrap();
        let pad0 = csw_pad(sid, i, &rho0);
        let pad1 = csw_pad(sid, i, &rho1);
        p0.push(pad0);
        p1.push(pad1);
        h0.push(csw_short(sid, pad0));
        b_points.push(b);
    }

    let otans = EmpRo::new("emp-ot:csw-base-ot:agg", sid)
        .absorb_bytes(&blocks_bytes(&h0))
        .squeeze_block();
    let proof = csw_short(sid, otans);
    assert_eq!(block_json(otans), fixture["otans"].as_str().unwrap());
    assert_eq!(block_json(proof), fixture["proof"].as_str().unwrap());

    for i in 0..length {
        let h1 = csw_short(sid, p1[i]);
        chi.push(h0[i].xor(h1));
        c0.push(p0[i].xor(csw_data0(i)));
        c1.push(p1[i].xor(csw_data1(i)));

        let alpha = 0x2000 + i as u64 * 17;
        let z_alpha = group.point_mul(&z, alpha).unwrap();
        let p_bi = csw_pad(sid, i, &z_alpha);
        recovered.push(p_bi.xor(if csw_choice(i) { c1[i] } else { c0[i] }));
    }

    assert_eq!(
        hex_encode(&b_points[0]),
        fixture["B_first"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(b_points.last().unwrap()),
        fixture["B_last"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&p0),
        fixture["p0_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&p1),
        fixture["p1_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&h0),
        fixture["h0_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&chi),
        fixture["chi_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&c0),
        fixture["c0_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&c1),
        fixture["c1_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&recovered),
        fixture["recovered_digest"].as_str().unwrap()
    );
    assert_eq!(block_json(p0[0]), fixture["p0_first"].as_str().unwrap());
    assert_eq!(block_json(p1[0]), fixture["p1_first"].as_str().unwrap());
    assert_eq!(block_json(chi[0]), fixture["chi_first"].as_str().unwrap());
    assert_eq!(block_json(c0[0]), fixture["c0_first"].as_str().unwrap());
    assert_eq!(block_json(c1[0]), fixture["c1_first"].as_str().unwrap());
    assert_eq!(
        block_json(recovered[0]),
        fixture["recovered_first"].as_str().unwrap()
    );
    assert_eq!(
        block_json(*recovered.last().unwrap()),
        fixture["recovered_last"].as_str().unwrap()
    );
    for (i, block) in recovered.iter().enumerate() {
        let expected = if csw_choice(i) {
            csw_data1(i)
        } else {
            csw_data0(i)
        };
        assert_eq!(*block, expected, "CSW recovered[{i}]");
    }
}

#[test]
fn mitccrh_helper_matches_cpp_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../compat/ag2pc/mitccrh-helper-v1.json"
    ))
    .unwrap();
    let seed = Block::make(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);

    let mut h8 = Mitccrh8::new(seed);
    let mut hash_8x2: Vec<Block> = (0..16)
        .map(|i| Block::make(0x1000_0000_0000_0000 | i, 0x2000_0000_0000_0000 | i))
        .collect();
    let mut hash_8x2_second: Vec<Block> = (0..16)
        .map(|i| Block::make(0x3000_0000_0000_0000 | i, 0x4000_0000_0000_0000 | i))
        .collect();
    h8.hash(&mut hash_8x2, 8, 2);
    h8.hash(&mut hash_8x2_second, 8, 2);

    let mut h4 = Mitccrh8::new(seed);
    let mut hash_4x2_first: Vec<Block> = (0..8)
        .map(|i| Block::make(0x5000_0000_0000_0000 | i, 0x6000_0000_0000_0000 | i))
        .collect();
    let mut hash_4x2_second: Vec<Block> = (0..8)
        .map(|i| Block::make(0x7000_0000_0000_0000 | i, 0x8000_0000_0000_0000 | i))
        .collect();
    h4.hash(&mut hash_4x2_first, 4, 2);
    h4.hash(&mut hash_4x2_second, 4, 2);

    let mut hc = Mitccrh8::new(seed);
    let mut hash_cir_8x2: Vec<Block> = (0..16)
        .map(|i| Block::make(0x9000_0000_0000_0000 | i, 0xa000_0000_0000_0000 | i))
        .collect();
    hc.hash_cir(&mut hash_cir_8x2, 8, 2);

    assert_block_json_array(&fixture, "hash_8x2", &hash_8x2);
    assert_block_json_array(&fixture, "hash_8x2_second", &hash_8x2_second);
    assert_block_json_array(&fixture, "hash_4x2_first", &hash_4x2_first);
    assert_block_json_array(&fixture, "hash_4x2_second", &hash_4x2_second);
    assert_block_json_array(&fixture, "hash_cir_8x2", &hash_cir_8x2);
    assert_eq!(
        blocks_digest_json(&hash_8x2),
        fixture["hash_8x2_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&hash_8x2_second),
        fixture["hash_8x2_second_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&hash_4x2_first),
        fixture["hash_4x2_first_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&hash_4x2_second),
        fixture["hash_4x2_second_digest"].as_str().unwrap()
    );
    assert_eq!(
        blocks_digest_json(&hash_cir_8x2),
        fixture["hash_cir_8x2_digest"].as_str().unwrap()
    );
}

#[test]
fn emp_hash_fixture_matches_cpp() {
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "emp_hash")
    {
        let msg = hex_decode(record["inputs"]["message_hex"].as_str().unwrap());
        assert_eq!(
            hex_encode(&hash_once(&msg)),
            record["outputs"]["sha256"].as_str().unwrap()
        );
    }
}

#[test]
fn emp_prp_fixture_matches_cpp() {
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "emp_prp")
    {
        let key = block_from_hex(record["inputs"]["key"].as_str().unwrap());
        let mut blocks = block_array_from_json(&record["inputs"]["blocks"]);
        Prp::new(key).permute_block(&mut blocks);
        let got: Vec<String> = blocks.into_iter().map(block_json).collect();
        let expected: Vec<String> = record["outputs"]["permuted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(got, expected);
    }
}

#[test]
fn emp_prg_fixture_matches_cpp() {
    let record = fixture_records()
        .into_iter()
        .find(|r| r["probe"] == "emp_prg" && r["case"] == "seeded")
        .unwrap();
    let seed = block_from_hex(record["inputs"]["seed"].as_str().unwrap());
    let id = record["inputs"]["id"].as_u64().unwrap();
    let mut prg = Prg::new(seed, id);

    let blocks: Vec<String> = prg.random_block(5).into_iter().map(block_json).collect();
    let expected_blocks: Vec<String> = record["outputs"]["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(blocks, expected_blocks);

    assert_eq!(
        hex_encode(&prg.random_data(23)),
        record["outputs"]["random_data_23"].as_str().unwrap()
    );

    let bools = prg.random_bool_aligned(17);
    let expected_bools: Vec<bool> = record["outputs"]["random_bool_17"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_bool().unwrap())
        .collect();
    assert_eq!(bools, expected_bools);
}

#[test]
fn emp_garble_hash_fixture_matches_cpp() {
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "emp_garble_hash")
    {
        let a = block_from_hex(record["inputs"]["a"].as_str().unwrap());
        let b = block_from_hex(record["inputs"]["b"].as_str().unwrap());
        let gate_index = record["inputs"]["gate_index"].as_u64().unwrap();
        if record["case"] == "preprocess_4x2" {
            let delta = block_from_hex(record["inputs"]["delta"].as_str().unwrap());
            let rows = garble_hash_preprocess(a, b, delta, gate_index);
            for (row, expected_row) in rows
                .iter()
                .zip(record["outputs"]["rows"].as_array().unwrap())
            {
                let expected = expected_row.as_array().unwrap();
                assert_eq!(block_json(row[0]), expected[0].as_str().unwrap());
                assert_eq!(block_json(row[1]), expected[1].as_str().unwrap());
            }
        } else {
            let row = record["inputs"]["row"].as_u64().unwrap();
            let blocks = garble_hash_online(a, b, gate_index, row);
            let expected = record["outputs"]["blocks"].as_array().unwrap();
            assert_eq!(block_json(blocks[0]), expected[0].as_str().unwrap());
            assert_eq!(block_json(blocks[1]), expected[1].as_str().unwrap());
        }
    }
}

#[test]
fn emp_point_fixture_matches_cpp() {
    let group = P256::new().unwrap();
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "emp_point")
    {
        let scalar = record["inputs"]["scalar"].as_u64().unwrap();
        let point = group.mul_gen(scalar).unwrap();
        assert_eq!(
            hex_encode(&point),
            record["outputs"]["point"].as_str().unwrap()
        );
        assert_eq!(
            hex_encode(&group.send_pt_bytes(&point).unwrap()),
            record["outputs"]["send_pt"].as_str().unwrap()
        );
        assert_eq!(
            block_json(group.kdf(&point, 1).unwrap()),
            record["outputs"]["kdf_id_1"].as_str().unwrap()
        );
        assert_eq!(
            block_json(group.kdf(&point, 42).unwrap()),
            record["outputs"]["kdf_id_42"].as_str().unwrap()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_csw_base_ot_roundtrip() {
    let port = free_port();
    let choices: Vec<bool> = (0..80).map(csw_choice).collect();
    let expected: Vec<Block> = choices
        .iter()
        .enumerate()
        .map(|(i, choice)| if *choice { csw_data1(i) } else { csw_data0(i) })
        .collect();
    let receiver_choices = choices.clone();
    let receiver = tokio::spawn(async move {
        let mut stream = EmpStream::listen(port).await.unwrap();
        csw_recv(&mut stream, &receiver_choices).await.unwrap()
    });

    let data0: Vec<Block> = (0..80).map(csw_data0).collect();
    let data1: Vec<Block> = (0..80).map(csw_data1).collect();
    let mut sender = EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        .await
        .unwrap();
    csw_send(&mut sender, &data0, &data1).await.unwrap();

    let out = timeout(LIVE_INTEROP_TIMEOUT, receiver)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_softspoken4_roundtrip() {
    let port = free_port();
    let alice = tokio::spawn(async move {
        let mut stream = EmpStream::listen(port).await.unwrap();
        let mut soft = SoftSpoken4::new(Role::Alice, true).unwrap();
        let out = soft.run(&mut stream, LIVE_SOFTSPOKEN_LENGTH).await.unwrap();
        (soft.delta(), out)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(async move {
        let mut stream = EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .await
            .unwrap();
        let mut soft = SoftSpoken4::new(Role::Bob, true).unwrap();
        soft.run(&mut stream, LIVE_SOFTSPOKEN_LENGTH).await.unwrap()
    });
    let ((delta, sender), receiver) = timeout(LIVE_INTEROP_TIMEOUT, async {
        (alice.await.unwrap(), bob.await.unwrap())
    })
    .await
    .unwrap();
    assert_softspoken_relation(&receiver, delta, &sender);
}

#[test]
fn softspoken_trim_drops_leftover_without_resetting_setup() {
    let mut soft = SoftSpoken4::new(Role::Bob, true).unwrap();
    soft.setup_done = true;
    soft.session = 17;
    soft.cur_send_session = 5;
    soft.cur_recv_session = 6;
    soft.leaves_send = vec![Block::make(1, 2); 4];
    soft.leaves_recv = vec![Block::make(3, 4); 4];
    soft.leftover = vec![Block::make(5, 6); 8];
    soft.leftover_pos = 2;
    soft.leftover_count = 6;

    soft.trim_idle_allocations();

    assert!(soft.leftover.is_empty());
    assert_eq!(soft.leftover_pos, 0);
    assert_eq!(soft.leftover_count, 0);
    assert!(soft.setup_done);
    assert_eq!(soft.session, 17);
    assert_eq!(soft.cur_send_session, 5);
    assert_eq!(soft.cur_recv_session, 6);
    assert_eq!(soft.leaves_send, vec![Block::make(1, 2); 4]);
    assert_eq!(soft.leaves_recv, vec![Block::make(3, 4); 4]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_ag2pc_triple_pool_draw_roundtrip() {
    let port = free_port();
    let alice = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Alice, 40)
            .await
            .unwrap();
        let bundle = pool
            .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
            .await
            .unwrap();
        pool.flush_cot_check(&mut streams).await.unwrap();
        (pool.delta(), bundle)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Bob, 40)
            .await
            .unwrap();
        let bundle = pool
            .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
            .await
            .unwrap();
        pool.flush_cot_check(&mut streams).await.unwrap();
        (pool.delta(), bundle)
    });
    let ((alice_delta, alice_bundle), (bob_delta, bob_bundle)) =
        timeout(LIVE_INTEROP_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
    assert!(verify_ag2pc_share_relation(
        &alice_bundle,
        alice_delta,
        &bob_bundle,
        bob_delta
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_ag2pc_protocol_process_inputs_and_decode_roundtrip() {
    let port = free_port();
    let alice = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        run_rust_ag2pc_protocol_script(&mut streams, Role::Alice)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        run_rust_ag2pc_protocol_script(&mut streams, Role::Bob)
            .await
            .unwrap()
    });
    let (alice_out, bob_out) = timeout(LIVE_INTEROP_TIMEOUT, async {
        (alice.await.unwrap(), bob.await.unwrap())
    })
    .await
    .unwrap();
    assert_eq!(alice_out, bob_out);
    assert_eq!(alice_out, vec![1, 0, 1, 1, 0, 1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_ag2pc_compute_inplace_random_masks_roundtrip() {
    let port = free_port();
    let alice = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Alice, 40)
            .await
            .unwrap();
        let rep_a = pool
            .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
            .await
            .unwrap();
        let rep_b = pool
            .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
            .await
            .unwrap();
        let sigma = pool
            .compute_inplace(&mut streams, &rep_a, &rep_b)
            .await
            .unwrap();
        pool.flush_cot_check(&mut streams).await.unwrap();
        (pool.delta(), rep_a, rep_b, sigma)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        let mut pool = Ag2pcTriplePool::setup(&mut streams, Role::Bob, 40)
            .await
            .unwrap();
        let rep_a = pool
            .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
            .await
            .unwrap();
        let rep_b = pool
            .draw(&mut streams, LIVE_AG2PC_DRAW_LENGTH)
            .await
            .unwrap();
        let sigma = pool
            .compute_inplace(&mut streams, &rep_a, &rep_b)
            .await
            .unwrap();
        pool.flush_cot_check(&mut streams).await.unwrap();
        (pool.delta(), rep_a, rep_b, sigma)
    });
    let ((alice_delta, alice_a, alice_b, alice_sigma), (bob_delta, bob_a, bob_b, bob_sigma)) =
        timeout(LIVE_INTEROP_TIMEOUT, async {
            (alice.await.unwrap(), bob.await.unwrap())
        })
        .await
        .unwrap();
    assert!(verify_ag2pc_share_relation(
        &alice_sigma,
        alice_delta,
        &bob_sigma,
        bob_delta
    ));
    for i in 0..LIVE_AG2PC_DRAW_LENGTH {
        let a = block_lsb(alice_a[i].mac) ^ block_lsb(bob_a[i].mac);
        let b = block_lsb(alice_b[i].mac) ^ block_lsb(bob_b[i].mac);
        let sigma = block_lsb(alice_sigma[i].mac) ^ block_lsb(bob_sigma[i].mac);
        assert_eq!(sigma, a & b, "sigma relation mismatch at {i}");
    }
}

#[test]
fn ag2pc_program_gate_stays_packed() {
    assert_eq!(std::mem::size_of::<Ag2pcProgramGate>(), 8);
}

#[test]
fn ag2pc_direct_chunk_program_matches_circuit_path() {
    let sha = sha256_compress_gadget().unwrap();
    for (bits, first) in [
        (vec![47usize], true),
        (vec![47usize, 46, 45], true),
        (vec![3usize, 1], false),
    ] {
        let circuit = build_chunk_circuit(&sha, &bits, first).unwrap();
        let via_circuit = Ag2pcProgram::from_circuit(&circuit).unwrap();
        let direct = Ag2pcProgram::chunk_from_sha(&sha, &bits, first).unwrap();
        assert_eq!(direct, via_circuit);
    }
}

#[test]
fn ag2pc_direct_tile_program_matches_circuit_path() {
    let sha = sha256_compress_gadget().unwrap();
    for (offset, height) in [(0usize, 1usize), (0, CACHE_TILE_HEIGHT), (8, 3)] {
        let circuit = build_tile_circuit(&sha, offset, height).unwrap();
        let via_circuit = Ag2pcProgram::from_circuit(&circuit).unwrap();
        let direct = Ag2pcProgram::tile_from_sha(&sha, offset, height).unwrap();
        assert_eq!(direct, via_circuit);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_ag2pc_program_roundtrip() {
    let port = free_port();
    let alice = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Alice, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        run_rust_ag2pc_program_script(&mut streams, Role::Alice)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bob = tokio::spawn(async move {
        let mut streams = Ag2pcStreams::open(Role::Bob, port, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        run_rust_ag2pc_program_script(&mut streams, Role::Bob)
            .await
            .unwrap()
    });
    let (alice_out, bob_out) = timeout(LIVE_INTEROP_TIMEOUT, async {
        (alice.await.unwrap(), bob.await.unwrap())
    })
    .await
    .unwrap();
    assert_eq!(alice_out, ag2pc_expected_output());
    assert_eq!(bob_out, ag2pc_expected_output());
}

#[cfg(feature = "cpp-probes")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_cpp_csw_base_ot_interop() {
    let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
    let bin = cpp_csw_probe();
    for transport in [TestTransport::Listen, TestTransport::Connect] {
        run_live_csw_case(&bin, transport, TestOtRole::Send).await;
        run_live_csw_case(&bin, transport, TestOtRole::Recv).await;
    }
}

#[cfg(feature = "cpp-probes")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_cpp_softspoken4_interop() {
    let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
    let bin = cpp_softspoken_probe();
    run_live_softspoken_case(&bin, Role::Alice).await;
    run_live_softspoken_case(&bin, Role::Bob).await;
}

#[cfg(feature = "cpp-probes")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_cpp_ag2pc_triple_pool_draw_interop() {
    let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
    let bin = cpp_ag2pc_triple_pool_probe();
    run_live_ag2pc_triple_pool_case(&bin, Role::Alice).await;
    run_live_ag2pc_triple_pool_case(&bin, Role::Bob).await;
}

#[cfg(feature = "cpp-probes")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_cpp_ag2pc_protocol_interop() {
    let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
    let bin = cpp_ag2pc_protocol_probe();
    run_live_ag2pc_protocol_case(&bin, Role::Alice).await;
    run_live_ag2pc_protocol_case(&bin, Role::Bob).await;
}

#[cfg(feature = "cpp-probes")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_cpp_ag2pc_compute_inplace_interop() {
    let _guard = LIVE_CPP_INTEROP_LOCK.lock().await;
    let bin = cpp_ag2pc_compute_probe();
    run_live_ag2pc_compute_case(&bin, Role::Alice).await;
    run_live_ag2pc_compute_case(&bin, Role::Bob).await;
}

#[cfg(feature = "cpp-probes")]
async fn run_live_csw_case(bin: &Path, rust_transport: TestTransport, rust_role: TestOtRole) {
    let port = free_port();
    let cpp_transport = match rust_transport {
        TestTransport::Listen => "connect",
        TestTransport::Connect => "listen",
    };
    let cpp_role = match rust_role {
        TestOtRole::Send => "recv",
        TestOtRole::Recv => "send",
    };
    let child = Command::new(bin)
        .current_dir(cpp_root())
        .arg(cpp_transport)
        .arg(port.to_string())
        .arg(cpp_role)
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if matches!(rust_transport, TestTransport::Connect) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut stream = open_stream(rust_transport, port).await.unwrap();
    let result = timeout(LIVE_INTEROP_TIMEOUT, run_rust_csw(&mut stream, rust_role)).await;
    let output = child.wait_with_output().unwrap();
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!(
            "Rust CSW failed: {e}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(_) => panic!(
            "Rust CSW timed out\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    }
    assert!(
        output.status.success(),
        "C++ CSW probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "cpp-probes")]
async fn run_live_softspoken_case(bin: &Path, rust_role: Role) {
    let port = free_port();
    let cpp_role = opposite_role(rust_role);
    let mut child = Command::new(bin)
        .current_dir(cpp_root())
        .arg(cpp_role.party_id().to_string())
        .arg(port.to_string())
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if rust_role == Role::Bob {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut stream = if rust_role == Role::Alice {
        EmpStream::listen(port).await.unwrap()
    } else {
        EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .await
            .unwrap()
    };
    let result = timeout(
        LIVE_INTEROP_TIMEOUT,
        run_rust_softspoken_peer(&mut stream, rust_role),
    )
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust SoftSpoken failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust SoftSpoken timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "C++ SoftSpoken probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "cpp-probes")]
async fn run_live_ag2pc_triple_pool_case(bin: &Path, rust_role: Role) {
    let port = free_port();
    let cpp_role = opposite_role(rust_role);
    let mut child = Command::new(bin)
        .current_dir(cpp_root())
        .arg(cpp_role.party_id().to_string())
        .arg(port.to_string())
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if rust_role == Role::Bob {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stream_result = timeout(
        LIVE_INTEROP_TIMEOUT,
        Ag2pcStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
    )
    .await;
    let mut streams = match stream_result {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC triple-pool stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC triple-pool stream open timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };
    let result = timeout(
        LIVE_INTEROP_TIMEOUT,
        run_rust_ag2pc_triple_pool_peer(&mut streams, rust_role),
    )
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC triple-pool failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC triple-pool timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "C++ AG2PC triple-pool probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "cpp-probes")]
async fn run_live_ag2pc_protocol_case(bin: &Path, rust_role: Role) {
    let port = free_port();
    let cpp_role = opposite_role(rust_role);
    let mut child = Command::new(bin)
        .current_dir(cpp_root())
        .arg(cpp_role.party_id().to_string())
        .arg(port.to_string())
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if rust_role == Role::Bob {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stream_result = timeout(
        LIVE_INTEROP_TIMEOUT,
        Ag2pcStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
    )
    .await;
    let mut streams = match stream_result {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC protocol stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC protocol stream open timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };
    let result = timeout(
        LIVE_INTEROP_TIMEOUT,
        run_rust_ag2pc_protocol_script(&mut streams, rust_role),
    )
    .await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC protocol failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC protocol timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "C++ AG2PC protocol probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "cpp-probes")]
async fn run_live_ag2pc_compute_case(bin: &Path, rust_role: Role) {
    let port = free_port();
    let cpp_role = opposite_role(rust_role);
    let mut child = Command::new(bin)
        .current_dir(cpp_root())
        .arg(cpp_role.party_id().to_string())
        .arg(port.to_string())
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if rust_role == Role::Bob {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stream_result = timeout(
        LIVE_INTEROP_TIMEOUT,
        Ag2pcStreams::open(rust_role, port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
    )
    .await;
    let mut streams = match stream_result {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC compute stream open failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC compute stream open timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };
    let result = timeout(
        LIVE_INTEROP_TIMEOUT,
        run_rust_ag2pc_compute_peer(&mut streams, rust_role),
    )
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC compute failed: {e}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "Rust AG2PC compute timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "C++ AG2PC compute probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "cpp-probes")]
async fn open_stream(transport: TestTransport, port: u16) -> Result<EmpStream> {
    match transport {
        TestTransport::Listen => EmpStream::listen(port).await.map_err(Into::into),
        TestTransport::Connect => EmpStream::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .await
            .map_err(Into::into),
    }
}

#[cfg(feature = "cpp-probes")]
async fn run_rust_softspoken_peer(stream: &mut EmpStream, role: Role) -> Result<()> {
    let mut soft = SoftSpoken4::new(role, true)?;
    let out = soft.run(stream, LIVE_SOFTSPOKEN_LENGTH).await?;
    if role == Role::Alice {
        stream.send_block(&[soft.delta()]).await?;
        stream.send_block(&out).await?;
        stream.flush().await?;
        let ok = stream.recv_data(1).await?[0];
        assert_eq!(ok, 1);
    } else {
        let delta = stream.recv_block(1).await?[0];
        let sender = stream.recv_block(LIVE_SOFTSPOKEN_LENGTH).await?;
        assert_softspoken_relation(&out, delta, &sender);
        stream.send_data(&[1]).await?;
        stream.flush().await?;
    }
    Ok(())
}

#[cfg(feature = "cpp-probes")]
async fn run_rust_ag2pc_triple_pool_peer(streams: &mut Ag2pcStreams, role: Role) -> Result<()> {
    let mut pool = Ag2pcTriplePool::setup(streams, role, 40).await?;
    let local = pool.draw(streams, LIVE_AG2PC_DRAW_LENGTH).await?;
    pool.flush_cot_check(streams).await?;

    let (peer_delta, peer) = if role == Role::Alice {
        send_ag2pc_bundle(&mut streams.main, pool.delta(), &local).await?;
        recv_ag2pc_bundle(&mut streams.main, LIVE_AG2PC_DRAW_LENGTH).await?
    } else {
        let peer = recv_ag2pc_bundle(&mut streams.main, LIVE_AG2PC_DRAW_LENGTH).await?;
        send_ag2pc_bundle(&mut streams.main, pool.delta(), &local).await?;
        peer
    };
    assert!(verify_ag2pc_share_relation(
        &local,
        pool.delta(),
        &peer,
        peer_delta
    ));
    pool.end(streams).await?;
    Ok(())
}

async fn run_rust_ag2pc_protocol_script(streams: &mut Ag2pcStreams, role: Role) -> Result<Vec<u8>> {
    let mut protocol = Ag2pcProtocol::setup(streams, role, 40).await?;
    let alice_bits = if role == Role::Alice {
        vec![1, 0]
    } else {
        vec![0, 0]
    };
    let bob_bits = if role == Role::Bob { vec![1] } else { vec![0] };
    let inputs = protocol
        .process_inputs(streams, &[Role::Alice, Role::Bob], &[alice_bits, bob_bits])
        .await?;
    protocol.flush_cot_check(streams).await?;

    let mut out = Vec::new();
    out.extend(
        protocol
            .decode(streams, &inputs[0], Ag2pcRevealRecipient::Public)
            .await?,
    );
    out.extend(
        protocol
            .decode(streams, &inputs[1], Ag2pcRevealRecipient::Public)
            .await?,
    );
    let public = protocol.public_wires(&[1, 0, 1]);
    out.extend(
        protocol
            .decode(streams, &public, Ag2pcRevealRecipient::Public)
            .await?,
    );
    assert_eq!(protocol.process_input_calls(), 1);
    protocol.end(streams).await?;
    Ok(out)
}

#[cfg(feature = "cpp-probes")]
async fn run_rust_ag2pc_compute_peer(streams: &mut Ag2pcStreams, role: Role) -> Result<()> {
    let mut pool = Ag2pcTriplePool::setup(streams, role, 40).await?;
    let rep_a = pool.draw(streams, LIVE_AG2PC_COMPUTE_LENGTH).await?;
    let rep_b = pool.draw(streams, LIVE_AG2PC_COMPUTE_LENGTH).await?;
    let sigma = pool.compute_inplace(streams, &rep_a, &rep_b).await?;
    pool.flush_cot_check(streams).await?;

    let (peer_delta, peer_a, peer_b, peer_sigma) = if role == Role::Alice {
        send_ag2pc_compute_verification(&mut streams.main, pool.delta(), &rep_a, &rep_b, &sigma)
            .await?;
        recv_ag2pc_compute_verification(&mut streams.main).await?
    } else {
        let peer = recv_ag2pc_compute_verification(&mut streams.main).await?;
        send_ag2pc_compute_verification(&mut streams.main, pool.delta(), &rep_a, &rep_b, &sigma)
            .await?;
        peer
    };
    assert!(verify_ag2pc_share_relation(
        &sigma,
        pool.delta(),
        &peer_sigma,
        peer_delta
    ));
    for i in 0..LIVE_AG2PC_COMPUTE_LENGTH {
        let a = block_lsb(rep_a[i].mac) ^ block_lsb(peer_a[i].mac);
        let b = block_lsb(rep_b[i].mac) ^ block_lsb(peer_b[i].mac);
        let out = block_lsb(sigma[i].mac) ^ block_lsb(peer_sigma[i].mac);
        assert_eq!(out, a & b, "cross-mode sigma mismatch at {i}");
    }
    pool.end(streams).await?;
    Ok(())
}

async fn run_rust_ag2pc_program_script(streams: &mut Ag2pcStreams, role: Role) -> Result<Vec<u8>> {
    let program = Ag2pcProgram::from_circuit(&ag2pc_test_circuit())?;
    assert_eq!(program.num_inputs(), 5);
    assert_eq!(program.output_len(), 1);
    assert_eq!(program.num_ands(), 2);

    let input = ag2pc_test_input();
    let bob_bits = input[0..3].to_vec();
    let alice_bits = input[3..5].to_vec();
    let mut session = Ag2pcSession::setup(streams, role, 40).await?;
    let inputs = session
        .process_inputs(streams, &[Role::Bob, Role::Alice], &[bob_bits, alice_bits])
        .await?;
    let all_inputs = Ag2pcSecureWires::concat(&inputs);
    let output = session.run_program(streams, &program, &all_inputs).await?;
    let bits = session.reveal_public(streams, &output).await?;
    session.end(streams).await?;
    Ok(bits)
}

#[cfg(feature = "cpp-probes")]
async fn send_ag2pc_bundle(
    stream: &mut EmpStream,
    delta: Block,
    bundle: &[AShareBundle],
) -> Result<()> {
    let mac: Vec<Block> = bundle.iter().map(|item| item.mac).collect();
    let key: Vec<Block> = bundle.iter().map(|item| item.key).collect();
    stream.send_block(&[delta]).await?;
    stream.send_block(&mac).await?;
    stream.send_block(&key).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(feature = "cpp-probes")]
async fn recv_ag2pc_bundle(
    stream: &mut EmpStream,
    len: usize,
) -> Result<(Block, Vec<AShareBundle>)> {
    let delta = stream.recv_block(1).await?[0];
    let mac = stream.recv_block(len).await?;
    let key = stream.recv_block(len).await?;
    Ok((
        delta,
        mac.into_iter()
            .zip(key)
            .map(|(mac, key)| AShareBundle { mac, key })
            .collect(),
    ))
}

#[cfg(feature = "cpp-probes")]
async fn send_ag2pc_compute_verification(
    stream: &mut EmpStream,
    delta: Block,
    rep_a: &[AShareBundle],
    rep_b: &[AShareBundle],
    sigma: &[AShareBundle],
) -> Result<()> {
    stream.send_block(&[delta]).await?;
    send_ag2pc_bundle_without_delta(stream, rep_a).await?;
    send_ag2pc_bundle_without_delta(stream, rep_b).await?;
    send_ag2pc_bundle_without_delta(stream, sigma).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(feature = "cpp-probes")]
async fn recv_ag2pc_compute_verification(
    stream: &mut EmpStream,
) -> Result<(
    Block,
    Vec<AShareBundle>,
    Vec<AShareBundle>,
    Vec<AShareBundle>,
)> {
    let delta = stream.recv_block(1).await?[0];
    let rep_a = recv_ag2pc_bundle_without_delta(stream, LIVE_AG2PC_COMPUTE_LENGTH).await?;
    let rep_b = recv_ag2pc_bundle_without_delta(stream, LIVE_AG2PC_COMPUTE_LENGTH).await?;
    let sigma = recv_ag2pc_bundle_without_delta(stream, LIVE_AG2PC_COMPUTE_LENGTH).await?;
    Ok((delta, rep_a, rep_b, sigma))
}

#[cfg(feature = "cpp-probes")]
async fn send_ag2pc_bundle_without_delta(
    stream: &mut EmpStream,
    bundle: &[AShareBundle],
) -> Result<()> {
    let mac: Vec<Block> = bundle.iter().map(|item| item.mac).collect();
    let key: Vec<Block> = bundle.iter().map(|item| item.key).collect();
    stream.send_block(&mac).await?;
    stream.send_block(&key).await?;
    Ok(())
}

#[cfg(feature = "cpp-probes")]
async fn recv_ag2pc_bundle_without_delta(
    stream: &mut EmpStream,
    len: usize,
) -> Result<Vec<AShareBundle>> {
    let mac = stream.recv_block(len).await?;
    let key = stream.recv_block(len).await?;
    Ok(mac
        .into_iter()
        .zip(key)
        .map(|(mac, key)| AShareBundle { mac, key })
        .collect())
}

fn assert_softspoken_relation(receiver_data: &[Block], delta: Block, sender_data: &[Block]) {
    assert_eq!(receiver_data.len(), sender_data.len());
    for i in 0..receiver_data.len() {
        let expected = if receiver_data[i].get_lsb() {
            sender_data[i].xor(delta)
        } else {
            sender_data[i]
        };
        assert_eq!(receiver_data[i], expected, "SoftSpoken COT item {i}");
    }
}

#[cfg(feature = "cpp-probes")]
async fn run_rust_csw(stream: &mut EmpStream, role: TestOtRole) -> Result<()> {
    let data0: Vec<Block> = (0..80).map(csw_data0).collect();
    let data1: Vec<Block> = (0..80).map(csw_data1).collect();
    match role {
        TestOtRole::Send => csw_send(stream, &data0, &data1).await,
        TestOtRole::Recv => {
            let choices: Vec<bool> = (0..80).map(csw_choice).collect();
            let out = csw_recv(stream, &choices).await?;
            let expected: Vec<Block> = choices
                .iter()
                .enumerate()
                .map(|(i, choice)| if *choice { data1[i] } else { data0[i] })
                .collect();
            assert_eq!(out, expected);
            Ok(())
        }
    }
}

#[cfg(feature = "cpp-probes")]
fn cpp_csw_probe() -> PathBuf {
    let root = cpp_root();
    let bin = root.join(".build/csw_probe");
    if !bin.exists() {
        let status = Command::new("make")
            .arg(".build/csw_probe")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success(), "failed to build .build/csw_probe");
    }
    assert!(
        bin.exists(),
        ".build/csw_probe was not built by the Cargo build script or test setup"
    );
    bin
}

#[cfg(feature = "cpp-probes")]
fn cpp_softspoken_probe() -> PathBuf {
    let root = cpp_root();
    let bin = root.join(".build/softspoken_probe");
    if !bin.exists() {
        let status = Command::new("make")
            .arg(".build/softspoken_probe")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success(), "failed to build .build/softspoken_probe");
    }
    assert!(
        bin.exists(),
        ".build/softspoken_probe was not built by the Cargo build script or test setup"
    );
    bin
}

#[cfg(feature = "cpp-probes")]
fn cpp_ag2pc_triple_pool_probe() -> PathBuf {
    let root = cpp_root();
    let bin = root.join(".build/ag2pc_triple_pool_probe");
    if !bin.exists() {
        let status = Command::new("make")
            .arg(".build/ag2pc_triple_pool_probe")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to build .build/ag2pc_triple_pool_probe"
        );
    }
    assert!(
        bin.exists(),
        ".build/ag2pc_triple_pool_probe was not built by the Cargo build script or test setup"
    );
    bin
}

#[cfg(feature = "cpp-probes")]
fn cpp_ag2pc_protocol_probe() -> PathBuf {
    let root = cpp_root();
    let bin = root.join(".build/ag2pc_protocol_probe");
    if !bin.exists() {
        let status = Command::new("make")
            .arg(".build/ag2pc_protocol_probe")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to build .build/ag2pc_protocol_probe"
        );
    }
    assert!(
        bin.exists(),
        ".build/ag2pc_protocol_probe was not built by the Cargo build script or test setup"
    );
    bin
}

#[cfg(feature = "cpp-probes")]
fn cpp_ag2pc_compute_probe() -> PathBuf {
    let root = cpp_root();
    let bin = root.join(".build/ag2pc_compute_probe");
    if !bin.exists() {
        let status = Command::new("make")
            .arg(".build/ag2pc_compute_probe")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to build .build/ag2pc_compute_probe"
        );
    }
    assert!(
        bin.exists(),
        ".build/ag2pc_compute_probe was not built by the Cargo build script or test setup"
    );
    bin
}

fn free_port() -> u16 {
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
