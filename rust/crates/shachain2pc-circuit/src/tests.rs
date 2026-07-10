use super::*;
use serde_json::Value;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn fixture_records() -> Vec<Value> {
    let path = repo_root().join("compat/v1/probes/cpp-compat-probe.jsonl");
    let data = std::fs::read_to_string(path).unwrap();
    data.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn sha_gadget() -> Circuit {
    load_bristol(repo_root().join(default_sha256_compress_path())).unwrap()
}

#[test]
fn embedded_gadget_matches_file() {
    // The gadget baked in via include_str! must parse to the same circuit as
    // the on-disk emp file, so the party can run with no runtime file.
    assert_eq!(sha256_compress_gadget().unwrap(), sha_gadget());
}

fn hex32(bytes: [u8; 32]) -> String {
    Value32::new(bytes).to_hex()
}

#[test]
fn split_chain_bits_matches_cpp_ordering() {
    assert_eq!(split_chain_bits(0, 16).unwrap(), vec![Vec::<usize>::new()]);

    let groups = split_chain_bits(0xffff_ffff_ffff, 16).unwrap();
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0], (32..=47).rev().collect::<Vec<_>>());
    assert_eq!(groups[1], (16..=31).rev().collect::<Vec<_>>());
    assert_eq!(groups[2], (0..=15).rev().collect::<Vec<_>>());

    assert_eq!(
        split_chain_bits(0b101101, 2).unwrap(),
        vec![vec![5, 3], vec![2, 0]]
    );
    assert!(split_chain_bits(1, 0).is_err());
    assert!(split_chain_bits(MAX_INDEX + 1, 1).is_err());
}

#[test]
fn reference_matches_cpp_fixture() {
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "shachain_reference")
    {
        let seed = Value32::from_hex(record["inputs"]["seed"].as_str().unwrap()).unwrap();
        let index = Index48::from_hex(record["inputs"]["index_hex"].as_str().unwrap()).unwrap();
        let got = generate_from_seed(seed, index).to_hex();
        assert_eq!(got, record["outputs"]["value"].as_str().unwrap());
    }
}

#[test]
fn circuit_digest_matches_cpp_fixture() {
    let sha = sha_gadget();
    for record in fixture_records()
        .into_iter()
        .filter(|r| r["probe"] == "circuit_digest")
    {
        let index = Index48::from_hex(record["inputs"]["index_hex"].as_str().unwrap()).unwrap();
        let circuit = build_circuit_for_index(index, &sha).unwrap();
        let gate_arr = to_emp_gate_array(&circuit);
        let digest = hex32(circuit_digest(&circuit, &gate_arr));

        assert_eq!(i64::from(circuit.num_gate()), record["outputs"]["num_gate"]);
        assert_eq!(i64::from(circuit.num_wire), record["outputs"]["num_wire"]);
        assert_eq!(
            circuit.count_type(GateType::And) as i64,
            record["outputs"]["and_gates"]
        );
        assert_eq!(
            gate_arr.len() as i64,
            record["outputs"]["emp_gate_array_ints"]
        );
        assert_eq!(digest, record["outputs"]["digest"].as_str().unwrap());
    }
}

#[test]
fn chunked_plaintext_eval_matches_reference() {
    let sha = sha_gadget();
    let seed =
        Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let alice =
        Value32::from_hex("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
            .unwrap();
    let bob = seed.xor(alice);
    let cases = [
        ("000000000001", 1),
        ("0000000000ff", 3),
        ("ffffffffffff", 16),
    ];

    for (index_hex, blocks_per_chunk) in cases {
        let index = Index48::from_hex(index_hex).unwrap();
        let groups = split_chain_bits(index.get(), blocks_per_chunk).unwrap();
        let mut input = bob.to_bits_msb();
        input.extend_from_slice(&alice.to_bits_msb());

        let mut out_bits = Vec::new();
        for (chunk, bits) in groups.iter().enumerate() {
            let circuit = build_chunk_circuit(&sha, bits, chunk == 0).unwrap();
            check_chunk_circuit(&circuit).unwrap();
            out_bits = eval_bristol(&circuit, &input).unwrap();
            input = out_bits.clone();
        }

        let got = Value32::from_bits_msb(&out_bits).unwrap();
        assert_eq!(got, generate_from_seed(seed, index));
    }
}

#[test]
fn tile_plaintext_eval_matches_low_subtree_reference() {
    let sha = sha_gadget();
    let seed =
        Value32::from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
            .unwrap();
    let circuit = build_tile_circuit(&sha, 0, CACHE_TILE_HEIGHT).unwrap();
    check_tile_circuit(&circuit, CACHE_TILE_HEIGHT).unwrap();
    let out_bits = eval_bristol(&circuit, &seed.to_bits_msb()).unwrap();
    assert_eq!(out_bits.len(), CACHE_TILE_BITS);

    for suffix in 0..CACHE_TILE_LEAVES {
        let start = suffix * VALUE_BITS;
        let got = Value32::from_bits_msb(&out_bits[start..start + VALUE_BITS]).unwrap();
        let expected = generate_from_seed(seed, Index48::new(suffix as u64).unwrap());
        assert_eq!(got, expected, "suffix {suffix}");
    }
}

#[test]
fn offset_tile_plaintext_eval_matches_intermediate_reference() {
    let sha = sha_gadget();
    let seed =
        Value32::from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
            .unwrap();

    for bit_offset in [0usize, 1, 4, 8, 20, 44] {
        for tile_height in [1usize, 2, 3, 4] {
            if bit_offset + tile_height > INDEX_BITS as usize {
                continue;
            }
            let circuit = build_tile_circuit(&sha, bit_offset, tile_height).unwrap();
            check_tile_circuit(&circuit, tile_height).unwrap();
            let out_bits = eval_bristol(&circuit, &seed.to_bits_msb()).unwrap();
            for suffix in 0..(1usize << tile_height) {
                let start = suffix * VALUE_BITS;
                let got = Value32::from_bits_msb(&out_bits[start..start + VALUE_BITS]).unwrap();
                let index = Index48::new((suffix as u64) << bit_offset).unwrap();
                let expected = generate_from_seed(seed, index);
                assert_eq!(
                    got, expected,
                    "bit_offset={bit_offset} tile_height={tile_height} suffix={suffix}"
                );
            }
        }
    }
}

#[test]
fn tile_level_plan_matches_cpp_shape() {
    assert_eq!(
        plan_tile_levels(8, 4).unwrap(),
        vec![
            TileLevel {
                bit_offset: 4,
                height: 4
            },
            TileLevel {
                bit_offset: 0,
                height: 4
            },
        ]
    );
    assert_eq!(
        plan_tile_levels(13, 4).unwrap(),
        vec![
            TileLevel {
                bit_offset: 12,
                height: 1
            },
            TileLevel {
                bit_offset: 8,
                height: 4
            },
            TileLevel {
                bit_offset: 4,
                height: 4
            },
            TileLevel {
                bit_offset: 0,
                height: 4
            },
        ]
    );
}

#[test]
fn chunk_tile_and_mode_digests_match_cpp_constants() {
    let sha = sha_gadget();
    let batch_indices = [0xffff_ffff_ffff, 0xffff_ffff_fffe, 0xffff_ffff_fffd];
    assert_eq!(
        hex32(batch_digest(&batch_indices, &sha)),
        "19102fa397acec25af910f805d89195b4e284757dda7791e42b5da2aacb19522"
    );
    assert_eq!(
        hex32(chunk_spec_digest(0xffff_ffff_ffff, 16, &sha)),
        "700937e6bc5769cde9473037cddaeae90a5f6a0652727b83041959ea3f87aae5"
    );
    assert_eq!(
        hex32(tree_digest(&batch_indices, 16, &sha)),
        "35a24a4d64c46acf1a099638e86ab4a54c4bb8856cf8f71413317c2001d4a8f9"
    );
    assert_eq!(
        hex32(cache_digest(
            0xffff_ffff_ff00,
            0xffff_ffff_ffff,
            16,
            CACHE_TILE_LEAVES as i32,
            &sha,
        )),
        "715a3bca84f65192fe867ed15c1fa57aeb5d611a6b0626b06d418d66123305d6"
    );

    let chunk = build_chunk_circuit(&sha, &[47, 46, 45], true).unwrap();
    assert_eq!(
        hex32(circuit_digest(&chunk, &to_emp_gate_array(&chunk))),
        "5104a2fd1427f01bdf0ca477649453bf836c3fb15ac26b49d4f865aa7baf140d"
    );

    let tile = build_tile_circuit(&sha, 0, CACHE_TILE_HEIGHT).unwrap();
    assert_eq!(
        hex32(circuit_digest(&tile, &to_emp_gate_array(&tile))),
        "5dead3f8a9201513f80f3dd6e674bd043fa546754a54a2480f1a27248b6bce7c"
    );
}

#[test]
fn plaintext_derivation_circuit_matches_reference() {
    let sha = sha_gadget();
    let cases = [
        Index48::from_hex("000000000001").unwrap(),
        Index48::from_hex("0000000000ff").unwrap(),
    ];
    let seed =
        Value32::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let alice =
        Value32::from_hex("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
            .unwrap();
    let bob = seed.xor(alice);
    for index in cases {
        let circuit = build_circuit_for_index(index, &sha).unwrap();
        let mut input = bob.to_bits_msb();
        input.extend_from_slice(&alice.to_bits_msb());
        let out_bits = eval_bristol(&circuit, &input).unwrap();
        let got = Value32::from_bits_msb(&out_bits).unwrap();
        assert_eq!(got, generate_from_seed(seed, index));
    }
}
