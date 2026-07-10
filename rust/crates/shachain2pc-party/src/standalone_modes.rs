async fn run_derivation_batch(
    role: Role,
    port: u16,
    indices: &[Index48],
    share: Value32,
    peer_ip: IpAddr,
) -> Result<Vec<(Index48, Value32)>, PartyError> {
    let first_index = *indices
        .first()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?;
    let mut timing = PhaseTiming::new(role, first_index);
    let sha = shared_sha_circuit();
    let index_values: Vec<u64> = indices.iter().map(|index| index.get()).collect();
    let digest = batch_digest(&index_values, &sha);
    timing.mark("build_batch_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark("input_auth");
    let mut authenticated = Vec::with_capacity(indices.len());
    for (i, &index) in indices.iter().enumerate() {
        let circuit = build_circuit_for_index(index, &sha)?;
        let program = Ag2pcProgram::from_circuit(&circuit)?;
        let mut out = session
            .run_program(&mut streams, &program, &seed_inputs)
            .await?;
        out.strip_labels_for_reveal();
        authenticated.push((indices[i], out));
        timing.mark("batch_item");
    }

    let outputs = reveal_authenticated_values(&mut session, &mut streams, &authenticated)
        .await
        .inspect(|_| timing.mark("batch_reveal"))?;
    session.end(&mut streams).await?;
    Ok(outputs)
}

async fn run_derivation_tree(
    role: Role,
    port: u16,
    indices: &[Index48],
    share: Value32,
    peer_ip: IpAddr,
    trunk_chunk_blocks: i32,
) -> Result<Vec<(Index48, Value32)>, PartyError> {
    let first_index = *indices
        .first()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?;
    let mut timing = PhaseTiming::new(role, first_index);
    let sha = shared_sha_circuit();
    let (_, low_mask, high_mask) = range_split_masks(indices)?;
    let trunk_groups = split_chain_bits(
        first_index.get() & high_mask,
        effective_chunk_size(trunk_chunk_blocks)?,
    )?;
    if trunk_groups.iter().map(Vec::len).sum::<usize>() == 0 {
        return Err(PartyError::UnsupportedMode(
            "shachain2pc: shared-trunk needs >=1 common high set bit (no shared hash in this range); use batch mode",
        ));
    }
    let tamper_branch = tamper_step_from_env();

    let index_values: Vec<u64> = indices.iter().map(|index| index.get()).collect();
    let digest = tree_digest(&index_values, trunk_chunk_blocks, &sha);
    timing.mark("build_tree_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark("input_auth");
    let first_trunk_program = chunk_program(&sha, &trunk_groups[0], true, false)?;
    let mut trunk = session
        .run_program(&mut streams, &first_trunk_program, &seed_inputs)
        .await?;
    drop(first_trunk_program);
    timing.mark("tree_trunk_0");

    for (chunk, bits) in trunk_groups.iter().enumerate().skip(1) {
        let program = chunk_program(&sha, bits, false, false)?;
        trunk = session.run_program(&mut streams, &program, &trunk).await?;
        timing.mark(match chunk {
            1 => "tree_trunk_1",
            2 => "tree_trunk_2",
            3 => "tree_trunk_3",
            _ => "tree_trunk",
        });
    }

    let mut authenticated = Vec::with_capacity(indices.len());
    for (i, &index) in indices.iter().enumerate() {
        let bits = set_bits_desc(index.get() & low_mask);
        let program = chunk_program(&sha, &bits, false, i as i64 == tamper_branch)?;
        let mut out = session.run_program(&mut streams, &program, &trunk).await?;
        out.strip_labels_for_reveal();
        authenticated.push((indices[i], out));
        timing.mark("tree_branch");
    }

    let outputs = reveal_authenticated_values(&mut session, &mut streams, &authenticated)
        .await
        .inspect(|_| timing.mark("tree_reveal"))?;
    session.end(&mut streams).await?;
    Ok(outputs)
}

async fn run_derivation_cache(
    role: Role,
    port: u16,
    indices: &[Index48],
    share: Value32,
    peer_ip: IpAddr,
    trunk_chunk_blocks: i32,
    tile_fanout: usize,
) -> Result<Vec<(Index48, Value32)>, PartyError> {
    let lo = indices
        .first()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?
        .get();
    let hi = indices
        .last()
        .ok_or(PartyError::UnsupportedMode("range must not be empty"))?
        .get();
    let mut timing = PhaseTiming::new(role, Index48::new(lo).expect("parser checked index"));
    let sha = shared_sha_circuit();
    let tile_height = tile_height_for_fanout(tile_fanout)?;
    let (split, low_mask, high_mask) = range_split_masks(&[
        Index48::new(lo).expect("parser checked index"),
        Index48::new(hi).expect("parser checked index"),
    ])?;
    let trunk_groups = split_chain_bits(lo & high_mask, effective_chunk_size(trunk_chunk_blocks)?)?;
    if trunk_groups.iter().map(Vec::len).sum::<usize>() == 0 {
        return Err(PartyError::UnsupportedMode(
            "shachain2pc: cache needs >=1 common high set bit (no shared trunk hash); use batch mode for this range",
        ));
    }
    let mut tamper = TamperCursor::from_env();

    let depth = if split < 0 {
        0usize
    } else {
        split as usize + 1
    };
    let aligned = split >= 0 && (lo & low_mask) == 0 && (hi & low_mask) == low_mask;
    let recursive_levels = if tile_height >= 1 && aligned && depth >= tile_height {
        Some(plan_tile_levels(depth, tile_height)?)
    } else {
        None
    };
    // Recursive-level tile circuits are built lazily, one level at a time, inside
    // the tiling loop below (see the level loop), so only the current level's
    // circuit is resident rather than all levels at once.

    // tile_program / one_step_program are built lazily below, after the recursive
    // path has had its chance to return -- the recursive case never uses them, so
    // building them up front just wastes a large unused circuit.

    let digest = cache_digest(
        lo,
        hi,
        trunk_chunk_blocks,
        i32::try_from(tile_fanout).map_err(|_| {
            PartyError::UnsupportedMode("SHACHAIN2PC_TILE_FANOUT is too large for this platform")
        })?,
        &sha,
    );
    timing.mark("build_cache_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark_streams("open_streams", &streams);
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark_streams("ag2pc_setup", &streams);

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark_streams("input_auth", &streams);
    let first_trunk_program = chunk_program(&sha, &trunk_groups[0], true, false)?;
    let mut trunk = session
        .run_program(&mut streams, &first_trunk_program, &seed_inputs)
        .await?;
    drop(first_trunk_program);
    timing.mark_streams("cache_trunk_0", &streams);

    for (chunk, bits) in trunk_groups.iter().enumerate().skip(1) {
        let program = chunk_program(&sha, bits, false, false)?;
        trunk = session.run_program(&mut streams, &program, &trunk).await?;
        timing.mark_streams(
            match chunk {
                1 => "cache_trunk_1",
                2 => "cache_trunk_2",
                3 => "cache_trunk_3",
                _ => "cache_trunk",
            },
            &streams,
        );
    }

    if let Some(levels) = &recursive_levels {
        let mut roots = vec![trunk.clone()];
        let n_levels = levels.len();
        for (level_index, &level) in levels.iter().enumerate() {
            // Build this level's tile circuit lazily; it is dropped at the end of
            // the iteration, so only one level's circuit is resident at a time.
            let program = build_tile_program(&sha, level.bit_offset, level.height, false)?;
            let is_bottom = level_index + 1 == n_levels;
            if is_bottom {
                let mut tiles = Vec::with_capacity(roots.len());
                for root in roots {
                    let tampered_program;
                    let program_ref = if tamper.matches_current() {
                        tampered_program = Some(build_tile_program(
                            &sha,
                            level.bit_offset,
                            level.height,
                            true,
                        )?);
                        tampered_program.as_ref().expect("tampered program set")
                    } else {
                        &program
                    };
                    let mut tile = session
                        .run_program(&mut streams, program_ref, &root)
                        .await?;
                    tile.strip_labels_for_reveal();
                    tiles.push(tile);
                    timing.mark_streams("cache_tile", &streams);
                    tamper.advance();
                }

                let leaf_mask = (1u64 << level.height) - 1;
                let mut results = vec![None; (hi - lo + 1) as usize];
                let mut reveal_index = hi;
                loop {
                    let suffix = reveal_index & low_mask;
                    let tile_index = (suffix >> level.height) as usize;
                    let slot = (suffix & leaf_mask) as usize;
                    let tile = tiles.get(tile_index).ok_or(PartyError::UnsupportedMode(
                        "shachain2pc: missing recursive cached tile",
                    ))?;
                    let leaf = tile.slice(slot * VALUE_BITS, (slot + 1) * VALUE_BITS)?;
                    let bits = session.reveal_public(&mut streams, &leaf).await?;
                    results[(reveal_index - lo) as usize] = Some(value_from_bits(&bits)?);
                    if reveal_index == lo {
                        break;
                    }
                    reveal_index -= 1;
                }
                streams.main.flush().await?;
                timing.mark_streams("cache_reveal", &streams);

                let outputs = indices
                    .iter()
                    .map(|index| {
                        let offset = (index.get() - lo) as usize;
                        Ok((
                            *index,
                            results[offset].ok_or(PartyError::UnsupportedMode(
                                "shachain2pc: missing recursive cached result",
                            ))?,
                        ))
                    })
                    .collect();
                session.end(&mut streams).await?;
                return outputs;
            }

            let mut next = Vec::with_capacity(roots.len() * (1usize << level.height));
            for root in roots {
                let tampered_program;
                let program_ref = if tamper.matches_current() {
                    tampered_program = Some(build_tile_program(
                        &sha,
                        level.bit_offset,
                        level.height,
                        true,
                    )?);
                    tampered_program.as_ref().expect("tampered program set")
                } else {
                    &program
                };
                let tile = session
                    .run_program(&mut streams, program_ref, &root)
                    .await?;
                for slot in 0..(1usize << level.height) {
                    next.push(tile.slice(slot * VALUE_BITS, (slot + 1) * VALUE_BITS)?);
                }
                timing.mark_streams("cache_tile", &streams);
                tamper.advance();
            }
            roots = next;
        }
    }

    // Only reached when the recursive tiling did not apply; build the fallback
    // programs now (kept out of the recursive case to save that RAM).
    let tile_program = if tile_fanout >= 2 {
        Some(build_tile_program(&sha, 0, CACHE_TILE_HEIGHT, false)?)
    } else {
        None
    };
    let one_step_program = chunk_program(&sha, &[0], false, false)?;

    let mut stack = CacheStack::new(trunk);
    let mut tile_outs: HashMap<u64, Ag2pcSecureWires> = HashMap::new();
    let mut single_outs: HashMap<u64, Ag2pcSecureWires> = HashMap::new();
    let tile_mask = (CACHE_TILE_LEAVES as u64) - 1;
    let can_tile = tile_fanout >= 2 && split >= (CACHE_TILE_HEIGHT as i32 - 1);

    let mut index = hi;
    loop {
        let tile_base = index & !tile_mask;
        let full_tile = can_tile
            && (index & tile_mask) == tile_mask
            && tile_base >= lo
            && tile_base + tile_mask <= hi;
        if full_tile {
            let prefix = set_bits_desc((tile_base & low_mask) & !tile_mask);
            align_cache_stack(
                &mut session,
                &mut streams,
                &sha,
                &one_step_program,
                &mut stack,
                &prefix,
                &mut tamper,
            )
            .await?;
            let tampered_program;
            let tile_program_ref = if tamper.matches_current() {
                tampered_program = Some(build_tile_program(&sha, 0, CACHE_TILE_HEIGHT, true)?);
                tampered_program.as_ref().expect("tampered program set")
            } else {
                tile_program
                    .as_ref()
                    .expect("full_tile requires tile_program")
            };
            let mut tile = session
                .run_program(&mut streams, tile_program_ref, stack.last())
                .await?;
            tile.strip_labels_for_reveal();
            tile_outs.insert(tile_base, tile);
            timing.mark_streams("cache_tile", &streams);
            tamper.advance();

            if tile_base == lo {
                break;
            }
            index = tile_base - 1;
            continue;
        }

        let low = set_bits_desc(index & low_mask);
        align_cache_stack(
            &mut session,
            &mut streams,
            &sha,
            &one_step_program,
            &mut stack,
            &low,
            &mut tamper,
        )
        .await?;
        let mut out = stack.last().clone();
        out.strip_labels_for_reveal();
        single_outs.insert(index, out);
        timing.mark_streams("cache_single", &streams);
        if index == lo {
            break;
        }
        index -= 1;
    }

    let mut results = vec![None; (hi - lo + 1) as usize];
    let mut reveal_index = hi;
    loop {
        let tile_base = reveal_index & !tile_mask;
        if let Some(tile) = tile_outs.get(&tile_base) {
            let slot = (reveal_index & tile_mask) as usize;
            let leaf = tile.slice(slot * VALUE_BITS, (slot + 1) * VALUE_BITS)?;
            let bits = session.reveal_public(&mut streams, &leaf).await?;
            results[(reveal_index - lo) as usize] = Some(value_from_bits(&bits)?);
        } else {
            let wires = single_outs
                .get(&reveal_index)
                .ok_or(PartyError::UnsupportedMode(
                    "shachain2pc: missing cached output",
                ))?;
            let bits = session.reveal_public(&mut streams, wires).await?;
            results[(reveal_index - lo) as usize] = Some(value_from_bits(&bits)?);
        }
        if reveal_index == lo {
            break;
        }
        reveal_index -= 1;
    }
    streams.main.flush().await?;
    timing.mark_streams("cache_reveal", &streams);

    let outputs = indices
        .iter()
        .map(|index| {
            let offset = (index.get() - lo) as usize;
            Ok((
                *index,
                results[offset].ok_or(PartyError::UnsupportedMode(
                    "shachain2pc: missing cached result",
                ))?,
            ))
        })
        .collect();
    session.end(&mut streams).await?;
    outputs
}

struct CacheStack {
    bits: Vec<usize>,
    vals: Vec<Ag2pcSecureWires>,
}

impl CacheStack {
    fn new(root: Ag2pcSecureWires) -> Self {
        Self {
            bits: Vec::new(),
            vals: vec![root],
        }
    }

    fn last(&self) -> &Ag2pcSecureWires {
        self.vals.last().expect("stack has trunk")
    }
}

struct TamperCursor {
    target: i64,
    current: i64,
}

impl TamperCursor {
    fn from_env() -> Self {
        Self {
            target: tamper_step_from_env(),
            current: 0,
        }
    }

    fn matches_current(&self) -> bool {
        self.current == self.target
    }

    fn advance(&mut self) {
        self.current += 1;
    }
}

async fn align_cache_stack(
    session: &mut Ag2pcSession,
    streams: &mut Ag2pcStreams,
    sha: &Circuit,
    one_step_template: &Ag2pcProgram,
    stack: &mut CacheStack,
    target: &[usize],
    tamper: &mut TamperCursor,
) -> Result<(), PartyError> {
    let mut prefix = 0usize;
    while prefix < stack.bits.len() && prefix < target.len() && stack.bits[prefix] == target[prefix]
    {
        prefix += 1;
    }
    stack.bits.truncate(prefix);
    stack.vals.truncate(prefix + 1);
    for &bit in &target[prefix..] {
        let should_tamper = tamper.matches_current();
        let program = if bit == 0 && !should_tamper {
            one_step_template.clone()
        } else {
            chunk_program(sha, &[bit], false, should_tamper)?
        };
        let next = session.run_program(streams, &program, stack.last()).await?;
        stack.vals.push(next);
        stack.bits.push(bit);
        tamper.advance();
    }
    Ok(())
}

async fn run_derivation_chunked(
    role: Role,
    port: u16,
    index: Index48,
    share: Value32,
    peer_ip: IpAddr,
    blocks_per_chunk: usize,
) -> Result<Value32, PartyError> {
    let mut timing = PhaseTiming::new(role, index);
    let sha = shared_sha_circuit();
    let groups = split_chain_bits(index.get(), blocks_per_chunk)?;
    let tamper_chunk = tamper_step_from_env();
    let digest = chunk_spec_digest(index.get(), blocks_per_chunk as i32, &sha);
    timing.mark("build_chunk_circuits");

    let mut streams = open_ag2pc_streams_after_digest(role, port, peer_ip, digest).await?;
    timing.mark("open_streams");
    let mut session = Ag2pcSession::setup(&mut streams, role, AG2PC_SSP).await?;
    streams.main.flush().await?;
    timing.mark("ag2pc_setup");

    let seed_inputs = authenticate_seed_inputs(&mut session, &mut streams, role, share).await?;
    timing.mark("input_auth");
    let first_program = chunk_program(&sha, &groups[0], true, tamper_chunk == 0)?;
    let mut carried = session
        .run_program(&mut streams, &first_program, &seed_inputs)
        .await?;
    drop(first_program);
    timing.mark("chunk_0");

    for (chunk, bits) in groups.iter().enumerate().skip(1) {
        let program = chunk_program(&sha, bits, false, chunk as i64 == tamper_chunk)?;
        carried = session
            .run_program(&mut streams, &program, &carried)
            .await?;
        timing.mark(match chunk {
            1 => "chunk_1",
            2 => "chunk_2",
            3 => "chunk_3",
            _ => "chunk",
        });
    }

    carried.strip_labels_for_reveal();
    let output = session.reveal_public(&mut streams, &carried).await?;
    session.end(&mut streams).await?;
    streams.main.flush().await?;
    timing.mark("reveal");
    value_from_bits(&output)
}
