#[derive(Clone, Debug, Default)]
pub struct Ag2pcSecureWires {
    pub lambda: Vec<u8>,
    pub wire_bundle: Vec<AShareBundle>,
    pub label0: Vec<Block>,
    pub eval_label: Vec<Block>,
}

impl Ag2pcSecureWires {
    pub fn len(&self) -> usize {
        self.lambda.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lambda.is_empty()
    }

    pub fn slice(&self, start: usize, end: usize) -> Result<Self> {
        if start > end || end > self.len() {
            return Err(CompatError::BadAuthenticatedSlice {
                len: self.len(),
                start,
                end,
            });
        }
        Ok(Self {
            lambda: self.lambda[start..end].to_vec(),
            wire_bundle: self.wire_bundle[start..end].to_vec(),
            label0: if self.label0.is_empty() {
                Vec::new()
            } else {
                self.label0[start..end].to_vec()
            },
            eval_label: if self.eval_label.is_empty() {
                Vec::new()
            } else {
                self.eval_label[start..end].to_vec()
            },
        })
    }

    pub fn concat(parts: &[Self]) -> Self {
        let total = parts.iter().map(Self::len).sum();
        let mut out = Self {
            lambda: Vec::with_capacity(total),
            wire_bundle: Vec::with_capacity(total),
            label0: Vec::new(),
            eval_label: Vec::new(),
        };
        if parts.iter().any(|part| !part.label0.is_empty()) {
            out.label0 = Vec::with_capacity(total);
        }
        if parts.iter().any(|part| !part.eval_label.is_empty()) {
            out.eval_label = Vec::with_capacity(total);
        }
        for part in parts {
            out.lambda.extend_from_slice(&part.lambda);
            out.wire_bundle.extend_from_slice(&part.wire_bundle);
            out.label0.extend_from_slice(&part.label0);
            out.eval_label.extend_from_slice(&part.eval_label);
        }
        out
    }

    pub fn strip_labels_for_reveal(&mut self) {
        self.label0.zeroize();
        self.eval_label.zeroize();
        self.label0.clear();
        self.eval_label.clear();
        self.label0.shrink_to_fit();
        self.eval_label.shrink_to_fit();
    }
}

impl Drop for Ag2pcSecureWires {
    fn drop(&mut self) {
        self.lambda.zeroize();
        self.wire_bundle.zeroize();
        self.label0.zeroize();
        self.eval_label.zeroize();
    }
}

pub struct Ag2pcTriplePool {
    state: Ag2pcTriplePoolState,
    abit1: SoftSpoken4,
    abit2: SoftSpoken4,
}

impl ops::Deref for Ag2pcTriplePool {
    type Target = Ag2pcTriplePoolState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl ops::DerefMut for Ag2pcTriplePool {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

pub struct Ag2pcProtocol {
    party: Role,
    triple_pool: Ag2pcTriplePool,
    delta: Block,
    prg: Prg,
    process_input_calls: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ag2pcRevealRecipient {
    Public,
    Party(Role),
}

struct Ag2pcComputeHashes<'a> {
    gmitc: &'a mut Mitccrh8,
    emitc: &'a mut Mitccrh8,
    feq: &'a mut Sha256,
}
