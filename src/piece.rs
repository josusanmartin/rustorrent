use crate::util::AtomicUpdate;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::torrent::{TorrentMeta, MAX_PIECE_LENGTH};
use crate::{sha1, sha256};

pub const BLOCK_LEN: u32 = 16 * 1024;
pub const PRIORITY_SKIP: u8 = 0;
#[allow(dead_code)]
pub const PRIORITY_LOW: u8 = 1;
pub const PRIORITY_NORMAL: u8 = 2;
pub const PRIORITY_HIGH: u8 = 3;

#[derive(Clone)]
pub enum PieceHash {
    Sha1([u8; 20]),
    Sha256 {
        root: [u8; 32],
        merkle_length: u32,
        data_length: u32,
    },
    Hybrid {
        sha1: [u8; 20],
        sha256: [u8; 32],
        merkle_length: u32,
        v2_data_length: u32,
    },
}

impl PieceHash {
    pub fn verify(&self, data: &[u8]) -> bool {
        match self {
            PieceHash::Sha1(expected) => sha1::sha1(data) == *expected,
            PieceHash::Sha256 {
                root,
                merkle_length,
                data_length,
            } => {
                data.len() == *data_length as usize
                    && sha256::merkle_piece_root(data, *merkle_length) == Some(*root)
            }
            PieceHash::Hybrid {
                sha1: expected_sha1,
                sha256: expected_sha256,
                merkle_length,
                v2_data_length,
            } => {
                sha1::sha1(data) == *expected_sha1
                    && data.get(..*v2_data_length as usize).is_some_and(|v2_data| {
                        sha256::merkle_piece_root(v2_data, *merkle_length) == Some(*expected_sha256)
                    })
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    Missing,
    Requested,
    Complete,
}

struct Piece {
    hash: PieceHash,
    offset: u64,
    length: u32,
    blocks: Vec<BlockState>,
    /// Number of `Missing` / `Complete` entries in `blocks`.
    missing: u32,
    done: u32,
    priority: u8,
    wanted: bool,
    verified: bool,
}

/// Aggregates over wanted pieces, maintained incrementally so progress
/// queries are O(1) instead of a scan over every piece.
#[derive(Default)]
struct Totals {
    wanted: usize,
    wanted_bytes: u64,
    verified: usize,
    verified_bytes: u64,
    remaining_blocks: usize,
}

pub struct PieceManager {
    pieces: Vec<Piece>,
    availability: Vec<u32>,
    reserved_by: Vec<Option<u64>>,
    reservation_time: Vec<Option<Instant>>,
    sequential: bool,
    /// Bit set of pieces that are wanted, unverified and still have a
    /// `Missing` block; bit 63 of word 0 is piece 0 (peer bitfield order), so
    /// selection is a word-wise AND with the peer's bitfield.
    candidates: Vec<u64>,
    totals: Totals,
}

#[derive(Clone, Copy)]
pub struct BlockRequest {
    pub index: u32,
    pub begin: u32,
    pub length: u32,
}

#[cfg_attr(test, derive(Debug))]
pub struct PieceBuffer {
    index: u32,
    length: u32,
    data: Vec<u8>,
    blocks: Vec<u8>,
    complete: usize,
    _budget_reservation: Option<PieceBufferReservation>,
}

#[cfg_attr(test, derive(Debug))]
pub struct PieceBufferBudget {
    limit: usize,
    used: AtomicUsize,
}

#[derive(Clone)]
pub struct PieceBufferBudgets {
    global: Arc<PieceBufferBudget>,
    torrent: Arc<PieceBufferBudget>,
}

#[cfg_attr(test, derive(Debug))]
struct BudgetCounterPermit {
    budget: Arc<PieceBufferBudget>,
    bytes: usize,
}

#[cfg_attr(test, derive(Debug))]
pub struct PieceBufferReservation {
    _torrent: BudgetCounterPermit,
    _global: BudgetCounterPermit,
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    InvalidPieceLength,
    InvalidPieces,
    InvalidBitfield,
    InvalidPiece,
    InvalidBlock,
    InvalidPriority,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidPieceLength => "invalid piece length",
            Error::InvalidPieces => "invalid pieces",
            Error::InvalidBitfield => "invalid bitfield",
            Error::InvalidPiece => "invalid piece index",
            Error::InvalidBlock => "invalid block",
            Error::InvalidPriority => "invalid priority",
        })
    }
}

impl std::error::Error for Error {}

impl PieceBufferBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>, bytes: usize) -> Option<BudgetCounterPermit> {
        self.used
            .update_with(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .ok()?;
        Some(BudgetCounterPermit {
            budget: Arc::clone(self),
            bytes,
        })
    }

    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

impl PieceBufferBudgets {
    pub fn new(global: Arc<PieceBufferBudget>, torrent: Arc<PieceBufferBudget>) -> Self {
        Self { global, torrent }
    }

    /// Reserves logical allocation bytes against both the per-torrent and
    /// process-wide limits. The returned non-cloneable guard releases both
    /// reservations when it is dropped.
    pub fn try_reserve(&self, bytes: usize) -> Option<PieceBufferReservation> {
        if bytes == 0 {
            return None;
        }
        let torrent = self.torrent.try_acquire(bytes)?;
        let global = self.global.try_acquire(bytes)?;
        Some(PieceBufferReservation {
            _torrent: torrent,
            _global: global,
        })
    }
}

impl Drop for BudgetCounterPermit {
    fn drop(&mut self) {
        let previous = self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
        debug_assert!(previous >= self.bytes);
    }
}

impl PieceManager {
    pub fn new(meta: &TorrentMeta) -> Result<Self, Error> {
        let piece_length = meta.info.piece_length;
        if piece_length == 0 || piece_length > MAX_PIECE_LENGTH {
            return Err(Error::InvalidPieceLength);
        }
        let piece_length = piece_length as u32;

        let pieces = match meta.meta_version {
            1 => Self::build_v1_pieces(meta, piece_length, None)?,
            2 => Self::build_v2_pieces(meta, piece_length)?,
            3 => {
                let v2_pieces = Self::build_v2_pieces(meta, piece_length)?;
                Self::build_v1_pieces(meta, piece_length, Some(&v2_pieces))?
            }
            _ => return Err(Error::InvalidPieces),
        };
        let piece_count = pieces.len();
        if piece_count == 0 || piece_count > u32::MAX as usize {
            return Err(Error::InvalidPieces);
        }

        let mut manager = Self {
            pieces,
            availability: vec![0; piece_count],
            reserved_by: vec![None; piece_count],
            reservation_time: vec![None; piece_count],
            sequential: false,
            candidates: Vec::new(),
            totals: Totals::default(),
        };
        manager.recount();
        Ok(manager)
    }

    fn build_v1_pieces(
        meta: &TorrentMeta,
        piece_length: u32,
        v2_pieces: Option<&[Piece]>,
    ) -> Result<Vec<Piece>, Error> {
        let piece_count = meta.info.pieces.len();
        if piece_count == 0 {
            return Err(Error::InvalidPieces);
        }

        let total_length = meta
            .info
            .checked_total_length()
            .ok_or(Error::InvalidPieces)?;
        if total_length == 0 {
            return Err(Error::InvalidPieces);
        }

        let min_total = (piece_count as u64 - 1)
            .checked_mul(piece_length as u64)
            .ok_or(Error::InvalidPieces)?;
        if total_length < min_total {
            return Err(Error::InvalidPieces);
        }
        let last_len = total_length - min_total;
        if last_len == 0 || last_len > piece_length as u64 {
            return Err(Error::InvalidPieces);
        }

        if v2_pieces.is_some_and(|v2_pieces| v2_pieces.len() != piece_count) {
            return Err(Error::InvalidPieces);
        }

        let mut pieces = Vec::with_capacity(piece_count);
        for (index, sha1_hash) in meta.info.pieces.iter().copied().enumerate() {
            let length = if index + 1 == piece_count {
                last_len as u32
            } else {
                piece_length
            };
            let offset = (index as u64)
                .checked_mul(piece_length as u64)
                .ok_or(Error::InvalidPieces)?;
            let hash = match v2_pieces.map(|v2_pieces| &v2_pieces[index]) {
                Some(Piece {
                    offset: v2_offset,
                    hash:
                        PieceHash::Sha256 {
                            root,
                            merkle_length,
                            data_length,
                        },
                    ..
                }) if *v2_offset == offset => PieceHash::Hybrid {
                    sha1: sha1_hash,
                    sha256: *root,
                    merkle_length: *merkle_length,
                    v2_data_length: *data_length,
                },
                Some(_) => return Err(Error::InvalidPieces),
                None => PieceHash::Sha1(sha1_hash),
            };
            pieces.push(Piece::new(hash, offset, length));
        }

        Ok(pieces)
    }

    fn build_v2_pieces(meta: &TorrentMeta, piece_length: u32) -> Result<Vec<Piece>, Error> {
        if piece_length < 16 * 1024 || !piece_length.is_power_of_two() {
            return Err(Error::InvalidPieceLength);
        }
        let piece_length_u64 = piece_length as u64;
        let mut pieces = Vec::new();
        let mut file_offset = 0u64;
        for entry in &meta.info.file_tree {
            if entry.length == 0 {
                continue;
            }
            let root = entry.pieces_root.ok_or(Error::InvalidPieces)?;
            let single = entry.length <= piece_length_u64;
            let file_piece_count = entry.length.div_ceil(piece_length_u64);
            let roots: &[[u8; 32]] = if single {
                std::slice::from_ref(&root)
            } else {
                let (_, hashes) = meta
                    .piece_layers
                    .iter()
                    .find(|(key, _)| key.as_slice() == root.as_slice())
                    .ok_or(Error::InvalidPieces)?;
                if u64::try_from(hashes.len()).ok() != Some(file_piece_count) {
                    return Err(Error::InvalidPieces);
                }
                hashes
            };
            if pieces.len().saturating_add(roots.len()) > u32::MAX as usize {
                return Err(Error::InvalidPieces);
            }

            for (file_piece_index, root) in roots.iter().enumerate() {
                let within_file = (file_piece_index as u64)
                    .checked_mul(piece_length_u64)
                    .ok_or(Error::InvalidPieces)?;
                let remaining = entry
                    .length
                    .checked_sub(within_file)
                    .ok_or(Error::InvalidPieces)?;
                let length = remaining.min(piece_length_u64) as u32;
                let merkle_length = if single {
                    v2_tree_length(length).ok_or(Error::InvalidPieces)?
                } else {
                    piece_length
                };
                let offset = file_offset
                    .checked_add(within_file)
                    .ok_or(Error::InvalidPieces)?;
                pieces.push(Piece::new(
                    PieceHash::Sha256 {
                        root: *root,
                        merkle_length,
                        data_length: length,
                    },
                    offset,
                    length,
                ));
            }
            file_offset = file_piece_count
                .checked_mul(piece_length_u64)
                .and_then(|span| file_offset.checked_add(span))
                .ok_or(Error::InvalidPieces)?;
        }
        Ok(pieces)
    }

    /// Recompute every aggregate from scratch after a bulk change.
    fn recount(&mut self) {
        self.totals = Totals::default();
        self.candidates.clear();
        self.candidates.resize(self.pieces.len().div_ceil(64), 0);
        for idx in 0..self.pieces.len() {
            self.account(idx, true);
        }
    }

    /// Add (`add`) or remove a piece's contribution to the aggregate counters
    /// and keep its bit in the candidate set current. Every mutation of a
    /// piece is bracketed by `account(idx, false)` / `account(idx, true)`.
    fn account(&mut self, idx: usize, add: bool) {
        let piece = &self.pieces[idx];
        let (word, bit) = (idx / 64, 1u64 << (63 - idx % 64));
        if add && piece.is_candidate() {
            self.candidates[word] |= bit;
        } else {
            self.candidates[word] &= !bit;
        }
        if !piece.wanted {
            return;
        }
        let verified = usize::from(piece.verified);
        let verified_bytes = if piece.verified {
            piece.length as u64
        } else {
            0
        };
        let remaining = piece.blocks.len() - piece.done as usize;
        let totals = &mut self.totals;
        if add {
            totals.wanted += 1;
            totals.wanted_bytes += piece.length as u64;
            totals.verified += verified;
            totals.verified_bytes += verified_bytes;
            totals.remaining_blocks += remaining;
        } else {
            totals.wanted -= 1;
            totals.wanted_bytes -= piece.length as u64;
            totals.verified -= verified;
            totals.verified_bytes -= verified_bytes;
            totals.remaining_blocks -= remaining;
        }
    }

    pub fn piece_count(&self) -> usize {
        self.pieces.len()
    }

    pub fn completed_pieces(&self) -> usize {
        self.totals.verified
    }

    pub fn completed_bytes(&self) -> u64 {
        self.totals.verified_bytes
    }

    pub fn remaining_blocks(&self) -> usize {
        self.totals.remaining_blocks
    }

    pub fn is_complete(&self) -> bool {
        self.totals.verified == self.totals.wanted
    }

    pub fn reset_verified(&mut self) {
        for piece in &mut self.pieces {
            piece.verified = false;
            piece.fill(BlockState::Missing);
        }
        self.reserved_by.fill(None);
        self.reservation_time.fill(None);
        self.recount();
    }

    pub fn piece_length(&self, index: u32) -> Option<u32> {
        self.pieces.get(index as usize).map(|piece| piece.length)
    }

    pub fn piece_offset(&self, index: u32) -> Option<u64> {
        self.pieces.get(index as usize).map(|piece| piece.offset)
    }

    pub fn piece_hash(&self, index: u32) -> Option<&PieceHash> {
        self.pieces.get(index as usize).map(|piece| &piece.hash)
    }

    pub fn is_piece_complete(&self, index: u32) -> bool {
        self.pieces
            .get(index as usize)
            .is_some_and(|piece| piece.verified)
    }

    pub fn is_piece_wanted(&self, index: u32) -> bool {
        self.pieces
            .get(index as usize)
            .is_some_and(|piece| piece.wanted)
    }

    #[cfg(test)]
    pub fn piece_priority(&self, index: u32) -> Option<u8> {
        self.pieces.get(index as usize).map(|piece| piece.priority)
    }

    pub fn wanted_bytes(&self) -> u64 {
        self.totals.wanted_bytes
    }

    pub fn wanted_pieces(&self) -> usize {
        self.totals.wanted
    }

    pub fn set_sequential(&mut self, sequential: bool) {
        self.sequential = sequential;
    }

    pub fn set_piece_priorities(&mut self, priorities: &[u8]) -> Result<(), Error> {
        if priorities.len() != self.pieces.len() {
            return Err(Error::InvalidPieces);
        }
        if priorities.iter().any(|priority| *priority > PRIORITY_HIGH) {
            return Err(Error::InvalidPriority);
        }
        for (idx, (piece, priority)) in self.pieces.iter_mut().zip(priorities).enumerate() {
            piece.priority = *priority;
            piece.wanted = *priority != PRIORITY_SKIP;
            if !piece.wanted {
                self.reserved_by[idx] = None;
                self.reservation_time[idx] = None;
            }
        }
        self.recount();
        Ok(())
    }

    pub fn bitfield_len(&self) -> usize {
        self.pieces.len().div_ceil(8)
    }

    pub fn apply_peer_bitfield(&mut self, bitfield: &[u8]) -> Result<(), Error> {
        self.validate_full_bitfield(bitfield)?;
        self.adjust_availability(bitfield, true);
        Ok(())
    }

    pub fn remove_peer_bitfield(&mut self, bitfield: &[u8]) -> Result<(), Error> {
        if bitfield.len() != self.bitfield_len() {
            return Err(Error::InvalidBitfield);
        }
        self.adjust_availability(bitfield, false);
        Ok(())
    }

    fn validate_full_bitfield(&self, bitfield: &[u8]) -> Result<(), Error> {
        if bitfield.len() != self.bitfield_len() {
            return Err(Error::InvalidBitfield);
        }
        let extra_bits = bitfield.len() * 8 - self.pieces.len();
        let mask = ((1u16 << extra_bits) - 1) as u8;
        if bitfield.last().is_some_and(|last| last & mask != 0) {
            return Err(Error::InvalidBitfield);
        }
        Ok(())
    }

    fn adjust_availability(&mut self, bitfield: &[u8], add: bool) {
        for (byte_index, byte) in bitfield.iter().enumerate() {
            let mut bits = *byte;
            while bits != 0 {
                let offset = bits.leading_zeros() as usize;
                bits &= !(0x80 >> offset);
                let idx = byte_index * 8 + offset;
                if let Some(value) = self.availability.get_mut(idx) {
                    *value = if add {
                        value.saturating_add(1)
                    } else {
                        value.saturating_sub(1)
                    };
                }
            }
        }
    }

    pub fn apply_have(&mut self, index: u32) -> Result<(), Error> {
        let value = self
            .availability
            .get_mut(index as usize)
            .ok_or(Error::InvalidPiece)?;
        *value = value.saturating_add(1);
        Ok(())
    }

    /// Word `word` of `candidates & peer bitfield`, MSB = lowest piece index.
    fn peer_candidates(&self, bitfield: &[u8], word: usize) -> u64 {
        let start = word * 8;
        let bytes = &bitfield[start..bitfield.len().min(start + 8)];
        let mut peer = [0u8; 8];
        peer[..bytes.len()].copy_from_slice(bytes);
        self.candidates[word] & u64::from_be_bytes(peer)
    }

    /// Pick the best candidate the peer has, preferring higher priority and
    /// then rarer pieces (lowest index on ties). `stale_before` switches to
    /// stealing: only pieces reserved by another peer before that instant.
    fn pick(
        &self,
        peer_id: u64,
        bitfield: &[u8],
        allow_reserved: bool,
        stale_before: Option<Instant>,
    ) -> Option<usize> {
        if bitfield.len() != self.bitfield_len() {
            return None;
        }
        let mut best: Option<(usize, u8, u32)> = None;
        for word in 0..self.candidates.len() {
            let mut bits = self.peer_candidates(bitfield, word);
            while bits != 0 {
                let offset = bits.leading_zeros() as usize;
                bits &= !(1u64 << (63 - offset));
                let idx = word * 64 + offset;
                match stale_before {
                    Some(cutoff) => {
                        if self.reserved_by[idx].is_none_or(|owner| owner == peer_id)
                            || self.reservation_time[idx].is_none_or(|at| at > cutoff)
                        {
                            continue;
                        }
                    }
                    None if !allow_reserved && self.reserved_by[idx].is_some() => continue,
                    None if self.sequential => return Some(idx),
                    None => {}
                }
                let priority = self.pieces[idx].priority;
                let rarity = self.availability[idx];
                if best.is_none_or(|(_, best_priority, best_rarity)| {
                    priority > best_priority || (priority == best_priority && rarity < best_rarity)
                }) {
                    best = Some((idx, priority, rarity));
                }
            }
        }
        best.map(|(idx, _, _)| idx)
    }

    fn reserve(&mut self, idx: usize, peer_id: u64, now: Instant) -> u32 {
        self.reserved_by[idx] = Some(peer_id);
        self.reservation_time[idx] = Some(now);
        idx as u32
    }

    pub fn reserve_piece_for_peer(
        &mut self,
        peer_id: u64,
        bitfield: &[u8],
        allow_reserved: bool,
    ) -> Option<u32> {
        let idx = self.pick(peer_id, bitfield, allow_reserved, None)?;
        if allow_reserved {
            return Some(idx as u32);
        }
        Some(self.reserve(idx, peer_id, Instant::now()))
    }

    pub fn has_needed_piece(&self, bitfield: &[u8]) -> bool {
        bitfield.len() == self.bitfield_len()
            && (0..self.candidates.len()).any(|word| self.peer_candidates(bitfield, word) != 0)
    }

    pub fn release_piece(&mut self, peer_id: u64, index: u32) {
        let idx = index as usize;
        if self.reserved_by.get(idx) == Some(&Some(peer_id)) {
            self.clear_reservation(index);
        }
    }

    pub fn clear_reservation(&mut self, index: u32) {
        let idx = index as usize;
        if idx < self.reserved_by.len() {
            self.reserved_by[idx] = None;
            self.reservation_time[idx] = None;
        }
    }

    /// Steal a piece that has been reserved by another peer for longer than
    /// `stale_threshold`. Returns the piece index if a stale reservation was
    /// found and reassigned to `peer_id`.
    pub fn steal_stale_piece(
        &mut self,
        peer_id: u64,
        bitfield: &[u8],
        stale_threshold: Duration,
    ) -> Option<u32> {
        let now = Instant::now();
        // A threshold beyond the monotonic clock's range cannot be stale yet.
        let cutoff = now.checked_sub(stale_threshold)?;
        let idx = self.pick(peer_id, bitfield, true, Some(cutoff))?;
        Some(self.reserve(idx, peer_id, now))
    }

    pub fn next_request_for_piece(
        &mut self,
        index: u32,
        allow_duplicate: bool,
    ) -> Option<BlockRequest> {
        let idx = index as usize;
        let piece = self.pieces.get(idx)?;
        if !piece.wanted {
            return None;
        }
        let block_index = piece.next_requestable_block(allow_duplicate)?;
        self.set_block(idx, block_index, BlockState::Requested);
        let piece = &self.pieces[idx];
        Some(BlockRequest {
            index,
            begin: block_index as u32 * BLOCK_LEN,
            length: piece.block_length(block_index),
        })
    }

    /// Apply a block state transition while keeping the aggregates current.
    /// `Requested` only replaces `Missing`; `Missing` never replaces
    /// `Complete`.
    fn set_block(&mut self, idx: usize, block_index: usize, state: BlockState) {
        let current = self.pieces[idx].blocks[block_index];
        let allowed = match state {
            BlockState::Requested => current == BlockState::Missing,
            BlockState::Missing => current == BlockState::Requested,
            BlockState::Complete => current != BlockState::Complete,
        };
        if !allowed {
            return;
        }
        self.account(idx, false);
        let piece = &mut self.pieces[idx];
        match current {
            BlockState::Missing => piece.missing -= 1,
            BlockState::Complete => piece.done -= 1,
            BlockState::Requested => {}
        }
        match state {
            BlockState::Missing => piece.missing += 1,
            BlockState::Complete => piece.done += 1,
            BlockState::Requested => {}
        }
        piece.blocks[block_index] = state;
        self.account(idx, true);
    }

    #[cfg(test)]
    pub fn select_next_request(&mut self, bitfield: &[u8]) -> Option<BlockRequest> {
        if bitfield.len() != self.bitfield_len() {
            return None;
        }

        let mut best_piece = None;
        let mut best_rarity = u32::MAX;
        for (idx, piece) in self.pieces.iter().enumerate() {
            if piece.verified || piece.missing == 0 {
                continue;
            }
            if !bitfield_has(bitfield, idx) {
                continue;
            }
            let rarity = self.availability[idx];
            if rarity < best_rarity {
                best_rarity = rarity;
                best_piece = Some(idx);
            }
        }

        let idx = best_piece?;
        let block_index = self.pieces[idx].next_requestable_block(false)?;
        self.set_block(idx, block_index, BlockState::Requested);
        Some(BlockRequest {
            index: idx as u32,
            begin: block_index as u32 * BLOCK_LEN,
            length: self.pieces[idx].block_length(block_index),
        })
    }

    fn block_index(&self, index: u32, begin: u32) -> Result<(usize, usize), Error> {
        let idx = index as usize;
        let piece = self.pieces.get(idx).ok_or(Error::InvalidPiece)?;
        let block_index = (begin / BLOCK_LEN) as usize;
        if !begin.is_multiple_of(BLOCK_LEN) || block_index >= piece.blocks.len() {
            return Err(Error::InvalidBlock);
        }
        Ok((idx, block_index))
    }

    pub fn mark_block_complete(
        &mut self,
        index: u32,
        begin: u32,
        length: u32,
    ) -> Result<bool, Error> {
        let (idx, block_index) = self.block_index(index, begin)?;
        let piece = &self.pieces[idx];
        if piece.block_length(block_index) != length {
            return Err(Error::InvalidBlock);
        }
        if piece.blocks[block_index] == BlockState::Complete {
            return Ok(false);
        }
        self.set_block(idx, block_index, BlockState::Complete);
        Ok(true)
    }

    pub fn mark_piece_complete(&mut self, index: u32) -> Result<bool, Error> {
        self.set_piece_state(index, true)
    }

    pub fn mark_block_missing(&mut self, index: u32, begin: u32) -> Result<(), Error> {
        let (idx, block_index) = self.block_index(index, begin)?;
        self.set_block(idx, block_index, BlockState::Missing);
        Ok(())
    }

    pub fn reset_piece(&mut self, index: u32) -> Result<(), Error> {
        self.set_piece_state(index, false).map(|_| ())
    }

    /// Mark a piece verified (all blocks complete) or reset it to missing.
    /// Either way its reservation ends. Returns whether `verified` changed.
    fn set_piece_state(&mut self, index: u32, verified: bool) -> Result<bool, Error> {
        let idx = index as usize;
        let changed = self.pieces.get(idx).ok_or(Error::InvalidPiece)?.verified != verified;
        self.account(idx, false);
        let piece = &mut self.pieces[idx];
        piece.verified = verified;
        piece.fill(if verified {
            BlockState::Complete
        } else {
            BlockState::Missing
        });
        self.account(idx, true);
        self.clear_reservation(index);
        Ok(changed)
    }
}

impl PieceBuffer {
    pub fn try_new(
        index: u32,
        length: u32,
        budgets: &PieceBufferBudgets,
    ) -> Result<Option<Self>, Error> {
        if length == 0 || length as u64 > MAX_PIECE_LENGTH {
            return Err(Error::InvalidPieceLength);
        }
        let blocks = block_count(length);
        let allocation_bytes = (length as usize)
            .checked_add(blocks)
            .ok_or(Error::InvalidPieceLength)?;
        let Some(reservation) = budgets.try_reserve(allocation_bytes) else {
            return Ok(None);
        };
        Self::allocate(index, length, Some(reservation)).map(Some)
    }

    #[cfg(test)]
    pub fn new(index: u32, length: u32) -> Result<Self, Error> {
        Self::allocate(index, length, None)
    }

    fn allocate(
        index: u32,
        length: u32,
        budget_reservation: Option<PieceBufferReservation>,
    ) -> Result<Self, Error> {
        if length == 0 || length as u64 > MAX_PIECE_LENGTH {
            return Err(Error::InvalidPieceLength);
        }
        let blocks = block_count(length);
        let mut data = Vec::new();
        data.try_reserve_exact(length as usize)
            .map_err(|_| Error::InvalidPieceLength)?;
        data.resize(length as usize, 0);
        let mut block_map = Vec::new();
        block_map
            .try_reserve_exact(blocks)
            .map_err(|_| Error::InvalidPieceLength)?;
        block_map.resize(blocks, 0);
        Ok(Self {
            index,
            length,
            data,
            blocks: block_map,
            complete: 0,
            _budget_reservation: budget_reservation,
        })
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn length(&self) -> u32 {
        self.length
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn add_block(&mut self, begin: u32, block: &[u8]) -> Result<bool, Error> {
        if !begin.is_multiple_of(BLOCK_LEN) {
            return Err(Error::InvalidBlock);
        }
        let block_index = (begin / BLOCK_LEN) as usize;
        if block_index >= self.blocks.len() {
            return Err(Error::InvalidBlock);
        }
        let expected_len = self.block_length(block_index) as usize;
        if block.len() != expected_len {
            return Err(Error::InvalidBlock);
        }
        let start = begin as usize;
        let end = start + block.len();
        if end > self.data.len() {
            return Err(Error::InvalidBlock);
        }
        if self.blocks[block_index] == 0 {
            self.data[start..end].copy_from_slice(block);
            self.blocks[block_index] = 1;
            self.complete += 1;
        }
        Ok(self.is_complete())
    }

    pub fn is_complete(&self) -> bool {
        self.complete == self.blocks.len()
    }

    fn block_length(&self, block_index: usize) -> u32 {
        let begin = block_index as u32 * BLOCK_LEN;
        let remaining = self.length.saturating_sub(begin);
        remaining.min(BLOCK_LEN)
    }
}

fn block_count(length: u32) -> usize {
    (length as u64).div_ceil(BLOCK_LEN as u64) as usize
}

fn v2_tree_length(data_length: u32) -> Option<u32> {
    let blocks = data_length.div_ceil(BLOCK_LEN);
    blocks.checked_next_power_of_two()?.checked_mul(BLOCK_LEN)
}

#[cfg(test)]
fn bitfield_has(bitfield: &[u8], index: usize) -> bool {
    let byte = bitfield[index / 8];
    let offset = index % 8;
    let mask = 0x80 >> offset;
    (byte & mask) != 0
}

impl Piece {
    fn new(hash: PieceHash, offset: u64, length: u32) -> Self {
        let blocks = block_count(length);
        Self {
            hash,
            offset,
            length,
            blocks: vec![BlockState::Missing; blocks],
            missing: blocks as u32,
            done: 0,
            priority: PRIORITY_NORMAL,
            wanted: true,
            verified: false,
        }
    }

    fn is_candidate(&self) -> bool {
        self.wanted && !self.verified && self.missing > 0
    }

    fn fill(&mut self, state: BlockState) {
        self.blocks.fill(state);
        let count = self.blocks.len() as u32;
        self.missing = if state == BlockState::Missing {
            count
        } else {
            0
        };
        self.done = if state == BlockState::Complete {
            count
        } else {
            0
        };
    }

    fn next_requestable_block(&self, allow_duplicate: bool) -> Option<usize> {
        let find = |wanted| self.blocks.iter().position(|state| *state == wanted);
        if self.missing > 0 {
            return find(BlockState::Missing);
        }
        if allow_duplicate {
            return find(BlockState::Requested);
        }
        None
    }

    fn block_length(&self, block_index: usize) -> u32 {
        let begin = block_index as u32 * BLOCK_LEN;
        let remaining = self.length.saturating_sub(begin);
        remaining.min(BLOCK_LEN)
    }
}

#[cfg(test)]
mod priority_tests {
    use super::*;
    use crate::torrent::{InfoDict, TorrentMeta};

    fn dummy_meta() -> TorrentMeta {
        TorrentMeta {
            announce: None,
            announce_list: Vec::new(),
            url_list: Vec::new(),
            httpseeds: Vec::new(),
            info_hash: [0u8; 20],
            info_hash_v2: None,
            piece_layers: Vec::new(),
            meta_version: 1,
            info: InfoDict {
                name: b"test".to_vec(),
                piece_length: 16,
                pieces: vec![[1u8; 20], [2u8; 20]],
                length: Some(32),
                files: Vec::new(),
                private: false,
                file_tree: Vec::new(),
            },
        }
    }

    #[test]
    fn prefers_high_priority_piece() {
        let meta = dummy_meta();
        let mut manager = PieceManager::new(&meta).unwrap();
        manager
            .set_piece_priorities(&[PRIORITY_LOW, PRIORITY_HIGH])
            .unwrap();
        let bitfield = vec![0b1100_0000];
        let selected = manager.reserve_piece_for_peer(1, &bitfield, false);
        assert_eq!(selected, Some(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::torrent::{FileInfo, FileTreeEntry, InfoDict, TorrentMeta};

    fn dummy_meta(pieces: usize, piece_length: u64, total_length: u64) -> TorrentMeta {
        let mut hashes = Vec::with_capacity(pieces);
        for i in 0..pieces {
            let mut hash = [0u8; 20];
            hash[0] = i as u8;
            hashes.push(hash);
        }
        TorrentMeta {
            announce: None,
            announce_list: Vec::new(),
            url_list: Vec::new(),
            httpseeds: Vec::new(),
            info_hash: [0u8; 20],
            info_hash_v2: None,
            piece_layers: Vec::new(),
            meta_version: 1,
            info: InfoDict {
                name: b"dummy".to_vec(),
                piece_length,
                pieces: hashes,
                length: Some(total_length),
                files: Vec::new(),
                private: false,
                file_tree: Vec::new(),
            },
        }
    }

    #[test]
    fn selects_rarest_piece() {
        let meta = dummy_meta(3, 16 * 1024, 48 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        let mut bitfield = vec![0b1010_0000];
        manager.apply_peer_bitfield(&bitfield).unwrap();

        let req = manager.select_next_request(&bitfield).unwrap();
        assert_eq!(req.index, 0);

        bitfield[0] = 0b1110_0000;
        manager.apply_peer_bitfield(&bitfield).unwrap();
        let req = manager.select_next_request(&bitfield).unwrap();
        assert_eq!(req.index, 1);
    }

    #[test]
    fn last_piece_shorter() {
        let meta = dummy_meta(2, 16 * 1024, 20 * 1024);
        let manager = PieceManager::new(&meta).unwrap();
        assert_eq!(manager.pieces[0].length, 16 * 1024);
        assert_eq!(manager.pieces[1].length, 4 * 1024);
    }

    #[test]
    fn rejects_an_extra_zero_length_piece() {
        let meta = dummy_meta(2, 16 * 1024, 16 * 1024);
        assert!(matches!(
            PieceManager::new(&meta),
            Err(Error::InvalidPieces)
        ));
    }

    #[test]
    fn apply_peer_bitfield_rejects_extra_bits() {
        let meta = dummy_meta(9, 16 * 1024, 9 * 16 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        let bitfield = [0xFF, 0x40];
        assert!(matches!(
            manager.apply_peer_bitfield(&bitfield),
            Err(Error::InvalidBitfield)
        ));
    }

    #[test]
    fn sequential_mode_prefers_lowest_index_piece() {
        let meta = dummy_meta(3, 16 * 1024, 48 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        manager.set_sequential(true);
        manager.mark_piece_complete(0).unwrap();
        let bitfield = [0b1110_0000];
        assert_eq!(manager.reserve_piece_for_peer(7, &bitfield, false), Some(1));
    }

    #[test]
    fn skipping_piece_clears_existing_reservation() {
        let meta = dummy_meta(2, 16 * 1024, 32 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        let bitfield = [0b1100_0000];
        assert_eq!(manager.reserve_piece_for_peer(1, &bitfield, false), Some(0));
        manager
            .set_piece_priorities(&[PRIORITY_SKIP, PRIORITY_NORMAL])
            .unwrap();
        assert_eq!(manager.reserve_piece_for_peer(2, &bitfield, false), Some(1));
    }

    #[test]
    fn next_request_for_piece_allows_duplicate_when_enabled() {
        let meta = dummy_meta(1, 16 * 1024, 16 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        let first = manager.next_request_for_piece(0, false).unwrap();
        assert_eq!(first.begin, 0);
        assert!(manager.next_request_for_piece(0, false).is_none());
        let duplicate = manager.next_request_for_piece(0, true).unwrap();
        assert_eq!(duplicate.begin, 0);
        assert_eq!(duplicate.length, first.length);
    }

    #[test]
    fn mark_block_complete_validates_alignment_and_size() {
        let meta = dummy_meta(1, 16 * 1024, 16 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        assert!(matches!(
            manager.mark_block_complete(0, 1, 16 * 1024),
            Err(Error::InvalidBlock)
        ));
        assert!(matches!(
            manager.mark_block_complete(0, 0, 8),
            Err(Error::InvalidBlock)
        ));
        assert!(manager.mark_block_complete(0, 0, 16 * 1024).unwrap());
        assert!(!manager.mark_block_complete(0, 0, 16 * 1024).unwrap());
    }

    #[test]
    fn complete_requires_hash_verified_piece_not_only_received_blocks() {
        let meta = dummy_meta(1, 16 * 1024, 16 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();

        assert!(manager.mark_block_complete(0, 0, 16 * 1024).unwrap());

        assert!(!manager.is_piece_complete(0));
        assert!(!manager.is_complete());
        assert_eq!(manager.completed_pieces(), 0);

        manager.mark_piece_complete(0).unwrap();

        assert!(manager.is_piece_complete(0));
        assert!(manager.is_complete());
        assert_eq!(manager.completed_pieces(), 1);
    }

    #[test]
    fn piece_buffer_tracks_completion_across_blocks() {
        let mut buffer = PieceBuffer::new(2, BLOCK_LEN + 4).unwrap();
        let first = vec![1u8; BLOCK_LEN as usize];
        let second = vec![2u8; 4];
        assert!(!buffer.add_block(0, &first).unwrap());
        assert!(buffer.add_block(BLOCK_LEN, &second).unwrap());
        assert!(buffer.is_complete());
        assert_eq!(&buffer.data()[BLOCK_LEN as usize..], second.as_slice());
    }

    #[test]
    fn piece_buffer_budgets_backpressure_and_release_with_buffer_lifetime() {
        let allocation = BLOCK_LEN as usize + 1;
        let global = Arc::new(PieceBufferBudget::new(allocation));
        let torrent = Arc::new(PieceBufferBudget::new(allocation * 2));
        let budgets = PieceBufferBudgets::new(Arc::clone(&global), Arc::clone(&torrent));

        let first = PieceBuffer::try_new(0, BLOCK_LEN, &budgets)
            .unwrap()
            .unwrap();
        assert_eq!(global.used(), allocation);
        assert_eq!(torrent.used(), allocation);
        assert!(PieceBuffer::try_new(1, BLOCK_LEN, &budgets)
            .unwrap()
            .is_none());
        assert_eq!(global.used(), allocation);
        assert_eq!(torrent.used(), allocation);

        drop(first);
        assert_eq!(global.used(), 0);
        assert_eq!(torrent.used(), 0);
        let second = PieceBuffer::try_new(1, BLOCK_LEN, &budgets)
            .unwrap()
            .unwrap();
        drop(second);
        assert_eq!(global.used(), 0);
        assert_eq!(torrent.used(), 0);
    }

    #[test]
    fn generic_piece_buffer_reservation_releases_both_budgets() {
        let global = Arc::new(PieceBufferBudget::new(32));
        let torrent = Arc::new(PieceBufferBudget::new(16));
        let budgets = PieceBufferBudgets::new(Arc::clone(&global), Arc::clone(&torrent));

        let reservation = budgets.try_reserve(12).unwrap();
        assert_eq!(global.used(), 12);
        assert_eq!(torrent.used(), 12);
        assert!(budgets.try_reserve(5).is_none());
        assert_eq!(global.used(), 12);
        assert_eq!(torrent.used(), 12);

        drop(reservation);
        assert_eq!(global.used(), 0);
        assert_eq!(torrent.used(), 0);
        assert!(budgets.try_reserve(0).is_none());
    }

    #[test]
    fn priority_updates_are_atomic_on_validation_error() {
        let meta = dummy_meta(2, 16 * 1024, 32 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        assert!(matches!(
            manager.set_piece_priorities(&[PRIORITY_SKIP, PRIORITY_HIGH + 1]),
            Err(Error::InvalidPriority)
        ));
        assert_eq!(manager.piece_priority(0), Some(PRIORITY_NORMAL));
        assert!(manager.is_piece_wanted(0));
    }

    #[test]
    fn v2_files_have_aligned_offsets_and_merkle_verification() {
        let first_data = b"abc";
        let second_data = b"hello";
        let meta = TorrentMeta {
            announce: None,
            announce_list: Vec::new(),
            url_list: Vec::new(),
            httpseeds: Vec::new(),
            info_hash: [0; 20],
            info_hash_v2: Some([0; 32]),
            piece_layers: Vec::new(),
            meta_version: 2,
            info: InfoDict {
                name: b"v2".to_vec(),
                piece_length: 64 * 1024,
                pieces: Vec::new(),
                length: None,
                files: Vec::new(),
                private: false,
                file_tree: vec![
                    FileTreeEntry {
                        path: vec![b"a".to_vec()],
                        length: first_data.len() as u64,
                        pieces_root: Some(sha256::sha256(first_data)),
                    },
                    FileTreeEntry {
                        path: vec![b"b".to_vec()],
                        length: second_data.len() as u64,
                        pieces_root: Some(sha256::sha256(second_data)),
                    },
                ],
            },
        };

        let manager = PieceManager::new(&meta).unwrap();
        assert_eq!(manager.piece_count(), 2);
        assert_eq!(manager.piece_offset(0), Some(0));
        assert_eq!(manager.piece_offset(1), Some(64 * 1024));
        assert_eq!(manager.piece_length(0), Some(3));
        assert_eq!(manager.piece_length(1), Some(5));
        assert!(manager.piece_hash(0).unwrap().verify(first_data));
        assert!(manager.piece_hash(1).unwrap().verify(second_data));
        assert!(!manager.piece_hash(1).unwrap().verify(b"HELLO"));
    }

    #[test]
    fn hybrid_pieces_require_both_hash_families() {
        let mut first_piece = b"abc".to_vec();
        first_piece.resize(16 * 1024, 0);
        let second_piece = b"hello".to_vec();
        let meta = TorrentMeta {
            announce: None,
            announce_list: Vec::new(),
            url_list: Vec::new(),
            httpseeds: Vec::new(),
            info_hash: [0; 20],
            info_hash_v2: Some([0; 32]),
            piece_layers: Vec::new(),
            meta_version: 3,
            info: InfoDict {
                name: b"hybrid".to_vec(),
                piece_length: 16 * 1024,
                pieces: vec![sha1::sha1(&first_piece), sha1::sha1(&second_piece)],
                length: None,
                files: vec![
                    FileInfo {
                        length: 3,
                        path: vec![b"a".to_vec()],
                        attr: Vec::new(),
                    },
                    FileInfo {
                        length: 16 * 1024 - 3,
                        path: vec![b".pad".to_vec(), b"16381".to_vec()],
                        attr: b"p".to_vec(),
                    },
                    FileInfo {
                        length: 5,
                        path: vec![b"b".to_vec()],
                        attr: Vec::new(),
                    },
                ],
                private: false,
                file_tree: vec![
                    FileTreeEntry {
                        path: vec![b"a".to_vec()],
                        length: 3,
                        pieces_root: Some(sha256::sha256(b"abc")),
                    },
                    FileTreeEntry {
                        path: vec![b"b".to_vec()],
                        length: 5,
                        pieces_root: Some(sha256::sha256(b"hello")),
                    },
                ],
            },
        };

        let manager = PieceManager::new(&meta).unwrap();
        assert!(matches!(
            manager.piece_hash(0),
            Some(PieceHash::Hybrid { .. })
        ));
        assert!(manager.piece_hash(0).unwrap().verify(&first_piece));
        assert!(manager.piece_hash(1).unwrap().verify(&second_piece));

        let mut nonzero_padding = first_piece;
        *nonzero_padding.last_mut().unwrap() = 1;
        assert!(!manager.piece_hash(0).unwrap().verify(&nonzero_padding));
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// The straightforward O(pieces) picker the incremental candidate set
    /// replaced; used as an oracle.
    fn reference_pick(
        manager: &PieceManager,
        peer_id: u64,
        bitfield: &[u8],
        allow_reserved: bool,
    ) -> Option<usize> {
        let mut best: Option<(usize, u8, u32)> = None;
        for (idx, piece) in manager.pieces.iter().enumerate() {
            let has_missing = piece.blocks.contains(&BlockState::Missing);
            if piece.verified || !has_missing || !piece.wanted || !bitfield_has(bitfield, idx) {
                continue;
            }
            if !allow_reserved && manager.reserved_by[idx].is_some() {
                continue;
            }
            let _ = peer_id;
            if manager.sequential {
                return Some(idx);
            }
            let (priority, rarity) = (piece.priority, manager.availability[idx]);
            if best.is_none_or(|(_, bp, br)| priority > bp || (priority == bp && rarity < br)) {
                best = Some((idx, priority, rarity));
            }
        }
        best.map(|(idx, _, _)| idx)
    }

    fn check_totals(manager: &PieceManager) {
        let wanted = manager.pieces.iter().filter(|piece| piece.wanted);
        assert_eq!(manager.wanted_pieces(), wanted.clone().count());
        assert_eq!(
            manager.wanted_bytes(),
            wanted.clone().map(|piece| piece.length as u64).sum::<u64>()
        );
        let verified = wanted.clone().filter(|piece| piece.verified);
        assert_eq!(manager.completed_pieces(), verified.clone().count());
        assert_eq!(
            manager.completed_bytes(),
            verified.map(|piece| piece.length as u64).sum::<u64>()
        );
        assert_eq!(
            manager.remaining_blocks(),
            wanted
                .map(|piece| {
                    piece
                        .blocks
                        .iter()
                        .filter(|state| **state != BlockState::Complete)
                        .count()
                })
                .sum::<usize>()
        );
        for (idx, piece) in manager.pieces.iter().enumerate() {
            assert_eq!(
                piece.missing as usize,
                piece
                    .blocks
                    .iter()
                    .filter(|state| **state == BlockState::Missing)
                    .count()
            );
            let bit = manager.candidates[idx / 64] >> (63 - idx % 64) & 1 == 1;
            assert_eq!(bit, piece.is_candidate(), "candidate bit for {idx}");
        }
    }

    #[test]
    fn incremental_picker_matches_reference_under_random_operations() {
        // 150 pieces of 3 blocks each, last piece shorter: exercises partial
        // trailing bitfield bytes and a partial final candidate word.
        let meta = dummy_meta(150, 48 * 1024, 149 * 48 * 1024 + 20_000);
        let mut manager = PieceManager::new(&meta).unwrap();
        let mut rng = Lcg(7);
        let len = manager.bitfield_len();
        let random_bitfield = |rng: &mut Lcg| {
            let mut bitfield = (0..len).map(|_| rng.next() as u8).collect::<Vec<_>>();
            *bitfield.last_mut().unwrap() &= 0xFC; // 150 pieces: 2 spare bits
            bitfield
        };
        for step in 0..4_000 {
            let piece = rng.below(150) as u32;
            match rng.below(12) {
                0 => {
                    let bitfield = random_bitfield(&mut rng);
                    manager.apply_peer_bitfield(&bitfield).unwrap();
                }
                1 => manager.apply_have(piece).unwrap(),
                2 => {
                    let _ = manager.next_request_for_piece(piece, rng.below(2) == 0);
                }
                3 => {
                    let begin = rng.below(3) as u32 * BLOCK_LEN;
                    let length =
                        manager.pieces[piece as usize].block_length(begin as usize / 16_384);
                    let _ = manager.mark_block_complete(piece, begin, length);
                }
                4 => {
                    let _ = manager.mark_block_missing(piece, rng.below(3) as u32 * BLOCK_LEN);
                }
                5 => {
                    manager.mark_piece_complete(piece).unwrap();
                }
                6 => manager.reset_piece(piece).unwrap(),
                7 if step % 50 == 0 => {
                    let priorities = (0..150).map(|_| rng.below(4) as u8).collect::<Vec<_>>();
                    manager.set_piece_priorities(&priorities).unwrap();
                }
                8 => manager.set_sequential(rng.below(4) == 0),
                9 => manager.release_piece(rng.below(3), piece),
                10 if step % 400 == 0 => manager.reset_verified(),
                _ => {
                    let bitfield = random_bitfield(&mut rng);
                    let allow_reserved = rng.below(3) == 0;
                    let peer = rng.below(3);
                    let expected = reference_pick(&manager, peer, &bitfield, allow_reserved);
                    assert_eq!(
                        manager.has_needed_piece(&bitfield),
                        reference_pick(&manager, peer, &bitfield, true).is_some()
                    );
                    let chosen = manager.reserve_piece_for_peer(peer, &bitfield, allow_reserved);
                    assert_eq!(chosen.map(|idx| idx as usize), expected, "step {step}");
                }
            }
            check_totals(&manager);
        }
    }

    #[test]
    fn steal_only_takes_stale_reservations_from_other_peers() {
        let meta = dummy_meta(3, 16 * 1024, 48 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        let all = [0b1110_0000];
        assert_eq!(manager.reserve_piece_for_peer(1, &all, false), Some(0));
        assert_eq!(manager.reserve_piece_for_peer(2, &all, false), Some(1));
        assert_eq!(
            manager.steal_stale_piece(1, &all, Duration::from_secs(3600)),
            None
        );
        assert_eq!(manager.steal_stale_piece(1, &all, Duration::ZERO), Some(1));
        assert_eq!(manager.reserved_by[1], Some(1));
        assert_eq!(
            manager.steal_stale_piece(1, &all, Duration::from_secs(u64::MAX)),
            None
        );
    }

    #[test]
    fn bitfield_word_extraction_handles_short_tails() {
        let meta = dummy_meta(70, 16 * 1024, 70 * 16 * 1024);
        let mut manager = PieceManager::new(&meta).unwrap();
        for index in 0..69 {
            manager.mark_piece_complete(index).unwrap();
        }
        let mut bitfield = vec![0u8; manager.bitfield_len()];
        assert!(!manager.has_needed_piece(&bitfield));
        bitfield[8] = 0b0000_0100; // piece 69
        assert!(manager.has_needed_piece(&bitfield));
        assert_eq!(
            manager.reserve_piece_for_peer(1, &bitfield, false),
            Some(69)
        );
        assert!(!manager.has_needed_piece(&bitfield[..8]));
    }

    /// `cargo test --release piece_picker_benchmark -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn piece_picker_benchmark() {
        let pieces = 50_000usize;
        let meta = dummy_meta(pieces, 1 << 20, pieces as u64 * (1 << 20));
        let mut manager = PieceManager::new(&meta).unwrap();
        let full = vec![0xFFu8; manager.bitfield_len()];
        let mut sparse = vec![0u8; manager.bitfield_len()];
        for (index, byte) in sparse.iter_mut().enumerate() {
            if index % 97 == 0 {
                *byte = 0x10;
            }
        }
        for _ in 0..20 {
            manager.apply_peer_bitfield(&full).unwrap();
        }
        // 90% of the torrent is already verified.
        for index in 0..(pieces as u32 * 9 / 10) {
            manager.mark_piece_complete(index).unwrap();
        }
        let started = Instant::now();
        let mut picked = 0usize;
        for round in 0..2_000u64 {
            let bitfield = if round % 2 == 0 { &full } else { &sparse };
            if let Some(index) = manager.reserve_piece_for_peer(round, bitfield, false) {
                picked += 1;
                manager.release_piece(round, index);
            }
            let _ = manager.has_needed_piece(bitfield);
            let _ = manager.completed_pieces();
            let _ = manager.is_complete();
            let _ = manager.remaining_blocks();
        }
        println!(
            "2000 picks over {pieces} pieces: {:?} ({picked} picked)",
            started.elapsed()
        );
    }
}
