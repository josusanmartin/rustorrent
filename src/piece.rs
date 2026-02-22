use std::fmt;

use crate::torrent::TorrentMeta;

pub const BLOCK_LEN: u32 = 16 * 1024;
pub const PRIORITY_SKIP: u8 = 0;
#[allow(dead_code)]
pub const PRIORITY_LOW: u8 = 1;
pub const PRIORITY_NORMAL: u8 = 2;
pub const PRIORITY_HIGH: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    Missing,
    Requested,
    Complete,
}

#[derive(Debug, Clone)]
pub struct Piece {
    pub index: u32,
    pub hash: [u8; 20],
    pub length: u32,
    blocks: Vec<BlockState>,
    priority: u8,
    wanted: bool,
    verified: bool,
}

#[derive(Debug)]
pub struct PieceManager {
    pieces: Vec<Piece>,
    availability: Vec<u32>,
    reserved_by: Vec<Option<u64>>,
    sequential: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct BlockRequest {
    pub index: u32,
    pub begin: u32,
    pub length: u32,
}

#[derive(Debug)]
pub struct PieceBuffer {
    index: u32,
    length: u32,
    data: Vec<u8>,
    blocks: Vec<u8>,
    complete: usize,
}

#[derive(Debug)]
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
        match self {
            Error::InvalidPieceLength => write!(f, "invalid piece length"),
            Error::InvalidPieces => write!(f, "invalid pieces"),
            Error::InvalidBitfield => write!(f, "invalid bitfield"),
            Error::InvalidPiece => write!(f, "invalid piece index"),
            Error::InvalidBlock => write!(f, "invalid block"),
            Error::InvalidPriority => write!(f, "invalid priority"),
        }
    }
}

impl std::error::Error for Error {}

impl PieceManager {
    pub fn new(meta: &TorrentMeta) -> Result<Self, Error> {
        let piece_count = meta.info.pieces.len();
        if piece_count == 0 {
            return Err(Error::InvalidPieces);
        }

        let total_length = meta.info.total_length();
        if total_length == 0 {
            return Err(Error::InvalidPieces);
        }

        let piece_length = meta.info.piece_length;
        if piece_length == 0 || piece_length > u32::MAX as u64 {
            return Err(Error::InvalidPieceLength);
        }
        let piece_length = piece_length as u32;

        let min_total = (piece_count as u64 - 1).saturating_mul(piece_length as u64);
        if total_length < min_total {
            return Err(Error::InvalidPieces);
        }
        let mut last_len = total_length - min_total;
        if last_len == 0 {
            last_len = piece_length as u64;
        }
        if last_len > piece_length as u64 {
            return Err(Error::InvalidPieces);
        }

        let mut pieces = Vec::with_capacity(piece_count);
        for (index, hash) in meta.info.pieces.iter().enumerate() {
            let length = if index + 1 == piece_count {
                last_len as u32
            } else {
                piece_length
            };
            let blocks = block_count(length);
            pieces.push(Piece {
                index: index as u32,
                hash: *hash,
                length,
                blocks: vec![BlockState::Missing; blocks],
                priority: PRIORITY_NORMAL,
                wanted: true,
                verified: false,
            });
        }

        Ok(Self {
            pieces,
            availability: vec![0; piece_count],
            reserved_by: vec![None; piece_count],
            sequential: false,
        })
    }

    pub fn piece_count(&self) -> usize {
        self.pieces.len()
    }

    pub fn completed_pieces(&self) -> usize {
        self.pieces
            .iter()
            .filter(|piece| piece.wanted && piece.verified)
            .count()
    }

    pub fn completed_bytes(&self) -> u64 {
        self.pieces
            .iter()
            .filter(|piece| piece.wanted && piece.verified)
            .map(|piece| piece.length as u64)
            .sum()
    }

    pub fn remaining_blocks(&self) -> usize {
        self.pieces
            .iter()
            .filter(|piece| piece.wanted)
            .map(|piece| piece.remaining_blocks())
            .sum()
    }

    pub fn is_complete(&self) -> bool {
        self.pieces
            .iter()
            .all(|piece| !piece.wanted || piece.is_complete())
    }

    pub fn reset_verified(&mut self) {
        for piece in &mut self.pieces {
            piece.verified = false;
            for block in &mut piece.blocks {
                *block = BlockState::Missing;
            }
        }
        for slot in &mut self.reserved_by {
            *slot = None;
        }
    }

    #[allow(dead_code)]
    pub fn next_missing_piece(&self) -> Option<u32> {
        let mut best = None;
        let mut best_priority = 0u8;
        for (idx, piece) in self.pieces.iter().enumerate() {
            if !piece.wanted || piece.is_complete() || !piece.has_missing() {
                continue;
            }
            if piece.priority > best_priority {
                best_priority = piece.priority;
                best = Some(idx as u32);
            }
        }
        best
    }

    pub fn piece_length(&self, index: u32) -> Option<u32> {
        self.pieces.get(index as usize).map(|piece| piece.length)
    }

    pub fn piece_hash(&self, index: u32) -> Option<[u8; 20]> {
        self.pieces.get(index as usize).map(|piece| piece.hash)
    }

    pub fn is_piece_complete(&self, index: u32) -> bool {
        self.pieces
            .get(index as usize)
            .map(|piece| piece.is_complete())
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn is_piece_wanted(&self, index: u32) -> bool {
        self.pieces
            .get(index as usize)
            .map(|piece| piece.wanted)
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn piece_priority(&self, index: u32) -> Option<u8> {
        self.pieces.get(index as usize).map(|piece| piece.priority)
    }

    pub fn wanted_bytes(&self) -> u64 {
        self.pieces
            .iter()
            .filter(|piece| piece.wanted)
            .map(|piece| piece.length as u64)
            .sum()
    }

    pub fn wanted_pieces(&self) -> usize {
        self.pieces.iter().filter(|piece| piece.wanted).count()
    }

    pub fn set_sequential(&mut self, sequential: bool) {
        self.sequential = sequential;
    }

    pub fn set_piece_priorities(&mut self, priorities: &[u8]) -> Result<(), Error> {
        if priorities.len() != self.pieces.len() {
            return Err(Error::InvalidPieces);
        }
        for (idx, (piece, priority)) in self.pieces.iter_mut().zip(priorities.iter()).enumerate() {
            if *priority > PRIORITY_HIGH {
                return Err(Error::InvalidPriority);
            }
            piece.priority = *priority;
            piece.wanted = *priority != PRIORITY_SKIP;
            if !piece.wanted {
                if let Some(reserved) = self.reserved_by.get_mut(idx) {
                    *reserved = None;
                }
            }
        }
        Ok(())
    }

    pub fn bitfield_len(&self) -> usize {
        (self.pieces.len() + 7) / 8
    }

    pub fn apply_peer_bitfield(&mut self, bitfield: &[u8]) -> Result<(), Error> {
        if bitfield.len() != self.bitfield_len() {
            return Err(Error::InvalidBitfield);
        }
        let total_bits = bitfield.len() * 8;
        let extra_bits = total_bits - self.pieces.len();
        if extra_bits > 0 {
            let mask = (1u8 << extra_bits) - 1;
            if bitfield[bitfield.len() - 1] & mask != 0 {
                return Err(Error::InvalidBitfield);
            }
        }
        for idx in 0..self.pieces.len() {
            if bitfield_has(bitfield, idx) {
                self.availability[idx] = self.availability[idx].saturating_add(1);
            }
        }
        Ok(())
    }

    pub fn apply_have(&mut self, index: u32) -> Result<(), Error> {
        let idx = index as usize;
        if idx >= self.pieces.len() {
            return Err(Error::InvalidPiece);
        }
        self.availability[idx] = self.availability[idx].saturating_add(1);
        Ok(())
    }

    pub fn reserve_piece_for_peer(
        &mut self,
        peer_id: u64,
        bitfield: &[u8],
        allow_reserved: bool,
    ) -> Option<u32> {
        if bitfield.len() != self.bitfield_len() {
            return None;
        }

        if self.sequential {
            // Sequential: pick lowest-index incomplete piece the peer has
            for (idx, piece) in self.pieces.iter().enumerate() {
                if piece.is_complete() || !piece.has_missing() {
                    continue;
                }
                if !piece.wanted {
                    continue;
                }
                if !bitfield_has(bitfield, idx) {
                    continue;
                }
                if !allow_reserved && self.reserved_by[idx].is_some() {
                    continue;
                }
                if !allow_reserved {
                    self.reserved_by[idx] = Some(peer_id);
                }
                return Some(idx as u32);
            }
            return None;
        }

        let mut best_piece = None;
        let mut best_priority = 0u8;
        let mut best_rarity = u32::MAX;
        for (idx, piece) in self.pieces.iter().enumerate() {
            if piece.is_complete() || !piece.has_missing() {
                continue;
            }
            if !piece.wanted {
                continue;
            }
            if !bitfield_has(bitfield, idx) {
                continue;
            }
            if !allow_reserved && self.reserved_by[idx].is_some() {
                continue;
            }
            let rarity = self.availability[idx];
            let priority = piece.priority;
            if best_piece.is_none()
                || priority > best_priority
                || (priority == best_priority && rarity < best_rarity)
            {
                best_priority = priority;
                best_rarity = rarity;
                best_piece = Some(idx);
            }
        }

        let idx = best_piece?;
        if !allow_reserved {
            self.reserved_by[idx] = Some(peer_id);
        }
        Some(idx as u32)
    }

    pub fn has_needed_piece(&self, bitfield: &[u8]) -> bool {
        if bitfield.len() != self.bitfield_len() {
            return false;
        }

        self.pieces.iter().enumerate().any(|(idx, piece)| {
            piece.wanted
                && !piece.is_complete()
                && piece.has_missing()
                && bitfield_has(bitfield, idx)
        })
    }

    pub fn release_piece(&mut self, peer_id: u64, index: u32) {
        let idx = index as usize;
        if idx >= self.reserved_by.len() {
            return;
        }
        if self.reserved_by[idx] == Some(peer_id) {
            self.reserved_by[idx] = None;
        }
    }

    pub fn clear_reservation(&mut self, index: u32) {
        let idx = index as usize;
        if idx < self.reserved_by.len() {
            self.reserved_by[idx] = None;
        }
    }

    pub fn next_request_for_piece(
        &mut self,
        index: u32,
        allow_duplicate: bool,
    ) -> Option<BlockRequest> {
        let piece = self.pieces.get_mut(index as usize)?;
        if !piece.wanted {
            return None;
        }
        let block_index = piece.next_requestable_block(allow_duplicate)?;
        let begin = block_index as u32 * BLOCK_LEN;
        let length = piece.block_length(block_index);
        if piece.blocks[block_index] == BlockState::Missing {
            piece.blocks[block_index] = BlockState::Requested;
        }
        Some(BlockRequest {
            index: piece.index,
            begin,
            length,
        })
    }

    pub fn remove_peer_bitfield(&mut self, bitfield: &[u8]) -> Result<(), Error> {
        if bitfield.len() != self.bitfield_len() {
            return Err(Error::InvalidBitfield);
        }
        for idx in 0..self.pieces.len() {
            if bitfield_has(bitfield, idx) {
                self.availability[idx] = self.availability[idx].saturating_sub(1);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn select_next_request(&mut self, bitfield: &[u8]) -> Option<BlockRequest> {
        if bitfield.len() != self.bitfield_len() {
            return None;
        }

        let mut best_piece = None;
        let mut best_rarity = u32::MAX;
        for (idx, piece) in self.pieces.iter().enumerate() {
            if piece.is_complete() || !piece.has_missing() {
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
        let piece = &mut self.pieces[idx];
        let block_index = piece.next_missing_block()?;
        let begin = block_index as u32 * BLOCK_LEN;
        let length = piece.block_length(block_index);
        piece.blocks[block_index] = BlockState::Requested;
        Some(BlockRequest {
            index: piece.index,
            begin,
            length,
        })
    }

    pub fn mark_block_complete(
        &mut self,
        index: u32,
        begin: u32,
        length: u32,
    ) -> Result<bool, Error> {
        let piece = self
            .pieces
            .get_mut(index as usize)
            .ok_or(Error::InvalidPiece)?;
        if begin % BLOCK_LEN != 0 {
            return Err(Error::InvalidBlock);
        }
        let block_index = (begin / BLOCK_LEN) as usize;
        if block_index >= piece.blocks.len() {
            return Err(Error::InvalidBlock);
        }
        if piece.block_length(block_index) != length {
            return Err(Error::InvalidBlock);
        }
        if piece.blocks[block_index] == BlockState::Complete {
            return Ok(false);
        }
        piece.blocks[block_index] = BlockState::Complete;
        Ok(true)
    }

    pub fn mark_piece_complete(&mut self, index: u32) -> Result<bool, Error> {
        let piece = self
            .pieces
            .get_mut(index as usize)
            .ok_or(Error::InvalidPiece)?;
        let was_new = !piece.verified;
        piece.verified = true;
        for state in &mut piece.blocks {
            *state = BlockState::Complete;
        }
        Ok(was_new)
    }

    pub fn mark_block_missing(&mut self, index: u32, begin: u32) -> Result<(), Error> {
        let piece = self
            .pieces
            .get_mut(index as usize)
            .ok_or(Error::InvalidPiece)?;
        if begin % BLOCK_LEN != 0 {
            return Err(Error::InvalidBlock);
        }
        let block_index = (begin / BLOCK_LEN) as usize;
        if block_index >= piece.blocks.len() {
            return Err(Error::InvalidBlock);
        }
        if piece.blocks[block_index] != BlockState::Complete {
            piece.blocks[block_index] = BlockState::Missing;
        }
        Ok(())
    }

    pub fn reset_piece(&mut self, index: u32) -> Result<(), Error> {
        let piece = self
            .pieces
            .get_mut(index as usize)
            .ok_or(Error::InvalidPiece)?;
        piece.verified = false;
        for state in &mut piece.blocks {
            *state = BlockState::Missing;
        }
        Ok(())
    }
}

impl PieceBuffer {
    pub fn new(index: u32, length: u32) -> Result<Self, Error> {
        if length == 0 {
            return Err(Error::InvalidPieceLength);
        }
        let blocks = block_count(length);
        Ok(Self {
            index,
            length,
            data: vec![0u8; length as usize],
            blocks: vec![0u8; blocks],
            complete: 0,
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
        if begin % BLOCK_LEN != 0 {
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
    ((length as u64 + BLOCK_LEN as u64 - 1) / BLOCK_LEN as u64) as usize
}

fn bitfield_has(bitfield: &[u8], index: usize) -> bool {
    let byte = bitfield[index / 8];
    let offset = index % 8;
    let mask = 0x80 >> offset;
    (byte & mask) != 0
}

impl Piece {
    fn is_complete(&self) -> bool {
        self.blocks
            .iter()
            .all(|state| *state == BlockState::Complete)
    }

    fn has_missing(&self) -> bool {
        self.blocks
            .iter()
            .any(|state| *state == BlockState::Missing)
    }

    fn remaining_blocks(&self) -> usize {
        self.blocks
            .iter()
            .filter(|state| **state != BlockState::Complete)
            .count()
    }

    #[allow(dead_code)]
    fn next_missing_block(&self) -> Option<usize> {
        self.blocks
            .iter()
            .position(|state| *state == BlockState::Missing)
    }

    fn next_requestable_block(&self, allow_duplicate: bool) -> Option<usize> {
        if let Some(idx) = self
            .blocks
            .iter()
            .position(|state| *state == BlockState::Missing)
        {
            return Some(idx);
        }
        if allow_duplicate {
            return self
                .blocks
                .iter()
                .position(|state| *state == BlockState::Requested);
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
            info: InfoDict {
                name: b"test".to_vec(),
                piece_length: 16,
                pieces: vec![[1u8; 20], [2u8; 20]],
                length: Some(32),
                files: Vec::new(),
                private: false,
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
    use crate::torrent::{InfoDict, TorrentMeta};

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
            info: InfoDict {
                name: b"dummy".to_vec(),
                piece_length,
                pieces: hashes,
                length: Some(total_length),
                files: Vec::new(),
                private: false,
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
        assert_eq!(manager.mark_block_complete(0, 0, 16 * 1024).unwrap(), true);
        assert_eq!(manager.mark_block_complete(0, 0, 16 * 1024).unwrap(), false);
    }

    #[test]
    fn piece_buffer_tracks_completion_across_blocks() {
        let mut buffer = PieceBuffer::new(2, BLOCK_LEN + 4).unwrap();
        let first = vec![1u8; BLOCK_LEN as usize];
        let second = vec![2u8; 4];
        assert_eq!(buffer.add_block(0, &first).unwrap(), false);
        assert_eq!(buffer.add_block(BLOCK_LEN, &second).unwrap(), true);
        assert!(buffer.is_complete());
        assert_eq!(&buffer.data()[BLOCK_LEN as usize..], second.as_slice());
    }
}
