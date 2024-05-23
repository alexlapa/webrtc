use super::fixed_big_int::*;

// ReplayDetector is the interface of sequence replay detector.
pub trait ReplayDetector {
    // Check returns true if given sequence number is not replayed.
    // Call accept() to mark the packet is received properly.
    fn check(&mut self, seq: u64) -> bool;
    fn accept(&mut self);
}

pub struct SlidingWindowDetector {
    accepted: bool,
    seq: u64,
    latest_seq: u64,
    max_seq: u64,
    window_size: usize,
    mask: FixedBigInt,
}

impl SlidingWindowDetector {
    // New creates ReplayDetector.
    // Created ReplayDetector doesn't allow wrapping.
    // It can handle monotonically increasing sequence number up to
    // full 64bit number. It is suitable for DTLS replay protection.
    pub fn new(window_size: usize, max_seq: u64) -> Self {
        SlidingWindowDetector {
            accepted: false,
            seq: 0,
            latest_seq: 0,
            max_seq,
            window_size,
            mask: FixedBigInt::new(window_size),
        }
    }
}

impl ReplayDetector for SlidingWindowDetector {
    fn check(&mut self, seq: u64) -> bool {
        self.accepted = false;

        if seq > self.max_seq {
            // Exceeded upper limit.
            return false;
        }

        if seq <= self.latest_seq {
            if self.latest_seq >= self.window_size as u64 + seq {
                return false;
            }
            if self.mask.bit((self.latest_seq - seq) as usize) != 0 {
                // The sequence number is duplicated.
                return false;
            }
        }

        self.accepted = true;
        self.seq = seq;
        true
    }

    fn accept(&mut self) {
        if !self.accepted {
            return;
        }

        if self.seq > self.latest_seq {
            // Update the head of the window.
            self.mask.lsh((self.seq - self.latest_seq) as usize);
            self.latest_seq = self.seq;
        }
        let diff = (self.latest_seq - self.seq) % self.max_seq;
        self.mask.set_bit(diff as usize);
    }
}

pub struct WrappedSlidingWindowDetector {
    accepted: bool,
    seq: u64,
    latest_seq: u64,
    max_seq: u64,
    window_size: usize,
    mask: FixedBigInt,
    init: bool,
}

impl WrappedSlidingWindowDetector {
    // WithWrap creates ReplayDetector allowing sequence wrapping.
    // This is suitable for short bitwidth counter like SRTP and SRTCP.
    pub fn new(window_size: usize, max_seq: u64) -> Self {
        WrappedSlidingWindowDetector {
            accepted: false,
            seq: 0,
            latest_seq: 0,
            max_seq,
            window_size,
            mask: FixedBigInt::new(window_size),
            init: false,
        }
    }
}

impl ReplayDetector for WrappedSlidingWindowDetector {
    fn check(&mut self, seq: u64) -> bool {
        self.accepted = false;

        if seq > self.max_seq {
            // Exceeded upper limit.
            return false;
        }
        if !self.init {
            if seq != 0 {
                self.latest_seq = seq - 1;
            } else {
                self.latest_seq = self.max_seq;
            }
            self.init = true;
        }

        let mut diff = self.latest_seq as i64 - seq as i64;
        // Wrap the number.
        if diff > self.max_seq as i64 / 2 {
            diff -= (self.max_seq + 1) as i64;
        } else if diff <= -(self.max_seq as i64 / 2) {
            diff += (self.max_seq + 1) as i64;
        }

        if diff >= self.window_size as i64 {
            // Too old.
            return false;
        }
        if diff >= 0 && self.mask.bit(diff as usize) != 0 {
            // The sequence number is duplicated.
            return false;
        }

        self.accepted = true;
        self.seq = seq;
        true
    }

    fn accept(&mut self) {
        if !self.accepted {
            return;
        }

        let mut diff = self.latest_seq as i64 - self.seq as i64;
        // Wrap the number.
        if diff > self.max_seq as i64 / 2 {
            diff -= (self.max_seq + 1) as i64;
        } else if diff <= -(self.max_seq as i64 / 2) {
            diff += (self.max_seq + 1) as i64;
        }

        assert!(diff < self.window_size as i64);

        if diff < 0 {
            // Update the head of the window.
            self.mask.lsh((-diff) as usize);
            self.latest_seq = self.seq;
        }
        self.mask
            .set_bit((self.latest_seq as isize - self.seq as isize) as usize);
    }
}

#[derive(Default)]
pub struct NoOpReplayDetector;

impl ReplayDetector for NoOpReplayDetector {
    fn check(&mut self, _: u64) -> bool {
        true
    }

    fn accept(&mut self) {}
}

#[cfg(test)]
mod replay_detector_test {
    use super::*;

    #[test]
    fn test_replay_detector() {
        const LARGE_SEQ: u64 = 0x100000000000;

        #[allow(clippy::type_complexity)]
        let tests: Vec<(&str, usize, u64, Vec<u64>, Vec<bool>, Vec<u64>, Vec<u64>)> = vec![
            (
                "Continuous",
                16,
                0x0000FFFFFFFFFFFF,
                vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true, true, true, true, true, true, true,
                ],
                vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                ],
                vec![],
            ),
            (
                "ValidLargeJump",
                16,
                0x0000FFFFFFFFFFFF,
                vec![
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                    LARGE_SEQ,
                    11,
                    LARGE_SEQ + 1,
                    LARGE_SEQ + 2,
                    LARGE_SEQ + 3,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true,
                ],
                vec![
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                    LARGE_SEQ,
                    LARGE_SEQ + 1,
                    LARGE_SEQ + 2,
                    LARGE_SEQ + 3,
                ],
                vec![],
            ),
            (
                "InvalidLargeJump",
                16,
                0x0000FFFFFFFFFFFF,
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, LARGE_SEQ, 11, 12, 13, 14, 15],
                vec![
                    true, true, true, true, true, true, true, true, true, true, false, true, true,
                    true, true, true,
                ],
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15],
                vec![],
            ),
            (
                "DuplicateAfterValidJump",
                196,
                0x0000FFFFFFFFFFFF,
                vec![0, 1, 2, 129, 0, 1, 2],
                vec![true, true, true, true, true, true, true],
                vec![0, 1, 2, 129],
                vec![],
            ),
            (
                "DuplicateAfterInvalidJump",
                196,
                0x0000FFFFFFFFFFFF,
                vec![0, 1, 2, 128, 0, 1, 2],
                vec![true, true, true, false, true, true, true],
                vec![0, 1, 2],
                vec![],
            ),
            (
                "ContinuousOffset",
                16,
                0x0000FFFFFFFFFFFF,
                vec![
                    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true,
                ],
                vec![
                    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
                ],
                vec![],
            ),
            (
                "Reordered",
                128,
                0x0000FFFFFFFFFFFF,
                vec![
                    96, 64, 16, 80, 32, 48, 8, 24, 88, 40, 128, 56, 72, 112, 104, 120,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true, true,
                ],
                vec![
                    96, 64, 16, 80, 32, 48, 8, 24, 88, 40, 128, 56, 72, 112, 104, 120,
                ],
                vec![],
            ),
            (
                "Old",
                100,
                0x0000FFFFFFFFFFFF,
                vec![
                    24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 8, 16,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true, true,
                ],
                vec![24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128],
                vec![],
            ),
            (
                "ContinuouesReplayed",
                8,
                0x0000FFFFFFFFFFFF,
                vec![
                    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true, true, true, true, true, true,
                ],
                vec![16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
                vec![],
            ),
            (
                "ReplayedLater",
                128,
                0x0000FFFFFFFFFFFF,
                vec![
                    16, 32, 48, 64, 80, 96, 112, 128, 16, 32, 48, 64, 80, 96, 112, 128,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true, true,
                ],
                vec![16, 32, 48, 64, 80, 96, 112, 128],
                vec![],
            ),
            (
                "ReplayedQuick",
                128,
                0x0000FFFFFFFFFFFF,
                vec![
                    16, 16, 32, 32, 48, 48, 64, 64, 80, 80, 96, 96, 112, 112, 128, 128,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true, true,
                    true, true, true,
                ],
                vec![16, 32, 48, 64, 80, 96, 112, 128],
                vec![],
            ),
            (
                "Strict",
                0,
                0x0000FFFFFFFFFFFF,
                vec![1, 3, 2, 4, 5, 6, 7, 8, 9, 10],
                vec![true, true, true, true, true, true, true, true, true, true],
                vec![1, 3, 4, 5, 6, 7, 8, 9, 10],
                vec![],
            ),
            (
                "Overflow",
                128,
                0x0000FFFFFFFFFFFF,
                vec![
                    0x0000FFFFFFFFFFFE,
                    0x0000FFFFFFFFFFFF,
                    0x0001000000000000,
                    0x0001000000000001,
                ],
                vec![true, true, true, true],
                vec![0x0000FFFFFFFFFFFE, 0x0000FFFFFFFFFFFF],
                vec![],
            ),
            (
                "WrapContinuous",
                64,
                0xFFFF,
                vec![
                    0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF, 0x0000, 0x0001, 0x0002, 0x0003,
                ],
                vec![true, true, true, true, true, true, true, true],
                vec![0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF],
                vec![
                    0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF, 0x0000, 0x0001, 0x0002, 0x0003,
                ],
            ),
            (
                "WrapReordered",
                64,
                0xFFFF,
                vec![
                    0xFFFD, 0xFFFC, 0x0002, 0xFFFE, 0x0000, 0x0001, 0xFFFF, 0x0003,
                ],
                vec![true, true, true, true, true, true, true, true],
                vec![0xFFFD, 0xFFFC, 0xFFFE, 0xFFFF],
                vec![
                    0xFFFD, 0xFFFC, 0x0002, 0xFFFE, 0x0000, 0x0001, 0xFFFF, 0x0003,
                ],
            ),
            (
                "WrapReorderedReplayed",
                64,
                0xFFFF,
                vec![
                    0xFFFD, 0xFFFC, 0xFFFC, 0x0002, 0xFFFE, 0xFFFC, 0x0000, 0x0001, 0x0001, 0xFFFF,
                    0x0001, 0x0003,
                ],
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ],
                vec![0xFFFD, 0xFFFC, 0xFFFE, 0xFFFF],
                vec![
                    0xFFFD, 0xFFFC, 0x0002, 0xFFFE, 0x0000, 0x0001, 0xFFFF, 0x0003,
                ],
            ),
        ];

        for (name, windows_size, max_seq, input, valid, expected, mut expected_wrap) in tests {
            if expected_wrap.is_empty() {
                expected_wrap.extend_from_slice(&expected);
            }

            for k in 0..2 {
                let mut det: Box<dyn ReplayDetector> = if k == 0 {
                    Box::new(SlidingWindowDetector::new(windows_size, max_seq))
                } else {
                    Box::new(WrappedSlidingWindowDetector::new(windows_size, max_seq))
                };
                let exp = if k == 0 { &expected } else { &expected_wrap };

                let mut out = vec![];
                for (i, seq) in input.iter().enumerate() {
                    let ok = det.check(*seq);
                    if ok && valid[i] {
                        out.push(*seq);
                        det.accept();
                    }
                }

                assert_eq!(&out, exp, "{name} failed");
            }
        }
    }
}
