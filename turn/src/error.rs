use std::{io, num::ParseIntError, time::SystemTimeError};

use thiserror::Error;

use crate::{net, stun};

#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum Error {
    #[error("turn: PacketConnConfigs and ConnConfigs are empty, unable to proceed")]
    ErrNoAvailableConns,
    #[error("turn: RelayAddressGenerator has invalid ListeningAddress")]
    ErrListeningAddressInvalid,
    #[error("turn: max retries exceeded")]
    ErrMaxRetriesExceeded,
    #[error("turn: MaxPort must be not 0")]
    ErrMaxPortNotZero,
    #[error("turn: MaxPort must be not 0")]
    ErrMinPortNotZero,
    #[error("turn: MaxPort less than MinPort")]
    ErrMaxPortLessThanMinPort,
    #[error("channel number not in [0x4000, 0x7FFF]")]
    ErrInvalidChannelNumber,
    #[error("channelData length != len(Data)")]
    ErrBadChannelDataLength,
    #[error("unexpected EOF")]
    ErrUnexpectedEof,
    #[error("invalid value for requested family attribute")]
    ErrInvalidRequestedFamilyValue,
    #[error("error code 443: peer address family mismatch")]
    ErrPeerAddressFamilyMismatch,
    #[error("fake error")]
    ErrFakeErr,
    #[error("use of closed network connection")]
    ErrClosed,
    #[error("you cannot use the same channel number with different peer")]
    ErrSameChannelDifferentPeer,
    #[error("allocations must not be created with a lifetime of 0")]
    ErrLifetimeZero,
    #[error("allocation attempt created with duplicate FiveTuple")]
    ErrDupeFiveTuple,
    #[error("duplicated Nonce generated, discarding request")]
    ErrDuplicatedNonce,
    #[error("no such user exists")]
    ErrNoSuchUser,
    #[error("unexpected class")]
    ErrUnexpectedClass,
    #[error("relay already allocated for 5-TUPLE")]
    ErrRelayAlreadyAllocatedForFiveTuple,
    #[error("RequestedTransport must be UDP")]
    ErrRequestedTransportMustBeUdp,
    #[error("no support for DONT-FRAGMENT")]
    ErrNoDontFragmentSupport,
    #[error("Request must not contain RESERVATION-TOKEN and EVEN-PORT")]
    ErrRequestWithReservationTokenAndEvenPort,
    #[error("Request must not contain RESERVATION-TOKEN and REQUESTED-ADDRESS-FAMILY")]
    ErrRequestWithReservationTokenAndReqAddressFamily,
    #[error("no allocation found")]
    ErrNoAllocationFound,
    #[error("unable to handle send-indication, no permission added")]
    ErrNoPermission,
    #[error("packet write smaller than packet")]
    ErrShortWrite,
    #[error("no such channel bind")]
    ErrNoSuchChannelBind,
    #[error("parse int: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("parse addr: {0}")]
    ParseIp(#[from] std::net::AddrParseError),
    #[error("{0}")]
    Io(#[source] IoError),
    #[error("{0}")]
    Util(#[from] net::Error),
    #[error("{0}")]
    Stun(#[from] stun::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(IoError(e))
    }
}

impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Self {
        Error::Other(e.to_string())
    }
}
