use std::{
    collections::HashMap,
    marker::{Send, Sync},
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::SystemTime,
};

use crate::{
    con::Conn,
    stun::{
        self, agent::*, attrs::*, error_code::*, fingerprint::*, integrity::*, msg::*,
        textattrs::*, uattrs::*, xoraddr::*,
    },
};
use md5::{Digest, Md5};
use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{
    allocation::{
        allocation_manager::*, channel_bind::ChannelBind, five_tuple::*, permission::Permission,
    },
    auth::*,
    error::*,
    proto::{
        chandata::ChannelData,
        channum::ChannelNumber,
        data::Data,
        evenport::EvenPort,
        lifetime::*,
        peeraddr::PeerAddress,
        relayaddr::RelayedAddress,
        reqfamily::{RequestedAddressFamily, REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6},
        reqtrans::RequestedTransport,
        rsrvtoken::ReservationToken,
        *,
    },
};

// https://tools.ietf.org/html/rfc5766#section-6.2 defines 3600 seconds recommendation
pub(crate) const MAXIMUM_ALLOCATION_LIFETIME: Duration = Duration::from_secs(3600);

// https://tools.ietf.org/html/rfc5766#section-4
pub(crate) const NONCE_LIFETIME: Duration = Duration::from_secs(3600);

/// Request contains all the state needed to process a single incoming datagram
pub struct Request {
    // Current Request State
    pub conn: Arc<dyn Conn + Send + Sync>,
    pub src_addr: SocketAddr,
    pub buff: Vec<u8>,

    // Server State
    pub allocation_manager: Arc<Manager>,
    pub nonces: Arc<Mutex<HashMap<String, Instant>>>,

    // User Configuration
    pub auth_handler: Arc<dyn AuthHandler + Send + Sync>,
    pub realm: String,
    pub channel_bind_timeout: Duration,

    pub five_tuple: FiveTuple,
}

impl Request {
    /// Processes the give [`Request`]
    pub async fn handle_request(&mut self) -> Result<(), Error> {
        if ChannelData::is_channel_data(&self.buff) {
            self.handle_data_packet().await
        } else {
            self.handle_turn_packet().await
        }
    }

    async fn handle_data_packet(&mut self) -> Result<(), Error> {
        log::debug!("received DataPacket from {}", self.src_addr);
        let mut c = ChannelData {
            raw: self.buff.clone(),
            ..Default::default()
        };
        c.decode()?;
        self.handle_channel_data(&c).await
    }

    async fn handle_turn_packet(&mut self) -> Result<(), Error> {
        log::debug!("handle_turn_packet");
        let mut m = Message {
            raw: self.buff.clone(),
            ..Default::default()
        };
        m.decode()?;
        if m.typ.class == CLASS_INDICATION {
            match m.typ.method {
                METHOD_SEND => self.handle_send_indication(&m).await,
                _ => Err(Error::ErrUnexpectedClass),
            }
        } else if m.typ.class == CLASS_REQUEST {
            match m.typ.method {
                METHOD_ALLOCATE => self.handle_allocate_request(&m).await,
                METHOD_REFRESH => self.handle_refresh_request(&m).await,
                METHOD_CREATE_PERMISSION => self.handle_create_permission_request(&m).await,
                METHOD_CHANNEL_BIND => self.handle_channel_bind_request(&m).await,
                METHOD_BINDING => self.handle_binding_request(&m).await,
                METHOD_CONNECT => {
                    unimplemented!("METHOD_CONNECT")
                }
                METHOD_CONNECTION_BIND => {
                    unimplemented!("METHOD_CONNECTION_BIND")
                }
                METHOD_CONNECTION_ATTEMPT => {
                    unimplemented!("METHOD_CONNECTION_ATTEMPT")
                }
                _ => Err(Error::ErrUnexpectedClass),
            }
        } else {
            Err(Error::ErrUnexpectedClass)
        }
    }

    pub(crate) async fn authenticate_request(
        &mut self,
        m: &Message,
        calling_method: Method,
    ) -> Result<Option<(Username, MessageIntegrity)>, Error> {
        if !m.contains(ATTR_MESSAGE_INTEGRITY) {
            self.respond_with_nonce(m, calling_method, CODE_UNAUTHORIZED)
                .await?;
            return Ok(None);
        }

        let mut nonce_attr = Nonce::new(ATTR_NONCE, String::new());
        let mut username_attr = Username::new(ATTR_USERNAME, String::new());
        let mut realm_attr = Realm::new(ATTR_REALM, String::new());
        let bad_request_msg = build_msg(
            m.transaction_id,
            MessageType::new(calling_method, CLASS_ERROR_RESPONSE),
            vec![Box::new(ErrorCodeAttribute {
                code: CODE_BAD_REQUEST,
                reason: vec![],
            })],
        )?;

        if let Err(err) = nonce_attr.get_from(m) {
            build_and_send_err(&self.conn, self.src_addr, bad_request_msg, err.into()).await?;
            return Ok(None);
        }

        let to_be_deleted = {
            // Assert Nonce exists and is not expired
            let mut nonces = self.nonces.lock().await;

            let to_be_deleted = if let Some(nonce_creation_time) = nonces.get(&nonce_attr.text) {
                Instant::now()
                    .checked_duration_since(*nonce_creation_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    >= NONCE_LIFETIME
            } else {
                true
            };

            if to_be_deleted {
                nonces.remove(&nonce_attr.text);
            }
            to_be_deleted
        };

        if to_be_deleted {
            self.respond_with_nonce(m, calling_method, CODE_STALE_NONCE)
                .await?;
            return Ok(None);
        }

        if let Err(err) = realm_attr.get_from(m) {
            build_and_send_err(&self.conn, self.src_addr, bad_request_msg, err.into()).await?;
            return Ok(None);
        }
        if let Err(err) = username_attr.get_from(m) {
            build_and_send_err(&self.conn, self.src_addr, bad_request_msg, err.into()).await?;
            return Ok(None);
        }

        let our_key = match self.auth_handler.auth_handle(
            &username_attr.to_string(),
            &realm_attr.to_string(),
            self.src_addr,
        ) {
            Ok(key) => key,
            Err(_) => {
                build_and_send_err(
                    &self.conn,
                    self.src_addr,
                    bad_request_msg,
                    Error::ErrNoSuchUser,
                )
                .await?;
                return Ok(None);
            }
        };

        let mi = MessageIntegrity(our_key);
        if let Err(err) = mi.check(&mut m.clone()) {
            build_and_send_err(&self.conn, self.src_addr, bad_request_msg, err.into()).await?;
            Ok(None)
        } else {
            Ok(Some((username_attr, mi)))
        }
    }

    async fn respond_with_nonce(
        &mut self,
        m: &Message,
        calling_method: Method,
        response_code: ErrorCode,
    ) -> Result<(), Error> {
        let nonce = build_nonce()?;

        {
            // Nonce has already been taken
            let mut nonces = self.nonces.lock().await;
            if nonces.contains_key(&nonce) {
                return Err(Error::ErrDuplicatedNonce);
            }
            nonces.insert(nonce.clone(), Instant::now());
        }

        let msg = build_msg(
            m.transaction_id,
            MessageType::new(calling_method, CLASS_ERROR_RESPONSE),
            vec![
                Box::new(ErrorCodeAttribute {
                    code: response_code,
                    reason: vec![],
                }),
                Box::new(Nonce::new(ATTR_NONCE, nonce)),
                Box::new(Realm::new(ATTR_REALM, self.realm.clone())),
            ],
        )?;

        build_and_send(&self.conn, self.src_addr, msg).await
    }

    pub(crate) async fn handle_binding_request(&mut self, m: &Message) -> Result<(), Error> {
        log::debug!("received BindingRequest from {}", self.src_addr);

        let (ip, port) = (self.src_addr.ip(), self.src_addr.port());

        let msg = build_msg(
            m.transaction_id,
            BINDING_SUCCESS,
            vec![
                Box::new(XorMappedAddress { ip, port }),
                Box::new(FINGERPRINT),
            ],
        )?;

        build_and_send(&self.conn, self.src_addr, msg).await
    }

    /// https://tools.ietf.org/html/rfc5766#section-6.2
    pub(crate) async fn handle_allocate_request(&mut self, m: &Message) -> Result<(), Error> {
        log::debug!("received AllocateRequest from {}", self.src_addr);

        // 1. The server MUST require that the request be authenticated.  This
        //    authentication MUST be done using the long-term credential
        //    mechanism of [https://tools.ietf.org/html/rfc5389#section-10.2.2]
        //    unless the client and server agree to use another mechanism through
        //    some procedure outside the scope of this document.
        let (username, message_integrity) =
            if let Some(mi) = self.authenticate_request(m, METHOD_ALLOCATE).await? {
                mi
            } else {
                log::debug!("no MessageIntegrity");
                return Ok(());
            };

        let mut requested_port = 0;
        let mut reservation_token = "".to_owned();
        let mut use_ipv4 = true;

        // 2. The server checks if the 5-tuple is currently in use by an existing
        //    allocation.  If yes, the server rejects the request with a 437 (Allocation
        //    Mismatch) error.
        if self
            .allocation_manager
            .get_allocation(&self.five_tuple)
            .await
            .is_some()
        {
            let msg = build_msg(
                m.transaction_id,
                MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                vec![Box::new(ErrorCodeAttribute {
                    code: CODE_ALLOC_MISMATCH,
                    reason: vec![],
                })],
            )?;

            return build_and_send_err(
                &self.conn,
                self.src_addr,
                msg,
                Error::ErrRelayAlreadyAllocatedForFiveTuple,
            )
            .await;
        }

        // 3. The server checks if the request contains a REQUESTED-TRANSPORT attribute.
        //    If the REQUESTED-TRANSPORT attribute is not included or is malformed, the
        //    server rejects the request with a 400 (Bad Request) error.  Otherwise, if
        //    the attribute is included but specifies a protocol other that UDP, the
        //    server rejects the request with a 442 (Unsupported Transport Protocol)
        //    error. + rfc6062
        let mut requested_transport = RequestedTransport::default();
        if let Err(err) = requested_transport.get_from(m) {
            let bad_request_msg = build_msg(
                m.transaction_id,
                MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                vec![Box::new(ErrorCodeAttribute {
                    code: CODE_BAD_REQUEST,
                    reason: vec![],
                })],
            )?;
            return build_and_send_err(&self.conn, self.src_addr, bad_request_msg, err.into())
                .await;
        }
        if requested_transport.protocol != PROTO_TCP && requested_transport.protocol != PROTO_UDP {
            let bad_request_msg = build_msg(
                m.transaction_id,
                MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                vec![Box::new(ErrorCodeAttribute {
                    code: CODE_UNSUPPORTED_TRANS_PROTO,
                    reason: vec![],
                })],
            )?;
            return build_and_send_err(
                &self.conn,
                self.src_addr,
                bad_request_msg,
                Error::UsupportedRelayProto,
            )
            .await;
        }

        // 4. The request may contain a DONT-FRAGMENT attribute.  If it does, but the
        //    server does not support sending UDP datagrams with the DF bit set to 1
        //    (see Section 12), then the server treats the DONT- FRAGMENT attribute in
        //    the Allocate request as an unknown comprehension-required attribute.
        if m.contains(ATTR_DONT_FRAGMENT) {
            let msg = build_msg(
                m.transaction_id,
                MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                vec![
                    Box::new(ErrorCodeAttribute {
                        code: CODE_UNKNOWN_ATTRIBUTE,
                        reason: vec![],
                    }),
                    Box::new(UnknownAttributes(vec![ATTR_DONT_FRAGMENT])),
                ],
            )?;
            return build_and_send_err(
                &self.conn,
                self.src_addr,
                msg,
                Error::ErrNoDontFragmentSupport,
            )
            .await;
        }

        // 5. The server checks if the request contains a RESERVATION-TOKEN attribute.
        //    If yes, and the request also contains an EVEN-PORT attribute, then the
        //    server rejects the request with a 400 (Bad Request) error.  Otherwise, it
        //    checks to see if the token is valid (i.e., the token is in range and has
        //    not expired and the corresponding relayed transport address is still
        //    available).  If the token is not valid for some reason, the server rejects
        //    the request with a 508 (Insufficient Capacity) error.
        let mut reservation_token_attr = ReservationToken::default();
        let reservation_token_attr_result = reservation_token_attr.get_from(m);
        if reservation_token_attr_result.is_ok() {
            let mut even_port = EvenPort::default();
            if even_port.get_from(m).is_ok() {
                let bad_request_msg = build_msg(
                    m.transaction_id,
                    MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                    vec![Box::new(ErrorCodeAttribute {
                        code: CODE_BAD_REQUEST,
                        reason: vec![],
                    })],
                )?;
                return build_and_send_err(
                    &self.conn,
                    self.src_addr,
                    bad_request_msg,
                    Error::ErrRequestWithReservationTokenAndEvenPort,
                )
                .await;
            }
        }

        // RFC 6156, Section 4.2:
        //
        // If it contains both a RESERVATION-TOKEN and a
        // REQUESTED-ADDRESS-FAMILY, the server replies with a 400
        // (Bad Request) Allocate error response.
        //
        // 4.2.1.  Unsupported Address Family
        // This document defines the following new error response code:
        // 440 (Address Family not Supported):  The server does not support the
        // address family requested by the client.
        let mut req_family = RequestedAddressFamily::default();
        match req_family.get_from(m) {
            Err(err) => {
                // Currently, the RequestedAddressFamily::get_from() function
                // returns Err::Other only when it is an
                // unsupported address family.
                if let stun::Error::Other(_) = err {
                    let addr_family_not_supported_msg = build_msg(
                        m.transaction_id,
                        MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                        vec![Box::new(ErrorCodeAttribute {
                            code: CODE_ADDR_FAMILY_NOT_SUPPORTED,
                            reason: vec![],
                        })],
                    )?;
                    return build_and_send_err(
                        &self.conn,
                        self.src_addr,
                        addr_family_not_supported_msg,
                        Error::ErrInvalidRequestedFamilyValue,
                    )
                    .await;
                }
            }
            Ok(()) => {
                if reservation_token_attr_result.is_ok() {
                    let bad_request_msg = build_msg(
                        m.transaction_id,
                        MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                        vec![Box::new(ErrorCodeAttribute {
                            code: CODE_BAD_REQUEST,
                            reason: vec![],
                        })],
                    )?;

                    return build_and_send_err(
                        &self.conn,
                        self.src_addr,
                        bad_request_msg,
                        Error::ErrRequestWithReservationTokenAndReqAddressFamily,
                    )
                    .await;
                }

                if req_family == REQUESTED_FAMILY_IPV6 {
                    use_ipv4 = false;
                }
            }
        }
        // 6. The server checks if the request contains an EVEN-PORT attribute. If yes,
        //    then the server checks that it can satisfy the request (i.e., can allocate
        //    a relayed transport address as described below).  If the server cannot
        //    satisfy the request, then the server rejects the request with a 508
        //    (Insufficient Capacity) error.
        let mut even_port = EvenPort::default();
        if even_port.get_from(m).is_ok() {
            let mut random_port = 1;

            while random_port % 2 != 0 {
                random_port = match self
                    .allocation_manager
                    .get_random_even_port(requested_transport.protocol)
                    .await
                {
                    Ok(port) => port,
                    Err(err) => {
                        let insufficient_capacity_msg = build_msg(
                            m.transaction_id,
                            MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                            vec![Box::new(ErrorCodeAttribute {
                                code: CODE_INSUFFICIENT_CAPACITY,
                                reason: vec![],
                            })],
                        )?;
                        return build_and_send_err(
                            &self.conn,
                            self.src_addr,
                            insufficient_capacity_msg,
                            err,
                        )
                        .await;
                    }
                };
            }

            requested_port = random_port;
            reservation_token = rand_seq(8);
        }

        // 7. At any point, the server MAY choose to reject the request with a 486
        //    (Allocation Quota Reached) error if it feels the client is trying to
        //    exceed some locally defined allocation quota.  The server is free to
        //    define this allocation quota any way it wishes, but SHOULD define it based
        //    on the username used to authenticate the request, and not on the client's
        //    transport address.

        // 8. Also at any point, the server MAY choose to reject the request with a 300
        //    (Try Alternate) error if it wishes to redirect the client to a different
        //    server.  The use of this error code and attribute follow the specification
        //    in [RFC5389].
        let lifetime_duration = allocation_lifetime(m);
        let a = match self
            .allocation_manager
            .create_allocation(
                self.five_tuple,
                Arc::clone(&self.conn),
                requested_port,
                lifetime_duration,
                username,
                use_ipv4,
                requested_transport.protocol,
            )
            .await
        {
            Ok(a) => a,
            Err(err) => {
                let insufficient_capacity_msg = build_msg(
                    m.transaction_id,
                    MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
                    vec![Box::new(ErrorCodeAttribute {
                        code: CODE_INSUFFICIENT_CAPACITY,
                        reason: vec![],
                    })],
                )?;
                return build_and_send_err(
                    &self.conn,
                    self.src_addr,
                    insufficient_capacity_msg,
                    err,
                )
                .await;
            }
        };

        // Once the allocation is created, the server replies with a success
        // response.  The success response contains:
        //   * An XOR-RELAYED-ADDRESS attribute containing the relayed transport
        //     address.
        //   * A LIFETIME attribute containing the current value of the time-to- expiry
        //     timer.
        //   * A RESERVATION-TOKEN attribute (if a second relayed transport address was
        //     reserved).
        //   * An XOR-MAPPED-ADDRESS attribute containing the client's IP address and
        //     port (from the 5-tuple).

        let (src_ip, src_port) = (self.src_addr.ip(), self.src_addr.port());
        let relay_ip = a.relay_addr.ip();
        let relay_port = a.relay_addr.port();
        let msg = {
            if !reservation_token.is_empty() {
                self.allocation_manager
                    .create_reservation(reservation_token.clone(), relay_port)
                    .await;
            }

            let mut response_attrs: Vec<Box<dyn Setter>> = vec![
                Box::new(RelayedAddress {
                    ip: relay_ip,
                    port: relay_port,
                }),
                Box::new(Lifetime(lifetime_duration)),
                Box::new(XorMappedAddress {
                    ip: src_ip,
                    port: src_port,
                }),
            ];

            if !reservation_token.is_empty() {
                response_attrs.push(Box::new(ReservationToken(
                    reservation_token.as_bytes().to_vec(),
                )));
            }

            response_attrs.push(Box::new(message_integrity));
            build_msg(
                m.transaction_id,
                MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE),
                response_attrs,
            )?
        };

        build_and_send(&self.conn, self.src_addr, msg).await
    }

    pub(crate) async fn handle_refresh_request(&mut self, m: &Message) -> Result<(), Error> {
        log::debug!("received RefreshRequest from {}", self.src_addr);

        let (_, message_integrity) =
            if let Some(mi) = self.authenticate_request(m, METHOD_REFRESH).await? {
                mi
            } else {
                log::debug!("no MessageIntegrity");
                return Ok(());
            };

        let lifetime_duration = allocation_lifetime(m);
        if lifetime_duration != Duration::from_secs(0) {
            let a = self
                .allocation_manager
                .get_allocation(&self.five_tuple)
                .await;
            if let Some(a) = a {
                // If a server receives a Refresh Request with a
                // REQUESTED-ADDRESS-FAMILY attribute, and the
                // attribute's value doesn't match the address
                // family of the allocation, the server MUST reply with a 443
                // (Peer Address Family Mismatch) Refresh error
                // response. [RFC 6156, Section 5.2]
                let mut req_family = RequestedAddressFamily::default();
                if req_family.get_from(m).is_ok()
                    && ((req_family == REQUESTED_FAMILY_IPV6 && !a.relay_addr.is_ipv6())
                        || (req_family == REQUESTED_FAMILY_IPV4 && !a.relay_addr.is_ipv4()))
                {
                    let peer_address_family_mismatch_msg = build_msg(
                        m.transaction_id,
                        MessageType::new(METHOD_REFRESH, CLASS_ERROR_RESPONSE),
                        vec![Box::new(ErrorCodeAttribute {
                            code: CODE_PEER_ADDR_FAMILY_MISMATCH,
                            reason: vec![],
                        })],
                    )?;
                    return build_and_send_err(
                        &self.conn,
                        self.src_addr,
                        peer_address_family_mismatch_msg,
                        Error::ErrPeerAddressFamilyMismatch,
                    )
                    .await;
                }
                a.refresh(lifetime_duration).await;
            } else {
                return Err(Error::ErrNoAllocationFound);
            }
        } else {
            self.allocation_manager
                .delete_allocation(&self.five_tuple)
                .await;
        }

        let msg = build_msg(
            m.transaction_id,
            MessageType::new(METHOD_REFRESH, CLASS_SUCCESS_RESPONSE),
            vec![
                Box::new(Lifetime(lifetime_duration)),
                Box::new(message_integrity),
            ],
        )?;

        build_and_send(&self.conn, self.src_addr, msg).await
    }

    pub(crate) async fn handle_create_permission_request(
        &mut self,
        m: &Message,
    ) -> Result<(), Error> {
        log::debug!("received CreatePermission from {}", self.src_addr);

        let a = self
            .allocation_manager
            .get_allocation(&self.five_tuple)
            .await;

        if let Some(a) = a {
            let (_, message_integrity) = if let Some(mi) = self
                .authenticate_request(m, METHOD_CREATE_PERMISSION)
                .await?
            {
                mi
            } else {
                log::debug!("no MessageIntegrity");
                return Ok(());
            };
            let mut add_count = 0;

            {
                for attr in &m.attributes.0 {
                    if attr.typ != ATTR_XOR_PEER_ADDRESS {
                        continue;
                    }

                    let mut peer_address = PeerAddress::default();
                    if peer_address.get_from(m).is_err() {
                        add_count = 0;
                        break;
                    }

                    // If an XOR-PEER-ADDRESS attribute contains an address of
                    // an address family different than that
                    // of the relayed transport address for the
                    // allocation, the server MUST generate an error response
                    // with the 443 (Peer Address Family
                    // Mismatch) response code. [RFC 6156, Section 6.2]
                    if (peer_address.ip.is_ipv4() && !a.relay_addr.is_ipv4())
                        || (peer_address.ip.is_ipv6() && !a.relay_addr.is_ipv6())
                    {
                        let peer_address_family_mismatch_msg = build_msg(
                            m.transaction_id,
                            MessageType::new(METHOD_CREATE_PERMISSION, CLASS_ERROR_RESPONSE),
                            vec![Box::new(ErrorCodeAttribute {
                                code: CODE_PEER_ADDR_FAMILY_MISMATCH,
                                reason: vec![],
                            })],
                        )?;
                        return build_and_send_err(
                            &self.conn,
                            self.src_addr,
                            peer_address_family_mismatch_msg,
                            Error::ErrPeerAddressFamilyMismatch,
                        )
                        .await;
                    }

                    log::debug!(
                        "adding permission for {}",
                        format!("{}:{}", peer_address.ip, peer_address.port)
                    );

                    a.add_permission(Permission::new(SocketAddr::new(
                        peer_address.ip,
                        peer_address.port,
                    )))
                    .await;
                    add_count += 1;
                }
            }

            let mut resp_class = CLASS_SUCCESS_RESPONSE;
            if add_count == 0 {
                resp_class = CLASS_ERROR_RESPONSE;
            }

            let msg = build_msg(
                m.transaction_id,
                MessageType::new(METHOD_CREATE_PERMISSION, resp_class),
                vec![Box::new(message_integrity)],
            )?;

            build_and_send(&self.conn, self.src_addr, msg).await
        } else {
            Err(Error::ErrNoAllocationFound)
        }
    }

    pub(crate) async fn handle_send_indication(&mut self, m: &Message) -> Result<(), Error> {
        log::debug!("received SendIndication from {}", self.src_addr);

        let a = self
            .allocation_manager
            .get_allocation(&self.five_tuple)
            .await;

        if let Some(a) = a {
            let mut data_attr = Data::default();
            data_attr.get_from(m)?;

            let mut peer_address = PeerAddress::default();
            peer_address.get_from(m)?;

            let msg_dst = SocketAddr::new(peer_address.ip, peer_address.port);

            let has_perm = a.has_permission(&msg_dst).await;
            if !has_perm {
                return Err(Error::ErrNoPermission);
            }

            let l = a.relay_socket.send_to(&data_attr.0, msg_dst).await?;
            if l != data_attr.0.len() {
                Err(Error::ErrShortWrite)
            } else {
                a.relayed_bytes
                    .fetch_add(data_attr.0.len(), Ordering::AcqRel);

                Ok(())
            }
        } else {
            Err(Error::ErrNoAllocationFound)
        }
    }

    pub(crate) async fn handle_channel_bind_request(&mut self, m: &Message) -> Result<(), Error> {
        log::debug!("received ChannelBindRequest from {}", self.src_addr);

        let a = self
            .allocation_manager
            .get_allocation(&self.five_tuple)
            .await;

        if let Some(a) = a {
            let bad_request_msg = build_msg(
                m.transaction_id,
                MessageType::new(METHOD_CHANNEL_BIND, CLASS_ERROR_RESPONSE),
                vec![Box::new(ErrorCodeAttribute {
                    code: CODE_BAD_REQUEST,
                    reason: vec![],
                })],
            )?;

            let (_, message_integrity) =
                if let Some(mi) = self.authenticate_request(m, METHOD_CHANNEL_BIND).await? {
                    mi
                } else {
                    log::debug!("no MessageIntegrity");
                    return Ok(());
                };
            let mut channel = ChannelNumber::default();
            if let Err(err) = channel.get_from(m) {
                return build_and_send_err(&self.conn, self.src_addr, bad_request_msg, err.into())
                    .await;
            }

            let mut peer_addr = PeerAddress::default();
            match peer_addr.get_from(m) {
                Err(err) => {
                    return build_and_send_err(
                        &self.conn,
                        self.src_addr,
                        bad_request_msg,
                        err.into(),
                    )
                    .await;
                }
                _ => {
                    // If the XOR-PEER-ADDRESS attribute contains an address of
                    // an address family different than that
                    // of the relayed transport address for the
                    // allocation, the server MUST generate an error response
                    // with the 443 (Peer Address Family
                    // Mismatch) response code. [RFC 6156, Section 7.2]
                    if (peer_addr.ip.is_ipv4() && !a.relay_addr.is_ipv4())
                        || (peer_addr.ip.is_ipv6() && !a.relay_addr.is_ipv6())
                    {
                        let peer_address_family_mismatch_msg = build_msg(
                            m.transaction_id,
                            MessageType::new(METHOD_CHANNEL_BIND, CLASS_ERROR_RESPONSE),
                            vec![Box::new(ErrorCodeAttribute {
                                code: CODE_PEER_ADDR_FAMILY_MISMATCH,
                                reason: vec![],
                            })],
                        )?;
                        return build_and_send_err(
                            &self.conn,
                            self.src_addr,
                            peer_address_family_mismatch_msg,
                            Error::ErrPeerAddressFamilyMismatch,
                        )
                        .await;
                    }
                }
            }

            log::debug!(
                "binding channel {} to {}",
                channel,
                format!("{}:{}", peer_addr.ip, peer_addr.port)
            );

            let result = {
                a.add_channel_bind(
                    ChannelBind::new(channel, SocketAddr::new(peer_addr.ip, peer_addr.port)),
                    self.channel_bind_timeout,
                )
                .await
            };
            if let Err(err) = result {
                return build_and_send_err(&self.conn, self.src_addr, bad_request_msg, err).await;
            }

            let msg = build_msg(
                m.transaction_id,
                MessageType::new(METHOD_CHANNEL_BIND, CLASS_SUCCESS_RESPONSE),
                vec![Box::new(message_integrity)],
            )?;
            build_and_send(&self.conn, self.src_addr, msg).await
        } else {
            Err(Error::ErrNoAllocationFound)
        }
    }

    pub(crate) async fn handle_channel_data(&mut self, c: &ChannelData) -> Result<(), Error> {
        log::debug!("received ChannelData from {}", self.src_addr);

        let a = self
            .allocation_manager
            .get_allocation(&self.five_tuple)
            .await;

        if let Some(a) = a {
            let channel = a.get_channel_addr(&c.number).await;
            if let Some(peer) = channel {
                let l = a.relay_socket.send_to(&c.data, peer).await?;
                if l != c.data.len() {
                    Err(Error::ErrShortWrite)
                } else {
                    a.relayed_bytes.fetch_add(c.data.len(), Ordering::AcqRel);

                    Ok(())
                }
            } else {
                Err(Error::ErrNoSuchChannelBind)
            }
        } else {
            Err(Error::ErrNoAllocationFound)
        }
    }
}

pub(crate) fn rand_seq(n: usize) -> String {
    let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes();
    let mut buf = vec![0u8; n];
    for b in &mut buf {
        *b = letters[rand::random::<usize>() % letters.len()];
    }
    if let Ok(s) = String::from_utf8(buf) {
        s
    } else {
        String::new()
    }
}

pub(crate) fn build_nonce() -> Result<String, Error> {
    // #nosec
    let mut s = String::new();
    s.push_str(
        format!(
            "{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_nanos()
        )
        .as_str(),
    );
    s.push_str(format!("{}", rand::random::<u64>()).as_str());

    let mut h = Md5::new();
    h.update(s.as_bytes());
    Ok(format!("{:x}", h.finalize()))
}

pub(crate) async fn build_and_send(
    conn: &Arc<dyn Conn + Send + Sync>,
    dst: SocketAddr,
    msg: Message,
) -> Result<(), Error> {
    let _ = conn.send_to(&msg.raw, dst).await?;
    Ok(())
}

/// Send a STUN packet and return the original error to the caller
pub(crate) async fn build_and_send_err(
    conn: &Arc<dyn Conn + Send + Sync>,
    dst: SocketAddr,
    msg: Message,
    err: Error,
) -> Result<(), Error> {
    build_and_send(conn, dst, msg).await?;

    Err(err)
}

pub(crate) fn build_msg(
    transaction_id: TransactionId,
    msg_type: MessageType,
    mut additional: Vec<Box<dyn Setter>>,
) -> Result<Message, Error> {
    let mut attrs: Vec<Box<dyn Setter>> = vec![
        Box::new(Message {
            transaction_id,
            ..Default::default()
        }),
        Box::new(msg_type),
    ];

    attrs.append(&mut additional);

    let mut msg = Message::new();
    msg.build(&attrs)?;
    Ok(msg)
}

pub(crate) fn allocation_lifetime(m: &Message) -> Duration {
    let mut lifetime_duration = DEFAULT_LIFETIME;

    let mut lifetime = Lifetime::default();
    if lifetime.get_from(m).is_ok() && lifetime.0 < MAXIMUM_ALLOCATION_LIFETIME {
        lifetime_duration = lifetime.0;
    }

    lifetime_duration
}

#[cfg(test)]
mod request_test {
    use std::{net::IpAddr, str::FromStr};

    use tokio::{
        net::UdpSocket,
        time::{Duration, Instant},
    };

    use crate::{con::*, error::Error, relay::*};

    use super::*;

    const STATIC_KEY: &str = "ABC";

    #[tokio::test]
    async fn test_allocation_lifetime_parsing() {
        let lifetime = Lifetime(Duration::from_secs(5));

        let mut m = Message::new();
        let lifetime_duration = allocation_lifetime(&m);

        assert_eq!(
            lifetime_duration, DEFAULT_LIFETIME,
            "Allocation lifetime should be default time duration"
        );

        lifetime.add_to(&mut m).unwrap();

        let lifetime_duration = allocation_lifetime(&m);
        assert_eq!(
            lifetime_duration, lifetime.0,
            "Expect lifetime_duration is {lifetime}, but {lifetime_duration:?}"
        );
    }

    #[tokio::test]
    async fn test_allocation_lifetime_overflow() {
        let lifetime = Lifetime(MAXIMUM_ALLOCATION_LIFETIME * 2);

        let mut m2 = Message::new();
        lifetime.add_to(&mut m2).unwrap();

        let lifetime_duration = allocation_lifetime(&m2);
        assert_eq!(
            lifetime_duration, DEFAULT_LIFETIME,
            "Expect lifetime_duration is {DEFAULT_LIFETIME:?}, but {lifetime_duration:?}"
        );
    }

    struct TestAuthHandler;
    impl AuthHandler for TestAuthHandler {
        fn auth_handle(
            &self,
            _username: &str,
            _realm: &str,
            _src_addr: SocketAddr,
        ) -> Result<Vec<u8>, Error> {
            Ok(STATIC_KEY.as_bytes().to_vec())
        }
    }

    #[tokio::test]
    async fn test_allocation_lifetime_deletion_zero_lifetime() {
        let l = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let allocation_manager = Arc::new(Manager::new(ManagerConfig {
            relay_addr_generator: Box::new(RelayAddressGeneratorNone {
                address: "0.0.0.0".to_owned(),
                net: Arc::new(Net::default()),
            }),
            alloc_close_notify: None,
        }));

        let socket = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 5000);
        let five_tuple = FiveTuple {
            src_addr: socket,
            dst_addr: l.local_addr().unwrap(),
            protocol: l.proto(),
        };
        let mut r = Request {
            conn: l,
            src_addr: socket,
            buff: vec![],
            allocation_manager,
            nonces: Arc::new(Mutex::new(HashMap::new())),
            auth_handler: Arc::new(TestAuthHandler {}),
            realm: String::new(),
            channel_bind_timeout: Duration::from_secs(0),
            five_tuple,
        };

        {
            let mut nonces = r.nonces.lock().await;
            nonces.insert(STATIC_KEY.to_owned(), Instant::now());
        }

        r.allocation_manager
            .create_allocation(
                r.five_tuple,
                Arc::clone(&r.conn),
                0,
                Duration::from_secs(3600),
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();
        assert!(r
            .allocation_manager
            .get_allocation(&r.five_tuple)
            .await
            .is_some());

        let mut m = Message::new();
        Lifetime::default().add_to(&mut m).unwrap();
        MessageIntegrity(STATIC_KEY.as_bytes().to_vec())
            .add_to(&mut m)
            .unwrap();
        Nonce::new(ATTR_NONCE, STATIC_KEY.to_owned())
            .add_to(&mut m)
            .unwrap();
        Realm::new(ATTR_REALM, STATIC_KEY.to_owned())
            .add_to(&mut m)
            .unwrap();
        Username::new(ATTR_USERNAME, STATIC_KEY.to_owned())
            .add_to(&mut m)
            .unwrap();

        r.handle_refresh_request(&m).await.unwrap();
        assert!(r
            .allocation_manager
            .get_allocation(&r.five_tuple)
            .await
            .is_none());
    }
}
