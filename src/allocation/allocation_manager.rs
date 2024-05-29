use std::collections::HashMap;

use futures::future;
use tokio::sync::mpsc;

use super::*;

use crate::{con::Conn, error::*, proto::Protocol, relay::*, stun::textattrs::Username};

/// `ManagerConfig` a bag of config params for `Manager`.
pub struct ManagerConfig {
    pub relay_addr_generator: Box<dyn RelayAddressGenerator + Send + Sync>,
    pub alloc_close_notify: Option<mpsc::Sender<AllocationInfo>>,
}

/// `Manager` is used to hold active allocations.
pub struct Manager {
    allocations: AllocationMap,
    reservations: Arc<Mutex<HashMap<String, u16>>>,
    relay_addr_generator: Box<dyn RelayAddressGenerator + Send + Sync>,
    alloc_close_notify: Option<mpsc::Sender<AllocationInfo>>,
}

impl Manager {
    /// Creates a new [`Manager`].
    pub fn new(config: ManagerConfig) -> Self {
        Manager {
            allocations: Arc::new(Mutex::new(HashMap::new())),
            reservations: Arc::new(Mutex::new(HashMap::new())),
            relay_addr_generator: config.relay_addr_generator,
            alloc_close_notify: config.alloc_close_notify,
        }
    }

    /// Closes this [`manager`] and closes all [`Allocation`]s it manages.
    pub async fn close(&self) -> Result<(), Error> {
        let allocations = self.allocations.lock().await;
        for a in allocations.values() {
            a.close().await?;
        }
        Ok(())
    }

    /// Returns the information about the all [`Allocation`]s associated with
    /// the specified [`FiveTuple`]s.
    pub async fn get_allocations_info(
        &self,
        five_tuples: Option<Vec<FiveTuple>>,
    ) -> HashMap<FiveTuple, AllocationInfo> {
        let mut infos = HashMap::new();

        let guarded = self.allocations.lock().await;

        guarded.iter().for_each(|(five_tuple, alloc)| {
            if five_tuples.is_none() || five_tuples.as_ref().unwrap().contains(five_tuple) {
                infos.insert(
                    *five_tuple,
                    AllocationInfo::new(
                        *five_tuple,
                        alloc.username.text.clone(),
                        alloc.relayed_bytes.load(Ordering::Acquire),
                    ),
                );
            }
        });

        infos
    }

    /// Fetches the [`Allocation`] matching the passed [`FiveTuple`].
    pub async fn get_allocation(&self, five_tuple: &FiveTuple) -> Option<Arc<Allocation>> {
        let allocations = self.allocations.lock().await;
        allocations.get(five_tuple).cloned()
    }

    /// Creates a new [`Allocation`] and starts relaying.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_allocation(
        &self,
        five_tuple: FiveTuple,
        turn_socket: Arc<dyn Conn + Send + Sync>,
        requested_port: u16,
        lifetime: Duration,
        username: Username,
        use_ipv4: bool,
        protocol: Protocol,
    ) -> Result<Arc<Allocation>, Error> {
        if lifetime == Duration::from_secs(0) {
            return Err(Error::ErrLifetimeZero);
        }

        if self.get_allocation(&five_tuple).await.is_some() {
            return Err(Error::ErrDupeFiveTuple);
        }

        let (relay_socket, relay_addr) = self
            .relay_addr_generator
            .allocate_conn(use_ipv4, requested_port, protocol)
            .await?;
        let mut a = Allocation::new(
            turn_socket,
            relay_socket,
            relay_addr,
            five_tuple,
            username,
            self.alloc_close_notify.clone(),
        );
        a.allocations = Some(Arc::clone(&self.allocations));

        log::debug!("listening on relay addr: {:?}", a.relay_addr);
        a.start(lifetime).await;
        a.packet_handler().await;

        let a = Arc::new(a);
        {
            let mut allocations = self.allocations.lock().await;
            allocations.insert(five_tuple, Arc::clone(&a));
        }

        Ok(a)
    }

    /// Removes an [`Allocation`].
    pub async fn delete_allocation(&self, five_tuple: &FiveTuple) {
        let allocation = self.allocations.lock().await.remove(five_tuple);

        if let Some(a) = allocation {
            if let Err(err) = a.close().await {
                log::error!("Failed to close allocation: {}", err);
            }
        }
    }

    /// Deletes the [`Allocation`]s according to the specified username `name`.
    pub async fn delete_allocations_by_username(&self, name: &str) {
        let to_delete = {
            let mut allocations = self.allocations.lock().await;

            let mut to_delete = Vec::new();

            // TODO(logist322): Use `.drain_filter()` once stabilized.
            allocations.retain(|_, allocation| {
                let match_name = allocation.username.text == name;

                if match_name {
                    to_delete.push(Arc::clone(allocation));
                }

                !match_name
            });

            to_delete
        };

        future::join_all(to_delete.iter().map(|a| async move {
            if let Err(err) = a.close().await {
                log::error!("Failed to close allocation: {}", err);
            }
        }))
        .await;
    }

    /// Stores the reservation for the token+port.
    pub async fn create_reservation(&self, reservation_token: String, port: u16) {
        let reservations = Arc::clone(&self.reservations);
        let reservation_token2 = reservation_token.clone();

        tokio::spawn(async move {
            let sleep = tokio::time::sleep(Duration::from_secs(30));
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => {
                    let mut reservations = reservations.lock().await;
                    reservations.remove(&reservation_token2);
                },
            }
        });

        let mut reservations = self.reservations.lock().await;
        reservations.insert(reservation_token, port);
    }

    /// Returns the port for a given reservation if it exists.
    pub async fn get_reservation(&self, reservation_token: &str) -> Option<u16> {
        let reservations = self.reservations.lock().await;
        reservations.get(reservation_token).copied()
    }

    /// Returns a random un-allocated udp4 port.
    pub async fn get_random_even_port(&self, protocol: Protocol) -> Result<u16, Error> {
        let (_, addr) = self
            .relay_addr_generator
            .allocate_conn(true, 0, protocol)
            .await?;
        Ok(addr.port())
    }
}

#[cfg(test)]
mod allocation_manager_test {
    use std::{net::Ipv4Addr, str::FromStr};

    use tokio::net::UdpSocket;

    use super::*;

    use crate::{
        proto::{lifetime::DEFAULT_LIFETIME, PROTO_UDP},
        stun::{attrs::ATTR_USERNAME, textattrs::TextAttribute},
    };

    fn new_test_manager() -> Manager {
        let config = ManagerConfig {
            relay_addr_generator: Box::new(RelayAddressGeneratorNone {
                address: "0.0.0.0".to_owned(),
            }),
            alloc_close_notify: None,
        };
        Manager::new(config)
    }

    fn random_five_tuple() -> FiveTuple {
        FiveTuple {
            src_addr: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), rand::random()),
            dst_addr: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), rand::random()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_packet_handler() {
        // turn server initialization
        let turn_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // client listener initialization
        let client_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src_addr = client_listener.local_addr().unwrap();
        let (data_ch_tx, mut data_ch_rx) = mpsc::channel(1);
        // client listener read data
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 1500];
            loop {
                let n = match client_listener.recv_from(&mut buffer).await {
                    Ok((n, _)) => n,
                    Err(_) => break,
                };

                let _ = data_ch_tx.send(buffer[..n].to_vec()).await;
            }
        });

        let m = new_test_manager();
        let a = m
            .create_allocation(
                FiveTuple {
                    src_addr,
                    dst_addr: turn_socket.local_addr().unwrap(),
                    ..Default::default()
                },
                Arc::new(turn_socket),
                0,
                DEFAULT_LIFETIME,
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();

        let peer_listener1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_listener2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let channel_bind = ChannelBind::new(
            ChannelNumber(MIN_CHANNEL_NUMBER),
            peer_listener2.local_addr().unwrap(),
        );

        let port = {
            // add permission with peer1 address
            a.add_permission(Permission::new(peer_listener1.local_addr().unwrap()))
                .await;
            // add channel with min channel number and peer2 address
            a.add_channel_bind(channel_bind.clone(), DEFAULT_LIFETIME)
                .await
                .unwrap();

            a.relay_socket.local_addr().port()
        };

        let relay_addr_with_host_str = format!("127.0.0.1:{port}");
        let relay_addr_with_host = SocketAddr::from_str(&relay_addr_with_host_str).unwrap();

        // test for permission and data message
        let target_text = "permission";
        let _ = peer_listener1
            .send_to(target_text.as_bytes(), relay_addr_with_host)
            .await
            .unwrap();
        let data = data_ch_rx
            .recv()
            .await
            .ok_or(Error::Other("data ch closed".to_owned()))
            .unwrap();

        let mut msg = Message::new();
        msg.raw = data;
        msg.decode().unwrap();

        let mut msg_data = Data::default();
        msg_data.get_from(&msg).unwrap();
        assert_eq!(
            target_text.as_bytes(),
            &msg_data.0,
            "get message doesn't equal the target text"
        );

        // test for channel bind and channel data
        let target_text2 = "channel bind";
        let _ = peer_listener2
            .send_to(target_text2.as_bytes(), relay_addr_with_host)
            .await
            .unwrap();
        let data = data_ch_rx
            .recv()
            .await
            .ok_or(Error::Other("data ch closed".to_owned()))
            .unwrap();

        // resolve channel data
        assert!(
            ChannelData::is_channel_data(&data),
            "should be channel data"
        );

        let mut channel_data = ChannelData {
            raw: data,
            ..Default::default()
        };
        channel_data.decode().unwrap();
        assert_eq!(
            channel_bind.number, channel_data.number,
            "get channel data's number is invalid"
        );
        assert_eq!(
            target_text2.as_bytes(),
            &channel_data.data,
            "get data doesn't equal the target text."
        );

        // listeners close
        m.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_create_allocation_duplicate_five_tuple() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let five_tuple = random_five_tuple();

        let _ = m
            .create_allocation(
                five_tuple,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();

        let result = m
            .create_allocation(
                five_tuple,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await;
        assert!(result.is_err(), "expected error, but got ok");
    }

    #[tokio::test]
    async fn test_delete_allocation() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let five_tuple = random_five_tuple();

        let _ = m
            .create_allocation(
                five_tuple,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();

        assert!(
            m.get_allocation(&five_tuple).await.is_some(),
            "Failed to get allocation right after creation"
        );

        m.delete_allocation(&five_tuple).await;

        assert!(
            m.get_allocation(&five_tuple).await.is_none(),
            "Get allocation with {five_tuple} should be nil after delete"
        );
    }

    #[tokio::test]
    async fn test_allocation_timeout() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let mut allocations = vec![];
        let lifetime = Duration::from_millis(100);

        for _ in 0..5 {
            let five_tuple = random_five_tuple();

            let a = m
                .create_allocation(
                    five_tuple,
                    Arc::clone(&turn_socket),
                    0,
                    lifetime,
                    TextAttribute::new(ATTR_USERNAME, "user".into()),
                    true,
                    PROTO_UDP,
                )
                .await
                .unwrap();

            allocations.push(a);
        }

        let mut count = 0;

        'outer: loop {
            count += 1;

            if count >= 10 {
                panic!("Allocations didn't timeout");
            }

            tokio::time::sleep(lifetime + Duration::from_millis(100)).await;

            let any_outstanding = false;

            for a in &allocations {
                if a.close().await.is_ok() {
                    continue 'outer;
                }
            }

            if !any_outstanding {
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_manager_close() {
        // turn server initialization
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let mut allocations = vec![];

        let a1 = m
            .create_allocation(
                random_five_tuple(),
                Arc::clone(&turn_socket),
                0,
                Duration::from_millis(100),
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();
        allocations.push(a1);

        let a2 = m
            .create_allocation(
                random_five_tuple(),
                Arc::clone(&turn_socket),
                0,
                Duration::from_millis(200),
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();
        allocations.push(a2);

        tokio::time::sleep(Duration::from_millis(150)).await;

        log::trace!("Mgr is going to be closed...");

        m.close().await.unwrap();

        for a in allocations {
            assert!(
                a.close().await.is_err(),
                "Allocation should be closed if lifetime timeout"
            );
        }
    }

    #[tokio::test]
    async fn test_delete_allocation_by_username() {
        let turn_socket: Arc<dyn Conn + Send + Sync> =
            Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

        let m = new_test_manager();

        let five_tuple1 = random_five_tuple();
        let five_tuple2 = random_five_tuple();
        let five_tuple3 = random_five_tuple();

        let _ = m
            .create_allocation(
                five_tuple1,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();
        let _ = m
            .create_allocation(
                five_tuple2,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                TextAttribute::new(ATTR_USERNAME, "user".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();
        let _ = m
            .create_allocation(
                five_tuple3,
                Arc::clone(&turn_socket),
                0,
                DEFAULT_LIFETIME,
                TextAttribute::new(ATTR_USERNAME, "user2".into()),
                true,
                PROTO_UDP,
            )
            .await
            .unwrap();

        assert_eq!(m.allocations.lock().await.len(), 3);

        m.delete_allocations_by_username("user").await;

        assert_eq!(m.allocations.lock().await.len(), 1);

        assert!(
            m.get_allocation(&five_tuple1).await.is_none()
                && m.get_allocation(&five_tuple2).await.is_none()
                && m.get_allocation(&five_tuple3).await.is_some()
        );
    }
}
