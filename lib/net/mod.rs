use std::{
    collections::{HashMap, HashSet, hash_map},
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use fallible_iterator::FallibleIterator;
use futures::{StreamExt, channel::mpsc};
use heed::types::{SerdeBincode, Unit};
use parking_lot::RwLock;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use sneed::{
    DatabaseUnique, DbError, EnvError, RoTxn, RwTxn, RwTxnError, UnitKey,
};
use tokio_stream::StreamNotifyClose;
use tracing::instrument;

use crate::{
    archive::Archive,
    state::State,
    types::{
        AuthorizedTransaction, Network, THIS_SIDECHAIN, VERSION, Version,
        net::{Peer, PeerConnectionStatus},
    },
    util::ErrorChain,
};

pub mod error;
mod peer;

pub use error::Error;
pub(crate) use peer::error::mailbox::Error as PeerConnectionMailboxError;
use peer::{
    Connection, ConnectionContext as PeerConnectionCtxt,
    ConnectionHandle as PeerConnectionHandle,
};
pub use peer::{
    ConnectionError as PeerConnectionError, Info as PeerConnectionInfo,
    InternalMessage as PeerConnectionMessage, PeerStateId,
    Request as PeerRequest, ResponseMessage as PeerResponse,
    message as peer_message,
};

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn configure_client() -> Result<ClientConfig, error::ConfigureClient> {
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .map_err(error::configure_client::Inner::Rustls)?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    let client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(client_config)))
}

/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Error> {
    let cert_key =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let keypair_der = cert_key.key_pair.serialize_der();
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(keypair_der.into());
    let cert_der = cert_key.cert.der().to_vec();
    let cert_chain = vec![cert_key.cert.into()];

    let mut server_config =
        ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(1_u8.into());

    Ok((server_config, cert_der))
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
pub fn make_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<(Endpoint, Vec<u8>), Error> {
    let (server_config, server_cert) = configure_server()?;

    tracing::info!("creating server endpoint: binding to {bind_addr}",);

    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    let client_cfg = configure_client()?;
    endpoint.set_default_client_config(client_cfg);
    Ok((endpoint, server_cert))
}

// None indicates that the stream has ended
pub type PeerInfoRx =
    mpsc::UnboundedReceiver<(SocketAddr, Option<PeerConnectionInfo>)>;

const SIGNET_SEED_NODE_ADDRS: &[SocketAddr] = {
    const SIGNET_MINING_SERVER: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 105, 148, 135)),
        4000 + THIS_SIDECHAIN as u16,
    );
    // thunder.bip300.xyz
    const BIP300_XYZ: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(95, 217, 243, 12)),
        4000 + THIS_SIDECHAIN as u16,
    );
    &[SIGNET_MINING_SERVER, BIP300_XYZ]
};

const FORKNET_SEED_NODE_ADDRS: &[SocketAddr] = {
    // explorer.bip300.xyz
    const BIP300_XYZ: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(157, 180, 8, 224)),
        4000 + THIS_SIDECHAIN as u16,
    );
    &[BIP300_XYZ]
};

const ALPHANET_SEED_NODE_ADDR: (&str, u16) =
    ("seed.alpha.ecash.eu.com", 4000 + THIS_SIDECHAIN as u16);

/// Name of the seed node that the network resolves at every dial.
fn seed_node_name(network: Network) -> Option<(&'static str, u16)> {
    match network {
        Network::Alphanet => Some(ALPHANET_SEED_NODE_ADDR),
        Network::Signet | Network::Regtest | Network::Forknet => None,
    }
}

fn seed_node_addrs(network: Network) -> Result<Vec<SocketAddr>, Error> {
    let addresses = match network {
        Network::Signet => SIGNET_SEED_NODE_ADDRS,
        Network::Regtest => &[],
        Network::Forknet => FORKNET_SEED_NODE_ADDRS,
        Network::Alphanet => {
            return ALPHANET_SEED_NODE_ADDR
                .to_socket_addrs()
                .map(Iterator::collect)
                .map_err(|source| Error::ResolveSeed {
                    address: format!(
                        "{}:{}",
                        ALPHANET_SEED_NODE_ADDR.0, ALPHANET_SEED_NODE_ADDR.1
                    ),
                    source,
                });
        }
    };
    Ok(addresses.to_vec())
}

// Keep track of peer state
// Exchange metadata
// Bulk download
// Propagation
//
// Initial block download
//
// 1. Download headers
// 2. Download blocks
// 3. Update the state
#[derive(Clone)]
pub struct Net {
    pub server: Endpoint,
    archive: Archive,
    magic_bytes: peer_message::MagicBytes,
    state: State,
    active_peers: Arc<RwLock<HashMap<SocketAddr, PeerConnectionHandle>>>,
    // None indicates that the stream has ended
    peer_info_tx:
        mpsc::UnboundedSender<(SocketAddr, Option<PeerConnectionInfo>)>,
    known_peers: DatabaseUnique<SerdeBincode<SocketAddr>, Unit>,
    seed_node_name: Option<(&'static str, u16)>,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
}

impl Net {
    pub const NUM_DBS: u32 = 2;

    fn add_active_peer(
        &self,
        addr: SocketAddr,
        peer_connection_handle: PeerConnectionHandle,
        info_rx: mpsc::UnboundedReceiver<PeerConnectionInfo>,
    ) -> Result<(), error::AlreadyConnected> {
        tracing::trace!(%addr, "add active peer: starting");
        let mut active_peers_write = self.active_peers.write();
        match active_peers_write.entry(addr) {
            hash_map::Entry::Occupied(_) => {
                tracing::error!(%addr, "add active peer: already connected");
                return Err(error::AlreadyConnected(addr));
            }
            hash_map::Entry::Vacant(active_peer_entry) => {
                active_peer_entry.insert(peer_connection_handle);
            }
        }
        drop(active_peers_write);
        tokio::spawn({
            let info_rx = StreamNotifyClose::new(info_rx)
                .map(move |info| Ok((addr, info)));
            let peer_info_tx = self.peer_info_tx.clone();
            async move {
                if let Err(_send_err) = info_rx.forward(peer_info_tx).await {
                    tracing::error!(%addr, "Failed to send peer connection info");
                }
            }
        });
        Ok(())
    }

    pub fn remove_active_peer(&self, addr: SocketAddr) {
        tracing::trace!(%addr, "remove active peer: starting");
        let mut active_peers_write = self.active_peers.write();
        if let Some(peer_connection) = active_peers_write.remove(&addr) {
            drop(peer_connection);
            tracing::info!(%addr, "remove active peer: disconnected");
        }
    }

    /// Apply the provided function to the peer connection handle,
    /// if it exists.
    pub fn try_with_active_peer_connection<F, T>(
        &self,
        addr: SocketAddr,
        f: F,
    ) -> Option<T>
    where
        F: FnMut(&PeerConnectionHandle) -> T,
    {
        let active_peers_read = self.active_peers.read();
        active_peers_read.get(&addr).map(f)
    }

    // TODO: This should have more context.
    // Last received message, connection state, etc.
    pub fn get_active_peers(&self) -> Vec<Peer> {
        self.active_peers
            .read()
            .iter()
            .map(|(addr, conn_handle)| Peer {
                address: *addr,
                status: conn_handle.connection_status(),
            })
            .collect()
    }

    #[instrument(skip_all, fields(addr), err(Debug))]
    pub fn connect_peer(
        &self,
        env: sneed::Env<heed::WithoutTls>,
        addr: SocketAddr,
    ) -> Result<(), Error> {
        if self.active_peers.read().contains_key(&addr) {
            tracing::error!("connect peer: already connected");
            return Err(error::AlreadyConnected(addr).into());
        }

        // This check happens within Quinn with a
        // generic "invalid remote address". We run the
        // same check, and provide a friendlier error
        // message.
        if addr.ip().is_unspecified() {
            return Err(Error::UnspecfiedPeerIP(addr.ip()));
        }
        let connecting = self.server.connect(addr, "localhost")?;
        let mut rwtxn = env.write_txn().map_err(EnvError::from)?;
        self.known_peers
            .put(&mut rwtxn, &addr, &())
            .map_err(DbError::from)?;
        rwtxn.commit().map_err(RwTxnError::from)?;
        let connection_ctxt = PeerConnectionCtxt {
            env,
            archive: self.archive.clone(),
            magic_bytes: self.magic_bytes,
            state: self.state.clone(),
        };

        let (connection_handle, info_rx) =
            peer::connect(connecting, connection_ctxt);
        self.add_active_peer(addr, connection_handle, info_rx)?;
        Ok(())
    }

    /// Delete peer from known_peers DB.
    /// Connections to the peer are not terminated.
    pub fn forget_peer(
        &self,
        rwtxn: &mut RwTxn,
        addr: &SocketAddr,
    ) -> Result<bool, Error> {
        self.known_peers
            .delete(rwtxn, addr)
            .map_err(|err| DbError::from(err).into())
    }

    fn known_peer_addrs(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Vec<SocketAddr>, DbError> {
        let peer_addrs = self.known_peers.iter_keys(rotxn)?.collect()?;
        Ok(peer_addrs)
    }

    fn is_active_peer(&self, addr: &SocketAddr) -> bool {
        self.active_peers.read().contains_key(addr)
    }

    /// Resolve the seed node name of the network to addresses.
    /// Returns an empty vector for a network without a seed node name.
    async fn resolve_seed_node_addrs(&self) -> Result<Vec<SocketAddr>, Error> {
        let Some((host, port)) = self.seed_node_name else {
            return Ok(Vec::new());
        };
        let addrs =
            tokio::net::lookup_host((host, port))
                .await
                .map_err(|source| Error::ResolveSeed {
                    address: format!("{host}:{port}"),
                    source,
                })?;
        Ok(addrs.collect())
    }

    /// Dial a peer that the database knows.
    /// Returns `true` if a connection started, and `false` if the peer is
    /// already connected.
    fn dial_known_peer(
        &self,
        env: sneed::Env<heed::WithoutTls>,
        addr: SocketAddr,
    ) -> Result<bool, Error> {
        if self.is_active_peer(&addr) {
            return Ok(false);
        }
        tracing::trace!(%addr, "connecting to already known peer");
        let () = self.connect_peer(env, addr)?;
        Ok(true)
    }

    /// Dial every peer that the database knows, and every address that the
    /// seed node name resolves to.
    /// Returns the number of connections that started.
    async fn dial_known_peers(
        &self,
        env: &sneed::Env<heed::WithoutTls>,
    ) -> Result<usize, Error> {
        let mut peer_addrs: HashSet<SocketAddr> = {
            let rotxn = env.read_txn().map_err(EnvError::from)?;
            self.known_peer_addrs(&rotxn)?.into_iter().collect()
        };
        match self.resolve_seed_node_addrs().await {
            Ok(seed_addrs) => peer_addrs.extend(seed_addrs),
            Err(err) => {
                tracing::error!("{:#}", ErrorChain::new(&err))
            }
        }
        let mut dialed = 0;
        for peer_addr in peer_addrs {
            match self.dial_known_peer(env.clone(), peer_addr) {
                Ok(true) => dialed += 1,
                Ok(false) => (),
                Err(err) => {
                    tracing::error!(%peer_addr, "{:#}", ErrorChain::new(&err))
                }
            }
        }
        Ok(dialed)
    }

    /// Dial the known peers again while no peer connection exists.
    /// `min_delay` is the shortest wait between two checks for a connection.
    /// The wait doubles after each redial, up to `max_delay`.
    /// The future returns only on a database error.
    pub async fn redial_known_peers(
        &self,
        env: sneed::Env<heed::WithoutTls>,
        min_delay: Duration,
        max_delay: Duration,
    ) -> Result<(), Error> {
        let mut delay = min_delay;
        let mut no_peers_at_last_check = false;
        loop {
            tokio::time::sleep(delay).await;
            if !self.active_peers.read().is_empty() {
                delay = min_delay;
                no_peers_at_last_check = false;
                continue;
            }
            // The net task reconnects to a peer that errored. A redial waits
            // for a full delay with no connection, so it never dials first.
            if !no_peers_at_last_check {
                no_peers_at_last_check = true;
                continue;
            }
            let dialed = self.dial_known_peers(&env).await?;
            tracing::info!(dialed, "no peer connection: dialed known peers");
            delay = (2 * delay).min(max_delay);
        }
    }

    pub fn new(
        env: &sneed::Env<heed::WithoutTls>,
        archive: Archive,
        magic_bytes_override: Option<peer_message::MagicBytes>,
        network: Network,
        state: State,
        bind_addr: SocketAddr,
    ) -> Result<(Self, PeerInfoRx), Error> {
        let (server, _) = make_server_endpoint(bind_addr)?;
        let active_peers = Arc::new(RwLock::new(HashMap::new()));
        let mut rwtxn = env.write_txn()?;
        let known_peers =
            match DatabaseUnique::open(env, &rwtxn, "known_peers")? {
                Some(known_peers) => known_peers,
                None => {
                    let known_peers =
                        DatabaseUnique::create(env, &mut rwtxn, "known_peers")?;
                    for seed_node_addr in seed_node_addrs(network)? {
                        known_peers.put(&mut rwtxn, &seed_node_addr, &())?;
                    }
                    known_peers
                }
            };
        let version = DatabaseUnique::create(env, &mut rwtxn, "net_version")?;
        if version.try_get(&rwtxn, &())?.is_none() {
            version.put(&mut rwtxn, &(), &*VERSION)?;
        }
        rwtxn.commit().map_err(RwTxnError::from)?;
        let magic_bytes = magic_bytes_override
            .unwrap_or_else(|| peer_message::magic_bytes(network));
        let (peer_info_tx, peer_info_rx) = mpsc::unbounded();
        let net = Net {
            server,
            archive,
            magic_bytes,
            state,
            active_peers,
            peer_info_tx,
            known_peers,
            seed_node_name: seed_node_name(network),
            _version: version,
        };
        let known_peers: Vec<SocketAddr> = {
            let rotxn = env.read_txn().map_err(EnvError::from)?;
            net.known_peer_addrs(&rotxn)?
        };
        let () = known_peers.into_iter().try_for_each(|peer_addr| {
            tracing::trace!(
                "new net: connecting to already known peer at {peer_addr}"
            );
            match net.connect_peer(env.clone(), peer_addr) {
                Err(Error::Connect(
                    quinn::ConnectError::InvalidRemoteAddress(addr),
                )) => {
                    tracing::warn!(
                        %addr, "new net: known peer with invalid remote address, removing"
                    );
                    let mut rwtxn = env.write_txn()?;
                    net.known_peers.delete(&mut rwtxn, &peer_addr).map_err(DbError::from)?;
                    rwtxn.commit()?;
                    tracing::info!(
                        %addr,
                        "new net: removed known peer with invalid remote address"
                    );
                    Ok(())
                }
                res => res,
            }
        })
        // TODO: would be better to indicate this in the return error? tbh I want to scrap
        // the typed error out of here, and just use anyhow
        .inspect_err(|err| {
            tracing::error!("unable to connect to known peers during net construction: {err:#}");
        })?;
        Ok((net, peer_info_rx))
    }

    /// Accept the next incoming connection. Returns Some(addr) if a connection was accepted
    /// and a new peer was added.
    pub async fn accept_incoming(
        &self,
        env: sneed::Env<heed::WithoutTls>,
    ) -> Result<Option<SocketAddr>, error::AcceptConnection> {
        tracing::debug!(
            "accept incoming: listening for connections on `{}`",
            self.server
                .local_addr()
                .map(|socket| socket.to_string())
                .unwrap_or("unknown address".into())
        );
        let connection = match self.server.accept().await {
            Some(conn) => {
                let remote_address = conn.remote_address();
                tracing::trace!("accepting connection from {remote_address}",);

                let raw_conn = conn.await.map_err(|error| {
                    error::AcceptConnection::Connection {
                        error,
                        remote_address,
                    }
                })?;
                Connection::new(raw_conn, self.magic_bytes)
            }
            None => {
                tracing::debug!("server endpoint closed");
                return Err(error::AcceptConnection::ServerEndpointClosed);
            }
        };
        let addr = connection.addr();

        tracing::trace!(%addr, "accepted incoming connection");
        if self.active_peers.read().contains_key(&addr) {
            tracing::info!(
                %addr, "incoming connection: already peered, refusing duplicate",
            );
            connection
                .inner
                .close(quinn::VarInt::from_u32(1), b"already connected");
        }
        if connection.inner.close_reason().is_some() {
            return Ok(None);
        }
        tracing::info!(%addr, "connected to new peer");
        let mut rwtxn = env.write_txn().map_err(EnvError::from)?;
        self.known_peers
            .put(&mut rwtxn, &addr, &())
            .map_err(DbError::from)?;
        rwtxn.commit().map_err(RwTxnError::from)?;

        tracing::trace!(%addr, "wrote peer to database");
        let connection_ctxt = PeerConnectionCtxt {
            env,
            archive: self.archive.clone(),
            magic_bytes: self.magic_bytes,
            state: self.state.clone(),
        };
        let (connection_handle, info_rx) =
            peer::handle(connection_ctxt, connection);
        self.add_active_peer(addr, connection_handle, info_rx)?;
        Ok(Some(addr))
    }

    /// Attempt to push an internal message to the specified peer
    /// Returns `true` if successful
    pub fn push_internal_message(
        &self,
        message: PeerConnectionMessage,
        addr: SocketAddr,
    ) -> bool {
        let active_peers_read = self.active_peers.read();
        let Some(peer_connection_handle) = active_peers_read.get(&addr) else {
            let err = Error::MissingPeerConnection(addr);
            tracing::warn!("{:#}", ErrorChain::new(&err));
            return false;
        };

        if let Err(send_err) = peer_connection_handle
            .internal_message_tx
            .unbounded_send(message)
        {
            let message = send_err.into_inner();
            tracing::warn!(
                "Failed to push internal message to peer connection {addr}: {message:?}"
            );
            return false;
        }
        true
    }

    /// Push a tx to all active peers, except those in the provided set
    pub fn push_tx(
        &self,
        exclude: HashSet<SocketAddr>,
        tx: &AuthorizedTransaction,
    ) {
        self.active_peers
            .read()
            .iter()
            .filter(|(addr, _)| !exclude.contains(addr))
            .for_each(|(addr, peer_connection_handle)| {
                match peer_connection_handle.connection_status() {
                    PeerConnectionStatus::Connecting => {
                        tracing::trace!(%addr, "skipping peer at {addr} because it is not fully connected");
                        return;
                    }
                    PeerConnectionStatus::Connected => {}
                }
                let request: PeerRequest = peer::message::PushTransactionRequest {
                    transaction: Box::new(tx.clone()),
                }.into();
                if let Err(_send_err) = peer_connection_handle
                    .internal_message_tx
                    .unbounded_send(request.into())
                {
                    let txid = tx.transaction.txid();
                    tracing::warn!("Failed to push tx {txid} to peer at {addr}")
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;

    use super::*;

    const TEST_REDIAL_MIN_DELAY: Duration = Duration::from_millis(50);
    const TEST_REDIAL_MAX_DELAY: Duration = Duration::from_millis(200);

    type TempNet = (
        temp_dir::TempDir,
        sneed::Env<heed::WithoutTls>,
        Net,
        PeerInfoRx,
    );

    fn temp_net() -> anyhow::Result<TempNet> {
        let directory = temp_dir::TempDir::new()?;
        let mut options = heed::EnvOpenOptions::new().read_txn_without_tls();
        options
            .map_size(64 * 1024 * 1024)
            .max_dbs(Archive::NUM_DBS + State::NUM_DBS + Net::NUM_DBS);
        let env = unsafe { sneed::Env::open(&options, directory.path()) }?;
        let archive = Archive::new(&env)?;
        let state = State::new(&env)?;
        let (net, peer_info_rx) = Net::new(
            &env,
            archive,
            None,
            Network::Regtest,
            state,
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        Ok((directory, env, net, peer_info_rx))
    }

    fn spawn_redial(
        env: sneed::Env<heed::WithoutTls>,
        net: Net,
    ) -> tokio::task::JoinHandle<Result<(), Error>> {
        tokio::spawn(async move {
            net.redial_known_peers(
                env,
                TEST_REDIAL_MIN_DELAY,
                TEST_REDIAL_MAX_DELAY,
            )
            .await
        })
    }

    /// A peer that drops leaves no connection, so the node dials it again.
    #[tokio::test]
    async fn a_lost_peer_is_dialed_again() -> anyhow::Result<()> {
        let (_directory, env, net, _peer_info_rx) = temp_net()?;
        let (remote, _) =
            make_server_endpoint((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
        let addr = remote.local_addr()?;
        net.connect_peer(env.clone(), addr)?;
        assert_eq!(net.get_active_peers().len(), 1);
        net.remove_active_peer(addr);
        assert!(net.get_active_peers().is_empty());

        let redial = spawn_redial(env.clone(), net.clone());
        let dialed_again =
            tokio::time::timeout(Duration::from_secs(5), async {
                while net.get_active_peers().is_empty() {
                    tokio::time::sleep(TEST_REDIAL_MIN_DELAY).await;
                }
            })
            .await;
        redial.abort();

        dialed_again.context("the node dialed the lost peer no more")?;
        assert_eq!(net.get_active_peers()[0].address, addr);
        Ok(())
    }

    /// A peer that holds a connection takes no redial, and the loop starts no
    /// second connection to it.
    #[tokio::test]
    async fn a_connected_peer_takes_no_redial() -> anyhow::Result<()> {
        let (_directory, env, net, _peer_info_rx) = temp_net()?;
        let (remote, _) =
            make_server_endpoint((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
        let addr = remote.local_addr()?;
        net.connect_peer(env.clone(), addr)?;

        assert!(!net.dial_known_peer(env.clone(), addr)?);
        assert_eq!(net.dial_known_peers(&env).await?, 0);

        let redial = spawn_redial(env.clone(), net.clone());
        tokio::time::sleep(TEST_REDIAL_MAX_DELAY * 5).await;
        redial.abort();

        let peers = net.get_active_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, addr);
        Ok(())
    }

    /// The database holds the address that the seed node had at startup.
    /// A seed node that moves gets a dial at the address that the name
    /// resolves to now.
    #[tokio::test]
    async fn a_moved_seed_is_dialed_at_the_new_address() -> anyhow::Result<()> {
        let (_directory, env, mut net, _peer_info_rx) = temp_net()?;
        let stale_addr =
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 1_u16));
        let mut rwtxn = env.write_txn()?;
        net.known_peers.put(&mut rwtxn, &stale_addr, &())?;
        rwtxn.commit()?;
        let (seed, _) =
            make_server_endpoint((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
        let seed_addr = seed.local_addr()?;
        net.seed_node_name = Some(("localhost", seed_addr.port()));

        let redial = spawn_redial(env.clone(), net.clone());
        let dialed_seed = tokio::time::timeout(Duration::from_secs(5), async {
            while !net.is_active_peer(&seed_addr) {
                tokio::time::sleep(TEST_REDIAL_MIN_DELAY).await;
            }
        })
        .await;
        redial.abort();

        dialed_seed.context("the node dialed the moved seed node no more")?;
        Ok(())
    }

    #[tokio::test]
    async fn rejected_duplicate_has_no_peer_close_event() -> anyhow::Result<()>
    {
        let directory = temp_dir::TempDir::new()?;
        let mut options = heed::EnvOpenOptions::new().read_txn_without_tls();
        options
            .map_size(64 * 1024 * 1024)
            .max_dbs(Archive::NUM_DBS + State::NUM_DBS + Net::NUM_DBS);
        let env = unsafe { sneed::Env::open(&options, directory.path()) }?;
        let archive = Archive::new(&env)?;
        let state = State::new(&env)?;
        let (net, info_rx) = Net::new(
            &env,
            archive,
            None,
            Network::Regtest,
            state,
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let (remote, _) =
            make_server_endpoint((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
        let addr = remote.local_addr()?;
        net.connect_peer(env.clone(), addr)?;
        let connection_ctxt = super::PeerConnectionCtxt {
            env,
            archive: net.archive.clone(),
            magic_bytes: net.magic_bytes,
            state: net.state.clone(),
        };
        let (duplicate, duplicate_info) = super::peer::connect(
            net.server.connect(addr, "localhost")?,
            connection_ctxt,
        );

        let error = net
            .add_active_peer(addr, duplicate, duplicate_info)
            .unwrap_err();
        assert_eq!(error.0, addr);
        assert_eq!(net.get_active_peers().len(), 1);
        drop(net);

        let events = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            info_rx.collect::<Vec<_>>(),
        )
        .await?;
        assert_eq!(events.iter().filter(|(_, info)| info.is_none()).count(), 1);
        Ok(())
    }

    #[test]
    fn alphanet_seed_uses_sidechain_port() {
        assert_eq!(ALPHANET_SEED_NODE_ADDR, ("seed.alpha.ecash.eu.com", 4098));
    }

    #[test]
    fn network_magic_keeps_distinct_values() {
        for (network, last_byte) in [
            (Network::Regtest, 0),
            (Network::Signet, 1),
            (Network::Forknet, 2),
            (Network::Alphanet, 3),
        ] {
            assert_eq!(
                peer_message::magic_bytes(network),
                [0x8d, 0x19, 0x28, last_byte]
            );
        }
    }

    #[test]
    fn existing_network_seeds_stay_the_same() -> anyhow::Result<()> {
        assert_eq!(seed_node_addrs(Network::Signet)?, SIGNET_SEED_NODE_ADDRS);
        assert_eq!(seed_node_addrs(Network::Forknet)?, FORKNET_SEED_NODE_ADDRS);
        assert!(seed_node_addrs(Network::Regtest)?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn ipv4_bind_accepts_mixed_address_families() -> anyhow::Result<()> {
        let directory = temp_dir::TempDir::new()?;
        let mut options = heed::EnvOpenOptions::new().read_txn_without_tls();
        options
            .map_size(64 * 1024 * 1024)
            .max_dbs(Archive::NUM_DBS + State::NUM_DBS + Net::NUM_DBS);
        let env = unsafe { sneed::Env::open(&options, directory.path()) }?;
        let archive = Archive::new(&env)?;
        let state = State::new(&env)?;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let ipv4 = socket.local_addr()?;
        let ipv6 =
            SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), ipv4.port());
        let mut transaction = env.write_txn()?;
        let peers: DatabaseUnique<SerdeBincode<SocketAddr>, Unit> =
            DatabaseUnique::create(&env, &mut transaction, "known_peers")?;
        for address in [ipv6, ipv4] {
            peers.put(&mut transaction, &address, &())?;
        }
        transaction.commit()?;
        let (net, _peer_info) = Net::new(
            &env,
            archive,
            None,
            Network::Regtest,
            state,
            "0.0.0.0:0".parse()?,
        )?;
        assert_eq!(
            net.get_active_peers()
                .iter()
                .map(|peer| peer.address)
                .collect::<Vec<_>>(),
            vec![ipv4]
        );
        assert_eq!(
            net.server.local_addr()?.ip(),
            std::net::Ipv4Addr::UNSPECIFIED
        );
        let transaction = env.read_txn()?;
        assert!(peers.try_get(&transaction, &ipv4)?.is_some());
        assert!(peers.try_get(&transaction, &ipv6)?.is_none());
        drop(transaction);
        net.remove_active_peer(ipv4);
        net.server.close(0_u32.into(), b"test complete");
        net.server.wait_idle().await;
        drop(net);
        drop(env);
        Ok(())
    }
}
