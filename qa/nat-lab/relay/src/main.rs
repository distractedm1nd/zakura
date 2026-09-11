use anyhow::Result;
use iroh_relay::{
    server::{
        testing::self_signed_tls_certs_and_config, AllowAll, CertConfig, QuicConfig,
        RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig,
    },
    RelayConfig, RelayMap, RelayQuicConfig,
};
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let (_map, _server) = relay().await?;
    println!("READY");
    // The parent owns the lifetime; this also bounds an orphaned helper.
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    Ok(())
}

async fn relay() -> Result<(RelayMap, Server)> {
    let (_, server_config) = self_signed_tls_certs_and_config();
    let bind: std::net::IpAddr = "0.0.0.0".parse()?;
    let mut config = RelayServerConfig::new((bind, 80));
    config.tls = Some(TlsConfig::new(
        (bind, 443),
        CertConfig::Manual { server_config },
    ));
    config.access = Arc::new(AllowAll);
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(config);
    server_config.quic = Some(QuicConfig::new((bind, 7842)));
    let server = Server::spawn(server_config).await?;
    let map = RelayConfig::new(
        "https://relay.test".parse()?,
        server.quic_addr().map(|a| RelayQuicConfig::new(a.port())),
    )
    .into();
    Ok((map, server))
}
