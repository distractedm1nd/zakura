//! Isolated Linux NAT comparison using Zakura's production transport configuration.

use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use iroh::{endpoint::Connection, tls::CaTlsConfig, EndpointAddr, RelayMap, RelayMode, SecretKey};
use iroh_relay::{RelayConfig, RelayQuicConfig};
use patchbay::{Device, IpSupport, Lab, Nat};
use serde_json::json;
use tokio::{
    sync::oneshot,
    time::{sleep, timeout},
};
use zakura_network::{
    config::Config,
    zakura::{direct_endpoint_builder, ZakuraLocalLimits},
};

const ALPN: &[u8] = b"zakura/nat-lab/1";
const SETUP: Duration = Duration::from_secs(30);
const OBSERVE: Duration = Duration::from_secs(10);
const TRANSFER: Duration = Duration::from_secs(8);
const PAYLOAD_LEN: usize = 1024 * 1024;

fn main() -> Result<()> {
    // Must happen before Tokio or tracing can start threads. All routers and firewall
    // rules then live in disposable namespaces, never the host network namespace.
    patchbay::init_userns()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let out = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .unwrap_or_else(|| "qa/nat-lab/results".into()),
    );
    std::fs::create_dir_all(&out)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut results = Vec::new();
            for (server, client, udp_blocked) in [
                (false, false, false),
                (false, true, false),
                (true, false, false),
                (true, true, false),
                (true, true, true),
            ] {
                let name = format!("server-{server}-client-{client}-udp-blocked-{udp_blocked}");
                eprintln!("Running {name}");
                let result = timeout(
                    Duration::from_secs(120),
                    run_case(out.join(&name), server, client, udp_blocked),
                )
                .await
                .context("case exceeded 120 seconds")??;
                println!("{result}");
                results.push(result);
                std::fs::write(
                    out.join("summary.json"),
                    serde_json::to_vec_pretty(&results)?,
                )?;
            }
            for enabled in [false, true] {
                eprintln!("Running no-relay-{enabled}");
                let result = timeout(
                    Duration::from_secs(60),
                    without_relay(out.join(format!("no-relay-{enabled}")), enabled),
                )
                .await??;
                println!("{result}");
                results.push(result);
                std::fs::write(
                    out.join("summary.json"),
                    serde_json::to_vec_pretty(&results)?,
                )?;
            }
            Ok(())
        })
}

fn endpoint(
    device: &Device,
    relay_map: RelayMap,
    enabled: bool,
) -> Result<iroh::endpoint::Builder> {
    let mut config = Config {
        network: zakura_chain::parameters::Network::Mainnet,
        ..Config::default()
    };
    config.zakura.nat_traversal = enabled;
    // Only relay connectivity and the isolated relay's test certificate differ
    // from production. Explicit IPv4 binds prevent an IPv6 path bypassing NAT.
    Ok(direct_endpoint_builder(SecretKey::generate())
        .relay_mode(RelayMode::Custom(relay_map))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind_addr(SocketAddr::from((
            device.ip().context("device has IPv4")?,
            0,
        )))?
        .alpns(vec![ALPN.to_vec()])
        .transport_config(ZakuraLocalLimits::from_config(&config).transport_config()))
}

fn selected(conn: &Connection) -> Option<String> {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| p.remote_addr().to_string())
}

fn direct(conn: &Connection) -> bool {
    conn.paths().iter().any(|p| p.is_selected() && p.is_ip())
}

async fn wait_direct(conn: &Connection) -> bool {
    timeout(OBSERVE, async {
        while !direct(conn) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

async fn exchange(conn: &Connection) -> Result<String> {
    timeout(TRANSFER, async {
        let payload = vec![0xa5; PAYLOAD_LEN];
        let expected = blake2b_simd::blake2b(&payload);
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&payload).await?;
        send.finish()?;
        let reply = recv.read_to_end(PAYLOAD_LEN).await?;
        ensure!(reply.len() == PAYLOAD_LEN, "truncated payload");
        ensure!(
            blake2b_simd::blake2b(&reply) == expected,
            "payload hash mismatch"
        );
        Ok(expected.to_hex().to_string())
    })
    .await
    .context("payload exchange timed out")?
}

async fn echo(conn: &Connection) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let data = recv.read_to_end(PAYLOAD_LEN).await?;
    ensure!(data.len() == PAYLOAD_LEN, "truncated request");
    send.write_all(&data).await?;
    send.finish()?;
    Ok(())
}

async fn run_case(
    out: PathBuf,
    server_enabled: bool,
    client_enabled: bool,
    udp_blocked: bool,
) -> Result<serde_json::Value> {
    let (lab, guard) = Lab::for_test(out).await?;
    let dc = lab
        .add_router("dc")
        .ip_support(IpSupport::V4Only)
        .build()
        .await?;
    let relay_device = lab.add_device("relay").uplink(dc.id()).build().await?;
    lab.dns_server()?.set_host(
        "relay.test",
        relay_device.ip().context("relay IPv4")?.into(),
    )?;
    let nat_a = lab
        .add_router("nat-a")
        .nat(Nat::Moderate)
        .ip_support(IpSupport::V4Only)
        .build()
        .await?;
    let nat_b = lab
        .add_router("nat-b")
        .nat(Nat::Moderate)
        .ip_support(IpSupport::V4Only)
        .build()
        .await?;
    let home = lab.add_device("home").uplink(nat_a.id()).build().await?;
    let phone = lab.add_device("phone").uplink(nat_b.id()).build().await?;
    if udp_blocked {
        phone.run_sync(|| {
            // Drop QUIC and QAD, retaining DNS and TCP to the relay.
            let mut command = std::process::Command::new("nft");
            command.args(["-f", "-"]).stdin(std::process::Stdio::piped());
            let mut child = command.spawn()?;
            use std::io::Write;
            child.stdin.take().context("piped nft stdin")?.write_all(b"table inet nat_lab {\n chain output {\n  type filter hook output priority 0; policy accept;\n  udp dport != 53 drop\n }\n}\n")?;
            ensure!(child.wait()?.success(), "install isolated UDP filter");
            Ok(())
        })?;
    }
    let relay_binary = std::env::var_os("ZAKURA_NAT_RELAY")
        .context("set ZAKURA_NAT_RELAY to the absolute path of the relay helper")?;
    let mut command = tokio::process::Command::new(relay_binary);
    command
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut relay_process = relay_device.spawn_command(command)?;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut ready = String::new();
    timeout(
        SETUP,
        BufReader::new(relay_process.stdout.take().context("relay stdout")?).read_line(&mut ready),
    )
    .await??;
    ensure!(ready.trim() == "READY", "relay failed to start: {ready}");
    let relay_map: RelayMap = RelayConfig::new(
        "https://relay.test".parse()?,
        Some(RelayQuicConfig::new(7842)),
    )
    .into();
    let server_map = relay_map.clone();
    let (addr_tx, addr_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let server_task = home.spawn(move |dev| async move {
        let ep = endpoint(&dev, server_map, server_enabled)?.bind().await?;
        timeout(SETUP, ep.online()).await?;
        let addr = ep.addr();
        // No direct socket hints: the initial path must use the lab relay.
        addr_tx
            .send(EndpointAddr::from_parts(
                addr.id,
                addr.addrs.into_iter().filter(|a| a.is_relay()),
            ))
            .map_err(|_| anyhow!("address receiver gone"))?;
        let conn = timeout(SETUP, async {
            ep.accept()
                .await
                .context("incoming connection")?
                .await
                .context("accept handshake")
        })
        .await??;
        let result = timeout(Duration::from_secs(80), async {
            tokio::pin!(finish_rx);
            loop {
                tokio::select! {
                    result = &mut finish_rx => { result?; break; }
                    result = echo(&conn) => { result?; }
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;
        ep.close().await;
        result
    })?;
    let (cut_tx, cut_rx) = oneshot::channel();
    let (cut_done_tx, cut_done_rx) = oneshot::channel();
    let client_task = phone.spawn(move |dev| async move {
        let ep = endpoint(&dev, relay_map, client_enabled)?.bind().await?;
        let addr = timeout(SETUP, addr_rx).await??;
        ensure!(addr.ip_addrs().next().is_none(), "bootstrap must be relay-only");
        let started = Instant::now();
        let conn = timeout(SETUP, ep.connect(addr, ALPN)).await??;
        let connect_ms = started.elapsed().as_millis();
        let initial_path = selected(&conn);
        let hash = exchange(&conn).await.context("transfer before relay cutoff")?;
        let became_direct = wait_direct(&conn).await;
        let path_before_cut = selected(&conn);
        let observed_ms = started.elapsed().as_millis();
        let expected_direct = server_enabled && client_enabled && !udp_blocked;
        ensure!(became_direct == expected_direct, "unexpected direct-path outcome: server={server_enabled} client={client_enabled} blocked={udp_blocked} path={path_before_cut:?}");
        let stats = conn.stats();
        if !server_enabled || !client_enabled {
            ensure!(stats.frame_rx.add_address == 0 && stats.frame_tx.add_address == 0 && stats.frame_rx.reach_out == 0 && stats.frame_tx.reach_out == 0, "disabled peer negotiated traversal");
        }
        cut_tx.send(()).map_err(|_| anyhow!("cut receiver gone"))?;
        timeout(SETUP, cut_done_rx).await??;
        let after_cut = exchange(&conn).await;
        ensure!(after_cut.is_ok() == expected_direct, "unexpected transfer after relay cutoff: {after_cut:?}");
        if expected_direct { ensure!(direct(&conn), "successful cutoff transfer must use IP"); }
        let report = json!({
            "server_nat_traversal": server_enabled, "client_nat_traversal": client_enabled,
            "udp_blocked": udp_blocked, "connect_ms": connect_ms,
            "initial_path": initial_path, "path_before_cut": path_before_cut,
            "direct": became_direct, "observed_ms": observed_ms,
            "payload_bytes_each_direction": PAYLOAD_LEN, "payload_blake2b": hash,
            "post_cut_transfer": after_cut.is_ok(), "post_cut_error": after_cut.err().map(|e| format!("{e:#}")),
            "add_address_rx": stats.frame_rx.add_address, "add_address_tx": stats.frame_tx.add_address,
            "reach_out_rx": stats.frame_rx.reach_out, "reach_out_tx": stats.frame_tx.reach_out,
        });
        let _ = finish_tx.send(());
        ep.close().await;
        Ok::<_, anyhow::Error>(report)
    })?;
    timeout(Duration::from_secs(75), cut_rx).await??;
    relay_process.start_kill()?;
    timeout(SETUP, relay_process.wait()).await??;
    lab.remove_device(relay_device.id())?;
    cut_done_tx
        .send(())
        .map_err(|_| anyhow!("cut acknowledgment receiver gone"))?;
    let (server, client) = tokio::join!(server_task, client_task);
    server??;
    let report = client??;
    guard.ok();
    lab.cleanup();
    Ok(report)
}

async fn without_relay(out: PathBuf, enabled: bool) -> Result<serde_json::Value> {
    let (lab, guard) = Lab::for_test(out).await?;
    let a = lab
        .add_router("nat-a")
        .nat(Nat::Moderate)
        .ip_support(IpSupport::V4Only)
        .build()
        .await?;
    let b = lab
        .add_router("nat-b")
        .nat(Nat::Moderate)
        .ip_support(IpSupport::V4Only)
        .build()
        .await?;
    let home = lab.add_device("home").uplink(a.id()).build().await?;
    let phone = lab.add_device("phone").uplink(b.id()).build().await?;
    let public_ip = a.uplink_ip().context("NAT has WAN address")?;
    let (addr_tx, addr_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let server = home.spawn(move |dev| async move {
        let ep = endpoint(&dev, RelayMap::empty(), enabled)?
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let port = ep
            .bound_sockets()
            .first()
            .context("bound IPv4 socket")?
            .port();
        // Give the dialer the WAN IP and even the local port, but install no
        // port forwarding or NAT mapping. This is deliberately an unreachable hint.
        let addr = EndpointAddr::new(ep.id()).with_ip_addr(SocketAddr::from((public_ip, port)));
        addr_tx
            .send(addr)
            .map_err(|_| anyhow!("address receiver gone"))?;
        let accepted = timeout(SETUP, async {
            tokio::select! {
                _ = ep.accept() => true,
                _ = done_rx => false,
            }
        })
        .await?;
        ep.close().await;
        ensure!(!accepted, "unexpected unsolicited connection through NAT");
        Ok::<_, anyhow::Error>(())
    })?;
    let client = phone.spawn(move |dev| async move {
        let ep = endpoint(&dev, RelayMap::empty(), enabled)?
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let addr = timeout(SETUP, addr_rx).await??;
        let connected = timeout(OBSERVE, ep.connect(addr, ALPN)).await;
        let succeeded = matches!(connected, Ok(Ok(_)));
        let _ = done_tx.send(());
        ep.close().await;
        ensure!(!succeeded, "unexpected connection without rendezvous");
        Ok::<_, anyhow::Error>(())
    })?;
    let (server, client) = tokio::join!(server, client);
    server??;
    client??;
    guard.ok();
    lab.cleanup();
    Ok(
        json!({"relay": false, "server_nat_traversal": enabled, "client_nat_traversal": enabled, "connected": false}),
    )
}
