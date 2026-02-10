use std::collections::BTreeMap;
use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use base64::Engine as _;
use reddsa::frost::redpallas;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use dkg_ceremony::config::{CeremonyConfigV1, Network};
use dkg_ceremony::proto::v1 as pb;
use dkg_ceremony::roster::{RosterOperatorV1, RosterV1};

const JUNOCASH_VERSION: &str = "0.9.8";
const JUNOCASH_RPC_USER: &str = "rpcuser";
const JUNOCASH_RPC_PASS: &str = "rpcpass";

// E2E:
// - Run an online DKG (5-of-3) across real dkg-admin processes.
// - Use the resulting UFVK to scan/regtest-build a TxPlan via juno-scan + juno-txbuild.
// - Use juno-txsign ext-prepare/ext-finalize, producing spend-auth sigs via rerandomized FROST.
// - Broadcast and mine on a Dockerized junocashd regtest node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn e2e_dkg_txbuild_txsign_ext_prepare_finalize() {
    if let Err(e) = e2e_impl().await {
        panic!("{e:#}");
    }
}

async fn e2e_impl() -> anyhow::Result<()> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = repo_root
        .parent()
        .ok_or_else(|| anyhow!("workspace_root_missing"))?
        .to_path_buf();

    let dkg_ceremony_bin = repo_root.join("bin/dkg-ceremony");
    let dkg_admin_repo = workspace_root.join("dkg-admin");
    let dkg_admin_bin = dkg_admin_repo.join("bin/dkg-admin");
    let juno_scan_repo = workspace_root.join("juno-scan");
    let juno_scan_bin = juno_scan_repo.join("bin/juno-scan");
    let juno_txbuild_repo = workspace_root.join("juno-txbuild");
    let juno_txbuild_bin = juno_txbuild_repo.join("bin/juno-txbuild");
    let juno_txsign_repo = workspace_root.join("juno-txsign");
    let juno_txsign_bin = juno_txsign_repo.join("bin/juno-txsign");

    // Ensure required binaries exist.
    run_make_build(&repo_root)?;
    run_make_build(&dkg_admin_repo)?;
    run_make_build(&juno_scan_repo)?;
    run_make_build(&juno_txbuild_repo)?;
    run_make_build(&juno_txsign_repo)?;

    for (name, path) in [
        ("dkg-ceremony", &dkg_ceremony_bin),
        ("dkg-admin", &dkg_admin_bin),
        ("juno-scan", &juno_scan_bin),
        ("juno-txbuild", &juno_txbuild_bin),
        ("juno-txsign", &juno_txsign_bin),
    ] {
        if !path.exists() {
            return Err(anyhow!("{name}_bin_missing: {}", path.display()));
        }
    }

    // Prepare temp workspace.
    let tmp = tempfile::TempDir::new().context("tempdir")?;

    // mTLS material for the ceremony coordinator and operator gRPC servers.
    let (ca_pem, client_cert_pem, client_key_pem, server_cert_pem, server_key_pem) =
        gen_test_mtls_material();

    let ca_path = tmp.path().join("ca.pem");
    let client_cert_path = tmp.path().join("client.pem");
    let client_key_path = tmp.path().join("client.key");
    let server_cert_path = tmp.path().join("server.pem");
    let server_key_path = tmp.path().join("server.key");
    std::fs::write(&ca_path, &ca_pem).context("write ca.pem")?;
    std::fs::write(&client_cert_path, &client_cert_pem).context("write client.pem")?;
    std::fs::write(&client_key_path, &client_key_pem).context("write client.key")?;
    std::fs::write(&server_cert_path, &server_cert_pem).context("write server.pem")?;
    std::fs::write(&server_key_path, &server_key_pem).context("write server.key")?;

    // DKG setup.
    let n: u16 = 5;
    let t: u16 = 3;

    let mut admin_ports = vec![];
    for _ in 0..n {
        admin_ports.push(pick_unused_port()?);
    }

    // Operator IDs must be stable and identifiers are assigned by sorting operator_id ascending.
    let operator_ids = (1u16..=n)
        .map(|i| format!("0x{i:040x}"))
        .collect::<Vec<_>>();

    let roster = RosterV1 {
        roster_version: 1,
        operators: operator_ids
            .iter()
            .enumerate()
            .map(|(i, op_id)| RosterOperatorV1 {
                operator_id: op_id.clone(),
                grpc_endpoint: Some(format!("https://localhost:{}", admin_ports[i])),
                age_recipient: None,
            })
            .collect(),
        coordinator_age_recipient: None,
    };
    let roster_hash_hex = roster.roster_hash_hex().context("roster_hash")?;

    // Start N dkg-admin gRPC servers.
    let mut admins = Vec::with_capacity(n as usize);
    for (i, op_id) in operator_ids.iter().enumerate() {
        let identifier = (i + 1) as u16;
        let listen_addr = format!("127.0.0.1:{}", admin_ports[i]);

        let state_dir = tmp.path().join(format!("op{identifier:02}/state"));
        std::fs::create_dir_all(&state_dir).context("mkdir state_dir")?;

        let admin_cfg_path = tmp.path().join(format!("op{identifier:02}/config.json"));
        std::fs::create_dir_all(admin_cfg_path.parent().unwrap()).context("mkdir op dir")?;

        let admin_cfg = serde_json::json!({
            "config_version": 1,
            "operator_id": op_id,
            "identifier": identifier,
            "threshold": t,
            "max_signers": n,
            "network": "regtest",
            "roster": &roster,
            "roster_hash_hex": &roster_hash_hex,
            "state_dir": state_dir,
            "age_identity_file": null,
            "grpc": {
                "listen_addr": listen_addr,
                "tls_ca_cert_pem_path": &ca_path,
                "tls_server_cert_pem_path": &server_cert_path,
                "tls_server_key_pem_path": &server_key_path,
                "coordinator_client_cert_sha256": null
            }
        });
        write_json_pretty(&admin_cfg_path, &admin_cfg).context("write dkg-admin config")?;

        let log_path = tmp.path().join(format!("op{identifier:02}/dkg-admin.log"));
        let log_file = File::create(&log_path).context("create admin log")?;
        let log_file_err = log_file.try_clone().context("clone admin log")?;

        let mut cmd = Command::new(&dkg_admin_bin);
        cmd.arg("--config").arg(&admin_cfg_path).arg("serve");
        cmd.env("RUST_LOG", "dkg_admin=info");
        cmd.stdout(Stdio::from(log_file));
        cmd.stderr(Stdio::from(log_file_err));

        let child = cmd.spawn().context("spawn dkg-admin")?;
        admins.push(ChildGuard::new(child));
    }

    for (i, p) in admin_ports.iter().enumerate() {
        let identifier = (i + 1) as u16;
        if let Err(e) = wait_for_tcp("127.0.0.1", *p, Duration::from_secs(30)) {
            let log_path = tmp.path().join(format!("op{identifier:02}/dkg-admin.log"));
            let log = std::fs::read_to_string(&log_path).unwrap_or_else(|_| "<log missing>".to_string());
            return Err(anyhow!(
                "wait for dkg-admin tcp failed: identifier={identifier} port={p}: {e:#}\n--- dkg-admin log ---\n{log}"
            ));
        }
    }

    // Run dkg-ceremony coordinator (online).
    let ceremony_cfg = CeremonyConfigV1 {
        config_version: 1,
        threshold: t,
        max_signers: n,
        network: Network::Regtest,
        roster: roster.clone(),
        roster_hash_hex: roster_hash_hex.clone(),
        out_dir: tmp.path().join("out"),
        transcript_dir: tmp.path().join("transcript"),
    };
    let ceremony_cfg_path = tmp.path().join("ceremony_config.json");
    write_json_pretty(&ceremony_cfg_path, &ceremony_cfg).context("write ceremony config")?;

    let mut dkg_ceremony_cmd = Command::new(&dkg_ceremony_bin);
    dkg_ceremony_cmd
        .arg("--config")
        .arg(&ceremony_cfg_path)
        .arg("online")
        .arg("--tls-ca-cert-pem-path")
        .arg(&ca_path)
        .arg("--tls-client-cert-pem-path")
        .arg(&client_cert_path)
        .arg("--tls-client-key-pem-path")
        .arg(&client_key_path)
        .arg("--tls-domain-name-override")
        .arg("localhost")
        .current_dir(&repo_root);
    run_cmd(dkg_ceremony_cmd)
    .context("run dkg-ceremony online")?;

    // Parse public outputs.
    let manifest_path = tmp.path().join("out/KeysetManifest.json");
    let manifest_raw = std::fs::read(&manifest_path).context("read KeysetManifest.json")?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_raw).context("parse KeysetManifest.json")?;

    let ufvk = manifest["ufvk"]
        .as_str()
        .ok_or_else(|| anyhow!("manifest.ufvk_missing"))?
        .to_string();
    let owallet_ua = manifest["owallet_ua"]
        .as_str()
        .ok_or_else(|| anyhow!("manifest.owallet_ua_missing"))?
        .to_string();

    let pkp_b64 = manifest["public_key_package"]
        .as_str()
        .ok_or_else(|| anyhow!("manifest.public_key_package_missing"))?;
    let pkp_bytes = base64::engine::general_purpose::STANDARD
        .decode(pkp_b64)
        .context("base64 decode public_key_package")?;
    let public_key_package =
        redpallas::keys::PublicKeyPackage::deserialize(&pkp_bytes).context("deserialize pkp")?;

    // Start Dockerized junocashd regtest.
    ensure_docker_available()?;
    ensure_junocashd_image(&repo_root)?;

    let container_name = format!(
        "dkg-ceremony-e2e-{}-{}",
        std::process::id(),
        pick_unused_port()?
    );
    let _jd = DockerContainerGuard::start(&container_name).context("start junocashd container")?;

    wait_for_junocashd_rpc(&container_name, Duration::from_secs(60))
        .context("wait for junocashd rpc")?;
    let rpc_host_port = docker_port(&container_name, "8232/tcp").context("docker port")?;
    let rpc_url = format!("http://{rpc_host_port}");

    // Start juno-scan (embedded rocksdb) and register UFVK wallet before funding.
    let scan_port = pick_unused_port()?;
    let scan_listen = format!("127.0.0.1:{scan_port}");
    let scan_url = format!("http://{scan_listen}");

    let db_path = tmp.path().join("scan.db");
    let scan_log_path = tmp.path().join("juno-scan.log");
    let scan_log = File::create(&scan_log_path).context("create scan log")?;
    let scan_log_err = scan_log.try_clone().context("clone scan log")?;

    let mut scan_cmd = Command::new(&juno_scan_bin);
    scan_cmd
        .arg("-listen")
        .arg(&scan_listen)
        .arg("-rpc-url")
        .arg(&rpc_url)
        .arg("-rpc-user")
        .arg(JUNOCASH_RPC_USER)
        .arg("-rpc-pass")
        .arg(JUNOCASH_RPC_PASS)
        .arg("-ua-hrp")
        .arg("jregtest")
        .arg("-confirmations")
        .arg("1")
        .arg("-poll-interval")
        .arg("200ms")
        .arg("-db-driver")
        .arg("rocksdb")
        .arg("-db-path")
        .arg(&db_path)
        .stdout(Stdio::from(scan_log))
        .stderr(Stdio::from(scan_log_err));

    let _scan = ChildGuard::new(scan_cmd.spawn().context("spawn juno-scan")?);
    wait_for_http_ok(&format!("{scan_url}/v1/health"), Duration::from_secs(60))
        .context("wait for juno-scan health")?;

    let wallet_id = format!("dkg-e2e-{}", std::process::id());
    http_post_json(
        &format!("{scan_url}/v1/wallets"),
        &serde_json::json!({ "wallet_id": &wallet_id, "ufvk": &ufvk }),
        Duration::from_secs(15),
    )
    .context("register wallet")?;

    // Fund the UA by shielding coinbase to it.
    // We mine enough blocks for coinbase maturity, then shield and confirm.
    docker_cli(&container_name, &["generate", "101"]).context("generate 101")?;
    let to_addr = owallet_ua;
    let shield_txid = shield_coinbase_to(&container_name, &to_addr).context("shield coinbase")?;
    docker_cli(&container_name, &["generate", "2"]).context("generate confirm")?;

    // Wait until juno-scan reports at least 1 unspent note for this wallet.
    wait_for_scan_note(&scan_url, &wallet_id, Duration::from_secs(120))
        .context("wait for scanned note")?;

    // Destination address (node wallet) for the withdrawal output.
    let node_ua = junocash_get_address_for_account(&container_name, 0)
        .context("z_getaddressforaccount")?;

    // Build a TxPlan via juno-txbuild using juno-scan for notes+witnesses.
    let txplan_path = tmp.path().join("txplan.json");
    let mut txbuild_cmd = Command::new(&juno_txbuild_bin);
    txbuild_cmd
        .arg("send")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--rpc-user")
        .arg(JUNOCASH_RPC_USER)
        .arg("--rpc-pass")
        .arg(JUNOCASH_RPC_PASS)
        .arg("--scan-url")
        .arg(&scan_url)
        .arg("--wallet-id")
        .arg(&wallet_id)
        .arg("--coin-type")
        .arg("8135")
        .arg("--account")
        .arg("0")
        .arg("--to")
        .arg(&node_ua)
        .arg("--amount-zat")
        .arg("1000000")
        .arg("--change-address")
        .arg(&to_addr)
        .arg("--minconf")
        .arg("1")
        .arg("--out")
        .arg(&txplan_path);
    run_cmd(txbuild_cmd)
    .context("juno-txbuild send")?;

    // Prepare the transaction for external signing.
    let prepared_path = tmp.path().join("prepared.json");
    let requests_path = tmp.path().join("requests.json");
    let mut txsign_prepare_cmd = Command::new(&juno_txsign_bin);
    txsign_prepare_cmd
        .arg("ext-prepare")
        .arg("--txplan")
        .arg(&txplan_path)
        .arg("--ufvk")
        .arg(manifest["ufvk"].as_str().unwrap())
        .arg("--out-prepared")
        .arg(&prepared_path)
        .arg("--out-requests")
        .arg(&requests_path);
    run_cmd(txsign_prepare_cmd)
    .context("juno-txsign ext-prepare")?;

    // Read signing requests.
    let reqs_raw = std::fs::read(&requests_path).context("read requests.json")?;
    let reqs_json: serde_json::Value =
        serde_json::from_slice(&reqs_raw).context("parse requests.json")?;
    let reqs = reqs_json["requests"]
        .as_array()
        .ok_or_else(|| anyhow!("requests.requests_missing"))?;
    if reqs.is_empty() {
        return Err(anyhow!("no signing requests"));
    }

    // Coordinator: produce spend-auth sigs using threshold signers (1..=t).
    let ceremony_hash = dkg_ceremony::ceremony_hash::ceremony_hash_hex_v1(
        Network::Regtest,
        t,
        n,
        &roster_hash_hex,
    )
    .context("ceremony_hash")?;

    let signer_ids = (1u16..=t).collect::<Vec<_>>();
    let mut signer_clients = Vec::with_capacity(signer_ids.len());
    for id_u16 in &signer_ids {
        let endpoint = format!("https://localhost:{}", admin_ports[(*id_u16 as usize) - 1]);
        let client = connect_admin(&endpoint, &ca_pem, &client_cert_pem, &client_key_pem)
            .await
            .with_context(|| format!("connect admin {id_u16}"))?;
        signer_clients.push((*id_u16, client));
    }

    let mut sigs_out = vec![];
    for req in reqs {
        let action_index = req["action_index"]
            .as_u64()
            .ok_or_else(|| anyhow!("request.action_index_missing"))? as u32;
        let sighash_hex = req["sighash"]
            .as_str()
            .ok_or_else(|| anyhow!("request.sighash_missing"))?;
        let alpha_hex = req["alpha"]
            .as_str()
            .ok_or_else(|| anyhow!("request.alpha_missing"))?;
        let rk_hex = req["rk"].as_str().ok_or_else(|| anyhow!("request.rk_missing"))?;

        let sighash = hex::decode(sighash_hex).context("decode sighash")?;
        if sighash.len() != 32 {
            return Err(anyhow!("sighash_len_invalid: {}", sighash.len()));
        }
        let alpha = hex::decode(alpha_hex).context("decode alpha")?;
        if alpha.len() != 32 {
            return Err(anyhow!("alpha_len_invalid: {}", alpha.len()));
        }
        let rk = hex::decode(rk_hex).context("decode rk")?;
        if rk.len() != 32 {
            return Err(anyhow!("rk_len_invalid: {}", rk.len()));
        }

        // Round 1 commitments
        let mut commitments = BTreeMap::<u16, Vec<u8>>::new();
        for (id_u16, client) in signer_clients.iter_mut() {
            let resp = client
                .smoke_sign_commit(pb::SmokeSignCommitRequest {
                    ceremony_hash: ceremony_hash.clone(),
                    message: sighash.clone(),
                    alpha: alpha.clone(),
                })
                .await
                .with_context(|| format!("smoke_sign_commit: {id_u16}"))?
                .into_inner();
            commitments.insert(*id_u16, resp.signing_commitments);
        }

        let signing_package_bytes =
            dkg_ceremony::smoke::make_signing_package(commitments, &sighash)
                .map_err(|e| anyhow!(e))?;
        let signing_package = redpallas::SigningPackage::deserialize(&signing_package_bytes)
            .context("deserialize signing package")?;

        // Round 2 shares
        let mut sig_shares = BTreeMap::new();
        for (id_u16, client) in signer_clients.iter_mut() {
            let resp = client
                .smoke_sign_share(pb::SmokeSignShareRequest {
                    ceremony_hash: ceremony_hash.clone(),
                    signing_package: signing_package_bytes.clone(),
                    alpha: alpha.clone(),
                })
                .await
                .with_context(|| format!("smoke_sign_share: {id_u16}"))?
                .into_inner();
            let share = redpallas::round2::SignatureShare::deserialize(&resp.signature_share)
                .context("deserialize sigshare")?;
            let ident: redpallas::Identifier = (*id_u16)
                .try_into()
                .map_err(|_| anyhow!("identifier_invalid: {id_u16}"))?;
            sig_shares.insert(ident, share);
        }

        let randomizer = redpallas::Randomizer::deserialize(&alpha).context("alpha deserialize")?;
        let randomized_params = redpallas::RandomizedParams::from_randomizer(
            public_key_package.verifying_key(),
            randomizer,
        );

        // Verify that juno-txsign's rk matches the derived randomized verifying key.
        let rk_expected = randomized_params
            .randomized_verifying_key()
            .serialize()
            .context("serialize rk")?;
        if rk_expected.as_slice() != rk.as_slice() {
            return Err(anyhow!("rk_mismatch"));
        }

        let sig = redpallas::aggregate(
            &signing_package,
            &sig_shares,
            &public_key_package,
            &randomized_params,
        )
        .context("aggregate")?;

        randomized_params
            .randomized_verifying_key()
            .verify(&sighash, &sig)
            .context("verify")?;

        let sig_bytes = sig.serialize().context("sig serialize")?;
        sigs_out.push(serde_json::json!({
            "action_index": action_index,
            "spend_auth_sig": hex::encode(sig_bytes),
        }));
    }

    let sigs_path = tmp.path().join("sigs.json");
    let sigs_json = serde_json::json!({
        "version": "v0",
        "signatures": sigs_out,
    });
    write_json_pretty(&sigs_path, &sigs_json).context("write sigs.json")?;

    // Finalize the transaction using ext-finalize.
    let mut txsign_finalize_cmd = Command::new(&juno_txsign_bin);
    txsign_finalize_cmd
        .arg("ext-finalize")
        .arg("--prepared-tx")
        .arg(&prepared_path)
        .arg("--sigs")
        .arg(&sigs_path)
        .arg("--json");
    let finalize_out = run_cmd(txsign_finalize_cmd)
    .context("juno-txsign ext-finalize")?;
    let finalize_json: serde_json::Value =
        serde_json::from_slice(finalize_out.as_bytes()).context("parse ext-finalize json")?;
    if finalize_json["status"].as_str() != Some("ok") {
        return Err(anyhow!("ext-finalize status != ok"));
    }
    let raw_tx_hex = finalize_json["data"]["raw_tx_hex"]
        .as_str()
        .ok_or_else(|| anyhow!("ext-finalize missing raw_tx_hex"))?
        .to_string();
    let txid = finalize_json["data"]["txid"]
        .as_str()
        .ok_or_else(|| anyhow!("ext-finalize missing txid"))?
        .to_string();

    // Broadcast and mine.
    let accepted = docker_cli(&container_name, &["sendrawtransaction", &raw_tx_hex])
        .context("sendrawtransaction")?;
    if !strings_eq_nocase(accepted.trim(), txid.trim()) {
        return Err(anyhow!("txid_mismatch: accepted={} want={}", accepted.trim(), txid));
    }
    docker_cli(&container_name, &["generate", "1"]).context("mine 1")?;

    // Verify tx is in the latest block.
    let height: u64 = docker_cli(&container_name, &["getblockcount"])?
        .trim()
        .parse()
        .context("parse height")?;
    let hash = docker_cli(&container_name, &["getblockhash", &height.to_string()])?
        .trim()
        .to_string();
    let blk_raw = docker_cli(&container_name, &["getblock", &hash, "1"])?;
    let blk_json: serde_json::Value =
        serde_json::from_slice(blk_raw.as_bytes()).context("parse getblock")?;
    let txs = blk_json["tx"]
        .as_array()
        .ok_or_else(|| anyhow!("getblock.tx missing"))?;
    let mut found = false;
    for t in txs {
        if let Some(s) = t.as_str() {
            if strings_eq_nocase(s, &txid) {
                found = true;
                break;
            }
        }
    }
    if !found {
        return Err(anyhow!("tx_not_mined"));
    }

    // Avoid "unused" warnings: keep txid around for debugging.
    let _ = shield_txid;

    // Guards drop here, terminating subprocesses and the docker container.
    drop(admins);

    Ok(())
}

fn run_make_build(dir: &Path) -> anyhow::Result<()> {
    let out = Command::new("make")
        .arg("build")
        .current_dir(dir)
        .output()
        .with_context(|| format!("run make build in {}", dir.display()))?;
    if !out.status.success() {
        return Err(anyhow!(
            "make build failed in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn write_json_pretty<P: AsRef<Path>, T: serde::Serialize>(path: P, v: &T) -> anyhow::Result<()> {
    let path = path.as_ref();
    let bytes = serde_json::to_vec_pretty(v).context("json serialize")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn pick_unused_port() -> anyhow::Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").context("bind port 0")?;
    Ok(l.local_addr().context("local_addr")?.port())
}

fn wait_for_tcp(host: &str, port: u16, timeout: Duration) -> anyhow::Result<()> {
    let addr = format!("{host}:{port}");
    let start = Instant::now();
    loop {
        match TcpStream::connect(addr.as_str()) {
            Ok(_) => return Ok(()),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(anyhow!("tcp_timeout: {addr}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn run_cmd(mut cmd: Command) -> anyhow::Result<String> {
    let out = cmd.output().with_context(|| format!("run {:?}", cmd))?;
    if !out.status.success() {
        return Err(anyhow!(
            "command failed: {:?}\nstdout: {}\nstderr: {}",
            cmd,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn ensure_docker_available() -> anyhow::Result<()> {
    let out = Command::new("docker")
        .arg("version")
        .output()
        .context("docker version")?;
    if !out.status.success() {
        return Err(anyhow!("docker_unavailable"));
    }
    Ok(())
}

fn ensure_junocashd_image(repo_root: &Path) -> anyhow::Result<()> {
    let tag = format!("dkg-ceremony-junocashd:{JUNOCASH_VERSION}");
    let inspect = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(&tag)
        .output()
        .context("docker image inspect")?;
    if inspect.status.success() {
        return Ok(());
    }

    let out = Command::new("docker")
        .arg("build")
        .arg("-t")
        .arg(&tag)
        .arg("-f")
        .arg("docker/junocashd/Dockerfile")
        .arg(".")
        .current_dir(repo_root)
        .output()
        .context("docker build")?;
    if !out.status.success() {
        return Err(anyhow!(
            "docker build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

struct DockerContainerGuard {
    name: String,
}

impl DockerContainerGuard {
    fn start(name: &str) -> anyhow::Result<Self> {
        let tag = format!("dkg-ceremony-junocashd:{JUNOCASH_VERSION}");
        let out = Command::new("docker")
            .arg("run")
            .arg("-d")
            .arg("--rm")
            .arg("-p")
            .arg("127.0.0.1::8232")
            .arg("--name")
            .arg(name)
            .arg(tag)
            .arg("-regtest")
            .arg("-server=1")
            .arg("-daemon=0")
            .arg("-listen=0")
            .arg("-txindex=1")
            .arg("-printtoconsole=1")
            .arg("-datadir=/data")
            .arg("-rpcbind=0.0.0.0")
            .arg("-rpcallowip=0.0.0.0/0")
            .arg("-rpcport=8232")
            .arg(format!("-rpcuser={JUNOCASH_RPC_USER}"))
            .arg(format!("-rpcpassword={JUNOCASH_RPC_PASS}"))
            .output()
            .context("docker run")?;
        if !out.status.success() {
            return Err(anyhow!(
                "docker run failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(Self {
            name: name.to_string(),
        })
    }
}

impl Drop for DockerContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .arg("rm")
            .arg("-f")
            .arg(&self.name)
            .output();
    }
}

fn docker_port(container: &str, port_proto: &str) -> anyhow::Result<String> {
    let out = Command::new("docker")
        .arg("port")
        .arg(container)
        .arg(port_proto)
        .output()
        .context("docker port")?;
    if !out.status.success() {
        return Err(anyhow!("docker port failed"));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return Err(anyhow!("docker port empty"));
    }
    Ok(s)
}

fn docker_cli(container: &str, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = Command::new("docker");
    cmd.arg("exec")
        .arg(container)
        .arg("junocash-cli")
        .arg("-regtest")
        .arg("-datadir=/data")
        .arg(format!("-rpcuser={JUNOCASH_RPC_USER}"))
        .arg(format!("-rpcpassword={JUNOCASH_RPC_PASS}"))
        .arg("-rpcport=8232");
    for a in args {
        cmd.arg(a);
    }
    run_cmd(cmd)
}

fn wait_for_junocashd_rpc(container: &str, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        if docker_cli(container, &["getblockcount"]).is_ok() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("junocashd_rpc_timeout"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn junocash_get_address_for_account(container: &str, account: u32) -> anyhow::Result<String> {
    let raw = docker_cli(container, &["z_getaddressforaccount", &account.to_string()])?;
    let v: serde_json::Value = serde_json::from_slice(raw.as_bytes()).context("parse json")?;
    let addr = v["address"]
        .as_str()
        .ok_or_else(|| anyhow!("missing address"))?
        .trim()
        .to_string();
    if addr.is_empty() {
        return Err(anyhow!("empty address"));
    }
    Ok(addr)
}

fn shield_coinbase_to(container: &str, to_addr: &str) -> anyhow::Result<String> {
    let raw = docker_cli(container, &["z_shieldcoinbase", "*", to_addr])?;
    let v: serde_json::Value = serde_json::from_slice(raw.as_bytes()).context("parse json")?;
    let opid = v["opid"]
        .as_str()
        .ok_or_else(|| anyhow!("missing opid"))?
        .trim()
        .to_string();
    if opid.is_empty() {
        return Err(anyhow!("empty opid"));
    }

    let start = Instant::now();
    loop {
        let status_raw = docker_cli(
            container,
            &["z_getoperationstatus", &format!("[\"{opid}\"]")],
        )?;
        let ops: serde_json::Value =
            serde_json::from_slice(status_raw.as_bytes()).context("parse op status")?;
        let arr = ops
            .as_array()
            .ok_or_else(|| anyhow!("op status not array"))?;
        if arr.len() != 1 {
            return Err(anyhow!("unexpected op status len"));
        }
        let st = arr[0]["status"].as_str().unwrap_or("").to_lowercase();
        match st.as_str() {
            "success" => {
                let txid = arr[0]["result"]["txid"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing txid"))?
                    .trim()
                    .to_string();
                if txid.is_empty() {
                    return Err(anyhow!("empty txid"));
                }
                return Ok(txid);
            }
            "failed" => {
                let msg = arr[0]["error"]["message"].as_str().unwrap_or("");
                return Err(anyhow!("shield failed: {msg}"));
            }
            _ => {}
        }
        if start.elapsed() > Duration::from_secs(120) {
            return Err(anyhow!("shield_timeout"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_http_ok(url: &str, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        let out = Command::new("curl")
            .arg("-sS")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg(url)
            .output()
            .context("curl")?;
        if out.status.success() {
            let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if code == "200" {
                return Ok(());
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("http_timeout: {url}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn http_post_json(url: &str, body: &serde_json::Value, timeout: Duration) -> anyhow::Result<()> {
    let payload = serde_json::to_string(body).context("json stringify")?;
    let out = Command::new("curl")
        .arg("-sS")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("content-type: application/json")
        .arg("--max-time")
        .arg(format!("{}", timeout.as_secs()))
        .arg(url)
        .arg("-d")
        .arg(payload)
        .output()
        .context("curl post")?;
    if !out.status.success() {
        return Err(anyhow!(
            "http_post_failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn wait_for_scan_note(scan_url: &str, wallet_id: &str, timeout: Duration) -> anyhow::Result<()> {
    let url = format!("{scan_url}/v1/wallets/{wallet_id}/notes");
    let start = Instant::now();
    loop {
        let out = Command::new("curl")
            .arg("-sS")
            .arg("--max-time")
            .arg("5")
            .arg(&url)
            .output()
            .context("curl notes")?;
        if out.status.success() {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(notes) = v["notes"].as_array() {
                    if !notes.is_empty() {
                        // Ensure required fields exist for txbuild scan mode (position, height).
                        let n0 = &notes[0];
                        if n0["position"].is_number() && n0["height"].is_number() {
                            return Ok(());
                        }
                    }
                }
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("scan_note_timeout"));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

async fn connect_admin(
    endpoint: &str,
    ca_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
) -> anyhow::Result<pb::dkg_admin_client::DkgAdminClient<Channel>> {
    let ca = Certificate::from_pem(ca_pem.to_vec());
    let ident = Identity::from_pem(client_cert_pem.to_vec(), client_key_pem.to_vec());

    let endpoint = Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| anyhow!("endpoint_invalid: {endpoint}: {e}"))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true);

    let tls_cfg = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(ident)
        .domain_name("localhost");

    let channel = endpoint.tls_config(tls_cfg)?.connect().await?;
    Ok(pb::dkg_admin_client::DkgAdminClient::new(channel))
}

fn strings_eq_nocase(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn gen_test_mtls_material() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "junocash-test-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params
        .distinguished_name
        .push(DnType::CommonName, "junocash-test-server");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let mut client_params = CertificateParams::new(vec!["coordinator".to_string()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params
        .distinguished_name
        .push(DnType::CommonName, "junocash-test-client");
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    (
        ca_pem,
        client_cert.pem().into_bytes(),
        client_key.serialize_pem().into_bytes(),
        server_cert.pem().into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
}
