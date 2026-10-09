use super::*;
use neutrino_network::libp2p::identity::Keypair;
use tokio::sync::oneshot;

#[tokio::test]
async fn real_network_worker_return_fails_the_node_lifecycle() {
    let tasks = TaskSupervisor::new();
    let (commands, command_rx) = mpsc::channel(4);
    let (events, _event_rx) = mpsc::channel(4);
    let service = NetworkService::new(Keypair::generate_ed25519(), command_rx, events).unwrap();
    drop(commands);
    let _ = tasks.spawner().spawn_critical("network", async move {
        Box::pin(service.run())
            .await
            .map_err(|error| error.to_string())
    });
    let result =
        supervise_lifecycle(&tasks, core::future::pending(), async { Ok(()) }, || {}).await;
    assert!(matches!(
        result,
        Err(NodeError::CriticalTask {
            task: "network",
            ..
        })
    ));
    tasks.shutdown().await;
}

#[tokio::test]
async fn startup_error_stops_an_already_started_rpc_server() {
    let tasks = TaskSupervisor::new();
    let handle = neutrino_rpc::serve(
        rpc_backend(),
        neutrino_rpc::RpcConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..neutrino_rpc::RpcConfig::default()
        },
    )
    .await
    .unwrap();
    let stop = handle.clone();
    tasks.on_shutdown(move || {
        let _ = stop.stop();
    });
    let result = supervise_lifecycle(
        &tasks,
        core::future::pending(),
        async { Err(NodeError::Engine("startup validation failed".into())) },
        || panic!("failed startup must not mark the node running"),
    )
    .await;
    assert!(matches!(result, Err(NodeError::Engine(_))));
    tasks.shutdown().await;
    tokio::time::timeout(Duration::from_secs(2), handle.stopped())
        .await
        .unwrap();
}

#[tokio::test]
async fn real_rpc_stop_is_an_unexpected_critical_completion() {
    let tasks = TaskSupervisor::new();
    let handle = neutrino_rpc::serve(
        rpc_backend(),
        neutrino_rpc::RpcConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..neutrino_rpc::RpcConfig::default()
        },
    )
    .await
    .unwrap();
    let stopped = handle.clone();
    let _ = tasks.spawner().spawn_critical("rpc", async move {
        stopped.stopped().await;
        Ok(())
    });
    handle.stop().unwrap();
    let result =
        supervise_lifecycle(&tasks, core::future::pending(), async { Ok(()) }, || {}).await;
    assert!(matches!(
        result,
        Err(NodeError::CriticalTask { task: "rpc", .. })
    ));
    tasks.shutdown().await;
}

#[tokio::test]
async fn signal_cancels_pending_startup_successfully() {
    let tasks = TaskSupervisor::new();
    let result = supervise_lifecycle(&tasks, async { Ok(()) }, core::future::pending(), || {
        panic!("cancelled startup must not mark the node running")
    })
    .await;
    assert!(result.is_ok());
    tasks.shutdown().await;
}

#[tokio::test]
async fn signal_after_successful_startup_is_a_successful_stop() {
    let tasks = TaskSupervisor::new();
    let (sender, receiver) = oneshot::channel();
    let mut started = false;
    let result = supervise_lifecycle(
        &tasks,
        async {
            receiver.await.unwrap();
            Ok(())
        },
        async {
            sender.send(()).unwrap();
            Ok(())
        },
        || started = true,
    )
    .await;
    assert!(result.is_ok());
    assert!(started);
    tasks.shutdown().await;
}

#[tokio::test]
async fn completed_failure_is_not_overwritten_by_a_concurrent_signal() {
    let tasks = TaskSupervisor::new();
    let task = tasks
        .spawner()
        .spawn_critical("sync", async { Err("fatal sync error".into()) })
        .unwrap();
    while !task.is_finished() {
        tokio::task::yield_now().await;
    }
    let result = supervise_lifecycle(&tasks, async { Ok(()) }, async { Ok(()) }, || {}).await;
    assert!(matches!(
        result,
        Err(NodeError::CriticalTask { task: "sync", .. })
    ));
    tasks.shutdown().await;
}

fn rpc_backend() -> Arc<dyn RpcBackend> {
    let engine = Engine::genesis(test_spec(), neutrino_storage::MemoryDatabase::new()).unwrap();
    Arc::new(ChainBackend::new(
        engine,
        neutrino_proof_system::MockProofSystem::new(),
    ))
}

fn test_spec() -> ChainSpec {
    use neutrino_primitives::{
        BoundedBytes, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo, RuntimeParams,
        StateParams, Validator, ZERO_HASH,
    };
    let validators = vec![Validator {
        pubkey: *ProposerKey::from_ikm(&[6; 32], 0)
            .unwrap()
            .public_key_bytes(),
        withdrawal_credentials: [7; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }];
    ChainSpec {
        name: BoundedBytes::new(b"lifecycle".to_vec()).unwrap(),
        chain_id: 41,
        genesis_time: 0,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [1; 32],
        genesis_seed: [2; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash: [4; 32],
        genesis_validator_set_root: neutrino_consensus_engine::validator_set::validator_set_root(
            &validators,
        ),
        consensus: ConsensusParams::default(),
        proof: ProofParams::default(),
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

#[test]
fn validators_require_a_key_and_full_nodes_do_not() {
    let error = required_proposer_key(None).unwrap_err();
    assert!(matches!(error, NodeError::ProposerKey(_)));
    assert!(error.to_string().contains("role=full"));
    let config: NodeConfig = toml::from_str("chain_id = 41\nrole = 'full'").unwrap();
    assert!(
        build_block_producer_config(&config, &test_spec())
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn sigint_and_sigterm_stop_the_lifecycle_successfully() {
    const CHILD: &str = "NEUTRINO_LIFECYCLE_SIGNAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(signal_child());
        return;
    }
    for signal in ["INT", "TERM"] {
        run_signal_child(CHILD, signal);
    }
}

#[cfg(unix)]
async fn signal_child() {
    use std::io::Write;
    let tasks = TaskSupervisor::new();
    let _ = tasks
        .spawner()
        .spawn_critical("history", core::future::pending());
    let result = supervise_lifecycle(&tasks, wait_for_shutdown(), async { Ok(()) }, || {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(b"NEUTRINO_SIGNAL_READY\n").unwrap();
        stdout.flush().unwrap();
    })
    .await;
    tasks.shutdown().await;
    assert!(result.is_ok(), "normal termination returned {result:?}");
}

#[cfg(unix)]
fn run_signal_child(environment: &str, signal: &str) {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("runner::lifecycle_tests::sigint_and_sigterm_stop_the_lifecycle_successfully")
        .arg("--nocapture")
        .env(environment, "1")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(output)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("NEUTRINO_SIGNAL_READY") {
                let _ = sender.send(());
            }
        }
    });
    if let Err(error) = receiver.recv_timeout(Duration::from_secs(10)) {
        let _ = child.kill();
        let _ = child.wait();
        reader.join().unwrap();
        panic!("child did not install signal handlers: {error}");
    }
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(child.id().to_string())
        .status()
        .unwrap();
    if !status.success() {
        let _ = child.kill();
        let _ = child.wait();
        reader.join().unwrap();
        panic!("failed to send {signal} to lifecycle child");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            reader.join().unwrap();
            assert!(status.success(), "signal child exited with {status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            reader.join().unwrap();
            panic!("lifecycle did not stop after {signal}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
