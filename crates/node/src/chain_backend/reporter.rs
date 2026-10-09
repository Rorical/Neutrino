//! Selective evidence retention driven exclusively by finalized runtime state.

use super::{ChainBackend, rpc_queries};
use neutrino_consensus_engine::RetentionPolicy;
use neutrino_default_runtime_core::{
    Address, MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_REPORTER_STATUS, ReporterIdentity,
    ReporterStatus, ReporterStatusRequest,
};
use neutrino_primitives::Hash;
use neutrino_proof_system::ProofSystem;
use neutrino_runtime_abi::QueryRequest;
use neutrino_storage::Database;
use neutrino_trie::Trie;

pub(super) struct ReporterRuntime {
    pub(super) recipient: Address,
    last_finalized: Option<Hash>,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Enable proof-bound rewards and refresh selective retention from finalized
    /// execution state. The configured address needs no local signing key.
    ///
    /// # Errors
    /// Rejects zero addresses and other retention roles. Unavailable execution
    /// state or economic queries retain existing sources until a later refresh.
    pub fn initialize_reporter(&self, recipient: Address) -> Result<(), String> {
        if recipient == [0; 32] {
            return Err("reporter reward address must be nonzero".into());
        }
        if !self.with_engine(|engine| {
            engine
                .retention_info()
                .is_ok_and(|info| info.policy == RetentionPolicy::Reporter)
        }) {
            return Err("reporter requires reporter retention policy".into());
        }
        *self.reporter.lock().expect("reporter runtime") = Some(ReporterRuntime {
            recipient,
            last_finalized: None,
        });
        self.refresh_reporter_tracking();
        Ok(())
    }

    pub(super) fn reporter_recipient(&self) -> Option<Address> {
        self.reporter
            .lock()
            .expect("reporter runtime")
            .as_ref()
            .map(|runtime| runtime.recipient)
    }

    /// Resolve an old receipt's own authenticated program for forensic verdicts.
    /// This does not make old receipts eligible for execution or live BFT.
    pub(super) fn accountability_block_program(&self, height: u64) -> Option<[u32; 8]> {
        self.with_engine(|engine| {
            let chunk = height
                .checked_sub(1)?
                .checked_div(engine.chain_spec().consensus.chunk_size)?;
            if chunk < engine.finalized_next_chunk_id()
                && let Some(record) = engine.store().historical_chunk(chunk).ok().flatten()
            {
                // Finality bound this exact source key in its historical leaf.
                // In particular, a restarted backend's default genesis key
                // cannot replace the key of an already finalized chunk zero.
                return Some(record.block_guest_vk_digest);
            }
            engine
                .programs_for_height(height)
                .ok()
                .map(|programs| programs.execution.block)
        })
    }

    pub(super) fn refresh_reporter_tracking(&self) {
        if let Err(error) = self.update_reporter_tracking() {
            // Failure never implies withdrawal: retaining sources is safe, while
            // deleting on a failed query would lose a slashable identity's proof.
            tracing::warn!(%error, "reporter retains sources until finalized economic query succeeds");
        }
    }

    fn update_reporter_tracking(&self) -> Result<(), String> {
        let Some(last_finalized) = self
            .reporter
            .lock()
            .expect("reporter runtime")
            .as_ref()
            .map(|runtime| runtime.last_finalized)
        else {
            return Ok(());
        };
        let executor = self
            .block_executor_snapshot()
            .ok_or("reporter requires an installed runtime executor")?;
        let snapshot = self.with_engine_mut(|engine| {
            let boundary = engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?;
            if last_finalized == Some(boundary.block_hash) {
                return Ok(None);
            }
            // New authenticated memberships get source ownership before the
            // query runs; failure can only retain extra data, never lose inputs.
            engine
                .seed_reporter_tracking()
                .map_err(|error| error.to_string())?;
            let data = rpc_queries::read_state_data(engine, boundary.state_root)
                .map_err(|error| error.to_string())?;
            let state = Trie::from_persisted(boundary.state_root, data.nodes, data.values);
            // A boundary can activate new programs. Its post-state was written by
            // the runtime executing its final block, before that activation.
            let runtime = engine
                .runtime_code_hash_for(boundary.height)
                .map_err(|error| error.to_string())?;
            let identities = engine
                .reporter_tracked_validators()
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|(pubkey, withdrawal_credentials)| ReporterIdentity {
                    pubkey,
                    withdrawal_credentials,
                })
                .collect::<Vec<_>>();
            Ok::<_, String>(Some((boundary, state, runtime, identities)))
        })?;
        let Some((boundary, state, runtime, identities)) = snapshot else {
            return Ok(());
        };
        let mut eligible = Vec::new();
        for group in identities.chunks(MAX_REPORTER_STATUS_IDENTITIES) {
            let request = QueryRequest {
                method: QUERY_METHOD_REPORTER_STATUS.to_owned(),
                args: borsh::to_vec(&ReporterStatusRequest {
                    identities: group.to_vec(),
                })
                .map_err(|error| error.to_string())?,
            };
            let response = executor.query(&request, runtime, &state)?;
            if !response.is_ok() {
                return Err("reporter status query did not succeed".into());
            }
            let statuses: Vec<ReporterStatus> =
                borsh::from_slice(&response.payload).map_err(|error| error.to_string())?;
            eligible.extend(eligible_identities(group, &statuses)?);
        }
        let mut raw_pool = self.slashing_pool.lock().expect("reporter raw pool");
        self.with_engine_mut(|engine| {
            if engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?
                != boundary
            {
                // Another finalization won the race; its callback will query the
                // new state. Never apply deletion using an older snapshot.
                return Ok(());
            }
            let removed = engine
                .set_reporter_eligible(&eligible)
                .map_err(|error| error.to_string())?;
            raw_pool.evidence.retain(|(key, _)| !removed.contains(key));
            for key in removed {
                raw_pool.seen.remove(&key);
            }
            if let Some(reporter) = self.reporter.lock().expect("reporter runtime").as_mut() {
                reporter.last_finalized = Some(boundary.block_hash);
            }
            Ok(())
        })
    }
}

fn eligible_identities(
    requested: &[ReporterIdentity],
    statuses: &[ReporterStatus],
) -> Result<Vec<(neutrino_primitives::BlsPublicKey, Address)>, String> {
    if requested.len() != statuses.len()
        || requested
            .iter()
            .zip(statuses)
            .any(|(identity, status)| *identity != status.identity)
    {
        return Err("reporter status query changed its identity batch".into());
    }
    Ok(statuses
        .iter()
        .filter(|status| status.pending || (!status.tombstoned && status.slashable_balance != 0))
        .map(|status| {
            (
                status.identity.pubkey,
                status.identity.withdrawal_credentials,
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_consensus_engine::Engine;
    use neutrino_default_runtime_core::{Validator, encode_validator, validator_key};
    use neutrino_proof_system::MockProofSystem;
    use neutrino_runtime_core::host::LiveTrie;
    use neutrino_runtime_host::WasmExecutor;
    use neutrino_storage::{Column, MemoryDatabase};

    fn finalized_genesis_backend() -> ChainBackend<MemoryDatabase, MockProofSystem> {
        let mut spec = super::super::state_sync_tests::spec();
        let mut live = LiveTrie::default();
        live.insert(
            &validator_key(&spec.initial_validators[0].withdrawal_credentials),
            encode_validator(&Validator {
                stake: 123,
                active: true,
            }),
        );
        spec.genesis_state_root = live.state_root();
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
        engine.install_genesis_state(live.trie().clone()).unwrap();
        engine.set_programs(neutrino_consensus_types::history_proof::GuestPrograms {
            execution: neutrino_consensus_types::history_proof::ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
            consensus: neutrino_consensus_types::history_proof::ConsensusPrograms {
                chunk: [4; 8],
                checkpoint: [5; 8],
            },
        });
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
        let backend = ChainBackend::new(engine, MockProofSystem::new());
        backend.set_block_executor(WasmExecutor::default_runtime().unwrap());
        backend
    }

    #[test]
    fn unfinalized_head_cannot_release_reporter_material() {
        let backend = finalized_genesis_backend();
        let header_hash = backend.with_engine_mut(|engine| {
            use neutrino_consensus_engine::{ProposerKey, body::compute_body_roots};
            use neutrino_consensus_types::{Block, Body, Header};
            let signer = ProposerKey::from_ikm(&[6; 32], 0).unwrap();
            let domain = engine.chain_spec().consensus_domain();
            let body = Body::default();
            let roots = compute_body_roots(&body);
            let speculative = Trie::new();
            // A signed, unfinalized header claims a post-state without stake.
            // Import it before restoring that head's trie, preserving the snap
            // installation invariant. The funded genesis remains finalized.
            let mut header = Header {
                height: 1,
                slot: 1,
                parent_hash: engine.head_hash(),
                proposer_index: 0,
                vrf_proof: signer.vrf_eval(domain, &engine.finalized_seed(), 1),
                state_root: speculative.root(),
                transactions_root: roots.transactions_root,
                votes_root: roots.votes_root,
                da_root: roots.da_root,
                runtime_extra: [0; 32],
                receipts_root: [0; 32],
                gas_used: 0,
                gas_limit: engine.chain_spec().genesis_gas_limit,
                timestamp: engine.clock().timestamp_for(1),
                signature: [0; 96],
            };
            header.signature = signer.sign_proposer_message(domain, &header.hash());
            let hash = header.hash();
            engine.import_block(&Block { header, body }).unwrap();
            engine.replace_state_with_reconstructed(speculative);
            assert_eq!(engine.head_height(), 1);
            assert_eq!(engine.finalized_next_chunk_id(), 0);
            assert_eq!(engine.state().root(), engine.head_state_root());
            assert_ne!(
                engine.head_state_root(),
                engine.chain_spec().genesis_state_root
            );
            hash
        });
        backend.initialize_reporter([9; 32]).unwrap();
        let identities =
            backend.with_engine(|engine| engine.store().reporter_tracked_validators().unwrap());
        assert_eq!(identities.len(), 1);
        assert_eq!(backend.reporter_recipient(), Some([9; 32]));
        assert!(
            backend
                .with_engine(|engine| engine.store().reporter_header(&header_hash).unwrap())
                .is_some()
        );
    }

    #[test]
    fn unavailable_finalized_state_preserves_tracking() {
        let backend = finalized_genesis_backend();
        backend.initialize_reporter([9; 32]).unwrap();
        let identities =
            backend.with_engine(|engine| engine.store().reporter_tracked_validators().unwrap());
        backend.with_engine_mut(|engine| {
            let root = engine.chain_spec().genesis_state_root;
            engine
                .store_mut()
                .db_mut()
                .delete(Column::TrieNodes, &root)
                .unwrap();
        });
        backend.initialize_reporter([9; 32]).unwrap();
        assert_eq!(
            backend.with_engine(|engine| { engine.store().reporter_tracked_validators().unwrap() }),
            identities
        );
    }

    #[test]
    fn pending_rewards_keep_identity_after_tombstone_until_execution() {
        let identity = ReporterIdentity {
            pubkey: [3; 48],
            withdrawal_credentials: [4; 32],
        };
        let pending = ReporterStatus {
            identity,
            slashable_balance: 0,
            tombstoned: true,
            pending: true,
        };
        assert_eq!(
            eligible_identities(&[identity], &[pending]).unwrap(),
            vec![(identity.pubkey, identity.withdrawal_credentials)]
        );
        let executed = ReporterStatus {
            pending: false,
            ..pending
        };
        assert_eq!(
            eligible_identities(&[identity], &[executed]).unwrap(),
            [] as [([u8; 48], [u8; 32]); 0]
        );
    }

    #[test]
    fn actual_withdrawal_controls_retention_and_query_order_is_authenticated() {
        let identity = ReporterIdentity {
            pubkey: [5; 48],
            withdrawal_credentials: [6; 32],
        };
        let bonded = ReporterStatus {
            identity,
            slashable_balance: 7,
            tombstoned: false,
            pending: false,
        };
        assert_eq!(
            eligible_identities(&[identity], &[bonded]).unwrap().len(),
            1
        );
        let withdrawn = ReporterStatus {
            slashable_balance: 0,
            ..bonded
        };
        assert_eq!(
            eligible_identities(&[identity], &[withdrawn]).unwrap(),
            [] as [([u8; 48], [u8; 32]); 0]
        );
        let other = ReporterIdentity {
            pubkey: [8; 48],
            ..identity
        };
        assert!(eligible_identities(&[other], &[bonded]).is_err());
        assert!(eligible_identities(&[identity], &[]).is_err());
    }
}
