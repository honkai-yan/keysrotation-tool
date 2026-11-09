use base64::{Engine, engine::general_purpose::STANDARD};
use keyrotation_protocol::*;
use keyrotation_server::{dispatcher, http, store::Repository, worker::DbWorker};
use keyrotation_transport::{Client, Endpoint, Identity, TransportError};
use std::sync::Arc;

fn encryption(seed: u8) -> EncryptionMeta {
    EncryptionMeta {
        content_format: 1,
        kdf: KdfParams::default(),
        salt: STANDARD.encode([seed; 16]),
        verifier: STANDARD.encode([seed; 39]),
    }
}
fn write(meta: &VaultMeta) -> WriteContext {
    WriteContext {
        operation_id: random_id(),
        generation: meta.generation.clone(),
        key_epoch: meta.key_epoch,
        valid_until: keyrotation_server::now() + OPERATION_TTL,
    }
}
fn call(client: &mut Client, token: &str, command: Command) -> ResponseBody {
    client
        .call(&RpcRequest::new(command, Some(token.into())))
        .unwrap()
}

fn contract(mut client: Client, mut other: Client) {
    assert!(matches!(
        client.call(&RpcRequest::new(Command::VaultMeta, None)),
        Err(TransportError::Remote(ApiError {
            code: ErrorCode::Unauthenticated,
            ..
        }))
    ));
    let ResponseBody::ServerInfo(info) = client
        .call(&RpcRequest::new(Command::ServerInfo, None))
        .unwrap()
    else {
        panic!("info")
    };
    assert!(!info.initialized);
    let ResponseBody::Session(session) = client
        .call(&RpcRequest::new(
            Command::AuthLogin {
                username: "admin".into(),
                password: "synthetic-password".into(),
            },
            None,
        ))
        .unwrap()
    else {
        panic!("session")
    };
    let token = session.token.unwrap();
    let ResponseBody::Session(other_session) = other
        .call(&RpcRequest::new(
            Command::AuthLogin {
                username: "admin".into(),
                password: "synthetic-password".into(),
            },
            None,
        ))
        .unwrap()
    else {
        panic!("other session")
    };
    let other_token = other_session.token.unwrap();
    let initial = WriteContext {
        operation_id: random_id(),
        generation: info.generation,
        key_epoch: 0,
        valid_until: info.server_time + OPERATION_TTL,
    };
    let ResponseBody::VaultMeta(mut meta) = call(
        &mut client,
        &token,
        Command::VaultInitialize {
            write: initial,
            encryption: encryption(1),
        },
    ) else {
        panic!("meta")
    };
    let create = Command::EntriesCreate {
        write: write(&meta),
        description: "原始描述".into(),
        content: STANDARD.encode([1; 28]),
    };
    let created = call(&mut client, &token, create.clone());
    assert_eq!(created, call(&mut client, &token, create.clone()));
    let ResponseBody::Entry(created) = created else {
        panic!("entry")
    };
    let id = created.entry.id;
    call(
        &mut client,
        &token,
        Command::EntriesUpdate {
            write: write(&meta),
            id,
            description: Some("先提交".into()),
            content: None,
        },
    );
    call(
        &mut other,
        &other_token,
        Command::EntriesUpdate {
            write: write(&meta),
            id,
            description: Some("后提交覆盖".into()),
            content: None,
        },
    );
    call(
        &mut client,
        &token,
        Command::EntriesUpdate {
            write: write(&meta),
            id,
            description: None,
            content: Some(STANDARD.encode([2; 28])),
        },
    );
    let ResponseBody::Entries(page) = call(
        &mut client,
        &token,
        Command::EntriesList {
            generation: meta.generation.clone(),
            expected_revision: None,
            after_id: None,
            limit: 100,
        },
    ) else {
        panic!("list")
    };
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].description, "后提交覆盖");
    assert!(matches!(
        client.call(&RpcRequest::new(
            Command::EntriesReadContent {
                generation: meta.generation.clone(),
                id,
                expected_revision: 1
            },
            Some(token.clone())
        )),
        Err(TransportError::Remote(ApiError {
            code: ErrorCode::RevisionChanged,
            ..
        }))
    ));
    let ResponseBody::Content(content) = call(
        &mut client,
        &token,
        Command::EntriesReadContent {
            generation: meta.generation.clone(),
            id,
            expected_revision: page.entries[0].revision,
        },
    ) else {
        panic!("content")
    };
    assert_eq!(content.content, STANDARD.encode([2; 28]));
    let ResponseBody::VaultMeta(current) = call(&mut client, &token, Command::VaultMeta) else {
        panic!("meta")
    };
    meta = current;
    let ResponseBody::Rotation(job) = call(
        &mut client,
        &token,
        Command::RotationBegin {
            write: write(&meta),
            expected_vault_revision: meta.vault_revision,
            new_encryption: encryption(3),
        },
    ) else {
        panic!("rotation")
    };
    call(
        &mut client,
        &token,
        Command::RotationStage {
            write: write(&meta),
            job_id: job.job_id.clone(),
            entries: vec![RotatedEntry {
                id,
                content: STANDARD.encode([3; 28]),
            }],
        },
    );
    let commit = Command::RotationCommit {
        write: write(&meta),
        job_id: job.job_id,
    };
    let result = call(&mut client, &token, commit.clone());
    assert_eq!(result, call(&mut client, &token, commit));
    let ResponseBody::Rotation(result) = result else {
        panic!("commit")
    };
    assert_eq!(result.committed_meta.as_ref().unwrap().key_epoch, 2);
    assert!(matches!(
        client.call(&RpcRequest::new(
            Command::EntriesUpdate {
                write: write(&meta),
                id,
                description: Some("old key".into()),
                content: None
            },
            Some(token.clone())
        )),
        Err(TransportError::Remote(ApiError {
            code: ErrorCode::KeyEpochChanged,
            ..
        }))
    ));
    call(&mut client, &token, Command::AuthLogout);
    assert!(matches!(
        call(&mut other, &other_token, Command::AuthValidate),
        ResponseBody::Session(_)
    ));
    assert!(matches!(
        client.call(&RpcRequest::new(Command::VaultMeta, Some(token))),
        Err(TransportError::Remote(ApiError {
            code: ErrorCode::Unauthenticated,
            ..
        }))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_business_contract_over_real_noise_http_and_verified_https() {
    for https in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        Repository::create(directory.path(), "admin", "synthetic-password").unwrap();
        let worker = DbWorker::open(directory.path()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = Endpoint::parse(&format!(
            "{}://127.0.0.1:{}/keys/",
            if https { "https" } else { "http" },
            address.port()
        ))
        .unwrap();
        let identity = Arc::new(Identity::generate().unwrap());
        let public = identity.public_base64();
        let app = http::router(
            endpoint.clone(),
            if https { None } else { Some(identity) },
            dispatcher(worker),
        )
        .unwrap();
        let handle = axum_server::Handle::new();
        let shutdown = handle.clone();
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let pem = certificate.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pem.clone().into_bytes(),
            certificate.signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let server = tokio::spawn(async move {
            if https {
                axum_server::from_tcp_rustls(listener, tls)
                    .unwrap()
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
                    .unwrap();
            } else {
                axum_server::from_tcp(listener)
                    .unwrap()
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
                    .unwrap();
            }
        });
        shutdown.listening().await.unwrap();
        tokio::task::spawn_blocking(move || {
            if https {
                let mut untrusted = Client::new(endpoint.clone(), None, None).unwrap();
                assert!(
                    untrusted
                        .call(&RpcRequest::new(Command::ServerInfo, None))
                        .is_err()
                );
            } else {
                let wrong = Identity::generate().unwrap().public_base64();
                let mut untrusted = Client::new(endpoint.clone(), Some(&wrong), None).unwrap();
                assert!(
                    untrusted
                        .call(&RpcRequest::new(Command::ServerInfo, None))
                        .is_err()
                );
            }
            let client = Client::new(
                endpoint.clone(),
                if https { None } else { Some(public.as_str()) },
                if https { Some(pem.as_str()) } else { None },
            )
            .unwrap();
            let other = Client::new(
                endpoint,
                if https { None } else { Some(public.as_str()) },
                if https { Some(pem.as_str()) } else { None },
            )
            .unwrap();
            contract(client, other);
        })
        .await
        .unwrap();
        shutdown.shutdown();
        server.await.unwrap();
    }
}

#[test]
fn committed_operations_survive_restart_and_expired_results_never_execute_again() {
    let directory = tempfile::tempdir().unwrap();
    let mut repo = Repository::create(directory.path(), "admin", "synthetic-password").unwrap();
    let time = 1000;
    let login = RpcRequest::new(
        Command::AuthLogin {
            username: "admin".into(),
            password: "synthetic-password".into(),
        },
        None,
    );
    let ResponseBody::Session(session) = repo.dispatch(&login, time).outcome.into_result().unwrap()
    else {
        panic!("login")
    };
    let token = session.token;
    let context = WriteContext {
        operation_id: random_id(),
        generation: repo.generation().unwrap(),
        key_epoch: 0,
        valid_until: time + OPERATION_TTL,
    };
    let initialize = RpcRequest::new(
        Command::VaultInitialize {
            write: context,
            encryption: encryption(1),
        },
        token.clone(),
    );
    let first = repo.dispatch(&initialize, time);
    assert!(first.outcome.clone().into_result().is_ok());
    drop(repo);
    let mut repo = Repository::open(directory.path()).unwrap();
    assert_eq!(first, repo.dispatch(&initialize, time + 1));
    let write = initialize.command.write().unwrap();
    let query = RpcRequest::new(
        Command::OperationsGet {
            generation: write.generation.clone(),
            operation_id: write.operation_id.clone(),
        },
        token.clone(),
    );
    let ResponseBody::Operation(record) = repo
        .dispatch(&query, time + 1)
        .outcome
        .into_result()
        .unwrap()
    else {
        panic!("operation result")
    };
    assert_eq!(record.state, OperationState::Committed);
    assert_eq!(*record.outcome.unwrap(), first.outcome);
    let mut changed = initialize.clone();
    if let Command::VaultInitialize { encryption, .. } = &mut changed.command {
        *encryption = super_encryption();
    }
    assert_eq!(
        repo.dispatch(&changed, time + 2)
            .outcome
            .into_result()
            .unwrap_err()
            .code,
        ErrorCode::OperationMismatch
    );
    let expired = repo.dispatch(
        &RpcRequest::new(Command::AuthValidate, token.clone()),
        time + SESSION_TTL,
    );
    assert_eq!(
        expired.outcome.into_result().unwrap_err().code,
        ErrorCode::SessionExpired
    );
    let ResponseBody::Session(session) = repo
        .dispatch(&login, time + OPERATION_TTL + 1)
        .outcome
        .into_result()
        .unwrap()
    else {
        panic!("login")
    };
    let mut retry = initialize;
    retry.session_token = session.token;
    assert_eq!(
        repo.dispatch(&retry, time + OPERATION_TTL + 1)
            .outcome
            .into_result()
            .unwrap_err()
            .code,
        ErrorCode::OperationExpired
    );
    assert_eq!(repo.meta().unwrap().key_epoch, 1);
}
fn super_encryption() -> EncryptionMeta {
    encryption(2)
}

#[test]
fn rotation_is_atomic_rejects_partial_batches_and_conflicts_and_handles_empty_vaults() {
    fn run(repo: &mut Repository, token: &str, command: Command) -> ApiResult<ResponseBody> {
        repo.dispatch(
            &RpcRequest::new(command, Some(token.into())),
            keyrotation_server::now(),
        )
        .outcome
        .into_result()
    }
    let directory = tempfile::tempdir().unwrap();
    let mut repo = Repository::create(directory.path(), "admin", "synthetic-password").unwrap();
    let response = repo
        .dispatch(
            &RpcRequest::new(
                Command::AuthLogin {
                    username: "admin".into(),
                    password: "synthetic-password".into(),
                },
                None,
            ),
            keyrotation_server::now(),
        )
        .outcome
        .into_result()
        .unwrap();
    let ResponseBody::Session(session) = response else {
        panic!("session")
    };
    let token = session.token.unwrap();
    let initial = WriteContext {
        operation_id: random_id(),
        generation: repo.generation().unwrap(),
        key_epoch: 0,
        valid_until: keyrotation_server::now() + OPERATION_TTL,
    };
    let ResponseBody::VaultMeta(mut meta) = run(
        &mut repo,
        &token,
        Command::VaultInitialize {
            write: initial,
            encryption: encryption(1),
        },
    )
    .unwrap() else {
        panic!("meta")
    };
    let mut ids = Vec::new();
    for i in 0..2 {
        let ResponseBody::Entry(entry) = run(
            &mut repo,
            &token,
            Command::EntriesCreate {
                write: write(&meta),
                description: format!("entry{i}"),
                content: STANDARD.encode([1; 28]),
            },
        )
        .unwrap() else {
            panic!("entry")
        };
        ids.push(entry.entry.id);
    }
    meta = repo.meta().unwrap();
    let ResponseBody::Rotation(job) = run(
        &mut repo,
        &token,
        Command::RotationBegin {
            write: write(&meta),
            expected_vault_revision: meta.vault_revision,
            new_encryption: encryption(2),
        },
    )
    .unwrap() else {
        panic!("rotation")
    };
    let invalid = run(
        &mut repo,
        &token,
        Command::RotationStage {
            write: write(&meta),
            job_id: job.job_id.clone(),
            entries: vec![
                RotatedEntry {
                    id: ids[0],
                    content: STANDARD.encode([2; 28]),
                },
                RotatedEntry {
                    id: 9999,
                    content: STANDARD.encode([2; 28]),
                },
            ],
        },
    );
    assert!(invalid.is_err());
    let ResponseBody::Rotation(status) = run(
        &mut repo,
        &token,
        Command::RotationStatus {
            generation: meta.generation.clone(),
            job_id: job.job_id.clone(),
        },
    )
    .unwrap() else {
        panic!("status")
    };
    assert_eq!(status.staged_entries, 0);
    assert_eq!(
        run(
            &mut repo,
            &token,
            Command::RotationCommit {
                write: write(&meta),
                job_id: job.job_id.clone()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::RotationIncomplete
    );
    run(
        &mut repo,
        &token,
        Command::RotationStage {
            write: write(&meta),
            job_id: job.job_id.clone(),
            entries: ids
                .iter()
                .map(|id| RotatedEntry {
                    id: *id,
                    content: STANDARD.encode([2; 28]),
                })
                .collect(),
        },
    )
    .unwrap();
    let ResponseBody::Content(content) = run(
        &mut repo,
        &token,
        Command::EntriesReadContent {
            generation: meta.generation.clone(),
            id: ids[0],
            expected_revision: 1,
        },
    )
    .unwrap() else {
        panic!("content")
    };
    assert_eq!(content.content, STANDARD.encode([1; 28]));
    assert_eq!(repo.meta().unwrap().key_epoch, 1);
    run(
        &mut repo,
        &token,
        Command::EntriesUpdate {
            write: write(&meta),
            id: ids[0],
            description: Some("concurrent write".into()),
            content: None,
        },
    )
    .unwrap();
    assert_eq!(
        run(
            &mut repo,
            &token,
            Command::RotationCommit {
                write: write(&meta),
                job_id: job.job_id
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::RotationConflict
    );
    assert_eq!(repo.meta().unwrap().key_epoch, 1);
    meta = repo.meta().unwrap();
    let ResponseBody::Rotation(job) = run(
        &mut repo,
        &token,
        Command::RotationBegin {
            write: write(&meta),
            expected_vault_revision: meta.vault_revision,
            new_encryption: encryption(2),
        },
    )
    .unwrap() else {
        panic!("rotation")
    };
    run(
        &mut repo,
        &token,
        Command::RotationStage {
            write: write(&meta),
            job_id: job.job_id.clone(),
            entries: ids
                .iter()
                .map(|id| RotatedEntry {
                    id: *id,
                    content: STANDARD.encode([2; 28]),
                })
                .collect(),
        },
    )
    .unwrap();
    let commit = Command::RotationCommit {
        write: write(&meta),
        job_id: job.job_id,
    };
    let confirmed = run(&mut repo, &token, commit.clone()).unwrap();
    assert_eq!(run(&mut repo, &token, commit).unwrap(), confirmed);
    meta = repo.meta().unwrap();
    assert_eq!(meta.key_epoch, 2);
    for id in ids {
        let entry = repo.entry(id).unwrap();
        let ResponseBody::Content(content) = run(
            &mut repo,
            &token,
            Command::EntriesReadContent {
                generation: meta.generation.clone(),
                id,
                expected_revision: entry.revision,
            },
        )
        .unwrap() else {
            panic!("content")
        };
        assert_eq!(content.content, STANDARD.encode([2; 28]));
        run(
            &mut repo,
            &token,
            Command::EntriesDelete {
                write: write(&meta),
                id,
            },
        )
        .unwrap();
    }
    meta = repo.meta().unwrap();
    let ResponseBody::Rotation(empty) = run(
        &mut repo,
        &token,
        Command::RotationBegin {
            write: write(&meta),
            expected_vault_revision: meta.vault_revision,
            new_encryption: encryption(3),
        },
    )
    .unwrap() else {
        panic!("empty rotation")
    };
    assert_eq!(empty.total_entries, 0);
    run(
        &mut repo,
        &token,
        Command::RotationCommit {
            write: write(&meta),
            job_id: empty.job_id,
        },
    )
    .unwrap();
    assert_eq!(repo.meta().unwrap().key_epoch, 3);
}
