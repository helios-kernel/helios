//! Integration tests for `helios-nu`: async IrBlock evaluator, pure `nu-command`
//! operators, Helios-native async commands, streaming external pipelines,
//! zenwave HTTP client, CSPRNG random, CJK values, and AST completion.

use core::time::Duration;

use async_net::TcpListener;
use futures_lite::future::block_on;
use futures_lite::io::{AsyncReadExt as _, AsyncWriteExt as _};
use helios_nu::test_env::TestHeliosEnv;
use helios_nu::{AsyncPipelineData, CompletionKind, GrantSpec, NuError, ShellSession, WatchEvent};
use nu_protocol::Value;

#[test]
fn pure_nu_commands_and_cjk_data_pipelines() {
    block_on(async {
        let mut session = ShellSession::new(TestHeliosEnv::new()).await;

        // Filters, math, strings, conversions, record, hash, url, path, semver, formats, bytes
        let sum = session.eval("[1 2 3 4 5] | math sum").await.unwrap();
        assert_eq!(sum.as_int().unwrap(), 15);

        let filtered = session
            .eval(r#"[{name: "北京", score: 90} {name: "東京", score: 85} {name: "서울", score: 95}] | where score >= 90 | get name | str join ",""#)
            .await
            .unwrap();
        assert_eq!(filtered.as_str().unwrap(), "北京,서울");

        // JSON/TOML/YAML round-trip with CJK (Chinese, Japanese, Korean)
        let json_rt = session
            .eval(r#"{cn: "你好世界", jp: "こんにちは", kr: "안녕하세요"} | to json | from json | get jp"#)
            .await
            .unwrap();
        assert_eq!(json_rt.as_str().unwrap(), "こんにちは");

        let sha = session
            .eval(r#""helios" | hash sha256 | str length"#)
            .await
            .unwrap();
        assert_eq!(sha.as_int().unwrap(), 64);

        let url_host = session
            .eval(r#""https://helios.example:8443/v1/inspect?k=1" | url parse | get host"#)
            .await
            .unwrap();
        assert_eq!(url_host.as_str().unwrap(), "helios.example");

        let path_base = session
            .eval(r#""/etc/helios/rc.nu" | path basename"#)
            .await
            .unwrap();
        assert_eq!(path_base.as_str().unwrap(), "rc.nu");

        let bytes_len = session
            .eval(r#"0x[deadbeef] | bytes length"#)
            .await
            .unwrap();
        assert_eq!(bytes_len.as_int().unwrap(), 4);

        // Custom commands, closures, match, try/catch/finally
        let custom = session
            .eval("def double [x: int] { $x * 2 }; [1 2 3] | each { |n| double $n } | math sum")
            .await
            .unwrap();
        assert_eq!(custom.as_int().unwrap(), 12);

        let caught = session
            .eval(r#"try { error make { msg: "expected-failure" } } catch { |e| $e.msg }"#)
            .await
            .unwrap();
        assert_eq!(caught.as_str().unwrap(), "expected-failure");

        let matched = session
            .eval(r#"match 42 { 0 => "zero", 42 => "answer", _ => "other" }"#)
            .await
            .unwrap();
        assert_eq!(matched.as_str().unwrap(), "answer");
    });
}

#[test]
fn async_external_streaming_grants_and_which() {
    block_on(async {
        let env = TestHeliosEnv::new();
        let mut session = ShellSession::new(env.clone()).await;

        // Streaming pipeline between two external programs (`echo-ext` -> `upper-pipe`)
        let piped = session
            .eval(r#"run-external "echo-ext" "hello" "helios" | run-external "upper-pipe" | str trim"#)
            .await
            .unwrap();
        assert_eq!(piped.as_str().unwrap(), "HELLO HELIOS");

        // Explicit `--grants` and `with-grants` scoping
        let _ = session
            .eval(r#"with-grants ["dir:/etc:ro" {kind: "net", target: "10.0.0.0/8"}] { run-external --grants "virtualize" "echo-ext" "scoped" }"#)
            .await
            .unwrap();

        let recorded = env.recorded_externals();
        let last = recorded.last().unwrap();
        assert_eq!(last.program, "echo-ext");
        assert_eq!(
            last.grants,
            vec![
                GrantSpec {
                    kind: "dir".to_owned(),
                    target: "/etc".to_owned(),
                    mode: Some("ro".to_owned()),
                },
                GrantSpec {
                    kind: "net".to_owned(),
                    target: "10.0.0.0/8".to_owned(),
                    mode: None,
                },
                GrantSpec {
                    kind: "virtualize".to_owned(),
                    target: String::new(),
                    mode: None,
                },
            ]
        );

        // `complete` captures stdout, stderr, exit_code from failing external
        let completed = session
            .eval(r#"run-external "fail-ext" | complete"#)
            .await
            .unwrap();
        let rec = completed.as_record().unwrap();
        assert_eq!(rec.get("stdout").unwrap().as_str().unwrap(), "partial-out");
        assert_eq!(rec.get("stderr").unwrap().as_str().unwrap(), "boom-stderr");
        assert_eq!(rec.get("exit_code").unwrap().as_int().unwrap(), 7);

        // `which` resolves built-ins and externals
        let which_res = session
            .eval(r#"which ls echo-ext | select command type"#)
            .await
            .unwrap();
        let rows = which_res.as_list().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0]
                .as_record()
                .unwrap()
                .get("type")
                .unwrap()
                .as_str()
                .unwrap(),
            "built-in"
        );
        assert_eq!(
            rows[1]
                .as_record()
                .unwrap()
                .get("type")
                .unwrap()
                .as_str()
                .unwrap(),
            "external"
        );
    });
}

#[test]
fn sys_inspect_ps_kill_whoami_sleep_clear_and_scoping() {
    block_on(async {
        let env = TestHeliosEnv::new();
        let mut session = ShellSession::new(env.clone()).await;

        let cpu_count = session.eval("sys cpu --long | length").await.unwrap();
        assert_eq!(cpu_count.as_int().unwrap(), 2);

        let hostname = session.eval("sys host | get hostname").await.unwrap();
        assert_eq!(hostname.as_str().unwrap(), "helios-test");

        let mem_total = session.eval("sys mem | get total").await.unwrap();
        assert_eq!(
            mem_total.as_filesize().unwrap().get(),
            2 * 1024 * 1024 * 1024
        );

        let iface = session.eval("sys net | first | get name").await.unwrap();
        assert_eq!(iface.as_str().unwrap(), "eth0");

        let mount = session.eval("sys disks | first | get mount").await.unwrap();
        assert_eq!(mount.as_str().unwrap(), "/");

        let combined_host = session.eval("sys | get host.name").await.unwrap();
        assert_eq!(combined_host.as_str().unwrap(), "Helios");

        // `inspect`
        let tasks = session
            .eval(r#"inspect "kernel/scheduler" | first | get value"#)
            .await
            .unwrap();
        assert_eq!(tasks.as_int().unwrap(), 7);

        // `ps` + `where`
        let http_pid = session
            .eval(r#"ps --long | where name == "http-client" | first | get pid"#)
            .await
            .unwrap();
        assert_eq!(http_pid.as_int().unwrap(), 2);

        // `kill`
        let _ = session.eval(r#"kill --signal INT 2"#).await.unwrap();
        let kills = env.recorded_kills();
        assert_eq!(kills.len(), 1);
        assert_eq!(kills[0].pid, 2);
        assert_eq!(kills[0].signal.as_deref(), Some("INT"));

        // `whoami`, `sleep`, `clear`
        let who = session.eval("whoami").await.unwrap();
        assert_eq!(who.as_str().unwrap(), "helios-root");

        let _ = session.eval("sleep 25ms").await.unwrap();
        assert_eq!(env.recorded_sleeps(), vec![Duration::from_millis(25)]);

        let _ = session.eval("clear").await.unwrap();
        assert_eq!(env.clear_count(), 1);

        // `with-scope`
        let _ = session
            .eval(r#"with-scope "/plugins/http-client" { run-external "echo-ext" "inside-scope" }"#)
            .await
            .unwrap();
        let (entered, left) = env.recorded_scopes();
        assert_eq!(entered, vec!["/plugins/http-client"]);
        assert_eq!(left, vec!["/plugins/http-client"]);
        assert_eq!(
            env.recorded_externals().last().unwrap().scope.as_deref(),
            Some("/plugins/http-client")
        );

        // `with-snapshot`
        let snap_id = session
            .eval(r#"with-snapshot "pre-upgrade" --moniker "/init" { |snap| $snap.id }"#)
            .await
            .unwrap();
        assert_eq!(snap_id.as_str().unwrap(), "snap-1");
        assert_eq!(env.recorded_snapshots().len(), 1);
        assert_eq!(env.released_snapshots(), vec!["snap-1"]);

        // `with-instruction-profile`
        let prof = session
            .eval(r#"with-instruction-profile --target "kernel/executor" { 21 + 21 }"#)
            .await
            .unwrap();
        let prec = prof.as_record().unwrap();
        assert_eq!(prec.get("result").unwrap().as_int().unwrap(), 42);
        assert_eq!(
            prec.get("target").unwrap().as_str().unwrap(),
            "kernel/executor"
        );
        assert_eq!(prec.get("instructions").unwrap().as_int().unwrap(), 12_345);
    });
}

#[test]
fn vfs_commands_extension_decoding_redirection_and_watch() {
    block_on(async {
        let env = TestHeliosEnv::new();
        env.insert_file(
            "/etc/config.json",
            r#"{"service":"helios","labels":["中文","日本語","한국어"]}"#
                .as_bytes()
                .to_vec(),
        );
        env.insert_file("/etc/app.toml", b"port = 8080\n".to_vec());
        env.insert_file("/etc/.env", b"MODE=production\n".to_vec());

        let mut session = ShellSession::new(env.clone()).await;

        // `cd` and `ls`
        let _ = session.eval("cd /etc").await.unwrap();
        let pwd = session.eval("$env.PWD").await.unwrap();
        assert_eq!(pwd.as_str().unwrap(), "/etc");

        let count_visible = session.eval("ls | length").await.unwrap();
        assert_eq!(count_visible.as_int().unwrap(), 2);
        let count_all = session.eval("ls -a | length").await.unwrap();
        assert_eq!(count_all.as_int().unwrap(), 3);

        // `open` extension-based decoding for `.json`, `.toml`, `.env` and `--raw`
        let label = session
            .eval("open config.json | get labels.2")
            .await
            .unwrap();
        assert_eq!(label.as_str().unwrap(), "한국어");

        let port = session.eval("open app.toml | get port").await.unwrap();
        assert_eq!(port.as_int().unwrap(), 8080);

        let env_mode = session.eval("open .env | get MODE").await.unwrap();
        assert_eq!(env_mode.as_str().unwrap(), "production");

        let raw_json = session.eval("open --raw config.json").await.unwrap();
        assert!(
            raw_json
                .as_str()
                .unwrap()
                .contains("\"service\":\"helios\"")
        );

        // `mkdir`, `save` (with extension encoding), `cp`, `mv`, `touch`, `glob`, `rm`
        let _ = session.eval("mkdir /tmp/work/sub").await.unwrap();
        let _ = session
            .eval(r#"{greeting: "你好"} | save /tmp/work/out.json"#)
            .await
            .unwrap();
        let saved_greeting = session
            .eval("open /tmp/work/out.json | get greeting")
            .await
            .unwrap();
        assert_eq!(saved_greeting.as_str().unwrap(), "你好");

        let _ = session
            .eval("cp /tmp/work/out.json /tmp/work/copy.json")
            .await
            .unwrap();
        let _ = session
            .eval("mv /tmp/work/copy.json /tmp/work/sub/moved.json")
            .await
            .unwrap();
        let _ = session.eval("touch /tmp/work/sub/empty.txt").await.unwrap();

        let globbed = session
            .eval(r#"glob "/tmp/work/**/*.json" | length"#)
            .await
            .unwrap();
        assert_eq!(globbed.as_int().unwrap(), 2);

        // VFS file redirection (`o>` and `o>>`) routed through HeliosEnv
        let _ = session
            .eval(r#""line1\n" o> /tmp/redir.txt; "line2\n" o>> /tmp/redir.txt"#)
            .await
            .unwrap();
        assert_eq!(
            env.read_vfs_bytes("/tmp/redir.txt").as_deref(),
            Some(b"line1\nline2\n".as_slice())
        );

        // `rm -r`
        let _ = session.eval("rm -r /tmp/work").await.unwrap();
        assert!(session.eval("open /tmp/work/out.json").await.is_err());

        // `watch` streams WatchEvents asynchronously into closure
        env.set_watch_events(
            "/etc",
            vec![
                WatchEvent {
                    operation: String::from("Write"),
                    path: String::from("/etc/config.json"),
                    new_path: None,
                },
                WatchEvent {
                    operation: String::from("Create"),
                    path: String::from("/etc/other.txt"),
                    new_path: None,
                },
            ],
        );
        let watched = session
            .eval(r#"watch /etc --glob "*.json" --max-events 1 { |op, path| $"($op):($path)" }"#)
            .await
            .unwrap();
        assert_eq!(
            watched.as_list().unwrap()[0].as_str().unwrap(),
            "Write:/etc/config.json"
        );
    });
}

#[test]
fn random_commands_use_platform_csprng() {
    block_on(async {
        let mut session = ShellSession::new(TestHeliosEnv::new()).await;

        let n = session.eval("random int 10..20").await.unwrap();
        let n = n.as_int().unwrap();
        assert!((10..=20).contains(&n));

        let f = session.eval("random float 1.0..2.0").await.unwrap();
        let f = f.as_float().unwrap();
        assert!((1.0..=2.0).contains(&f));

        let b_true = session.eval("random bool --bias 1.0").await.unwrap();
        assert!(b_true.as_bool().unwrap());

        let b_false = session.eval("random bool --bias 0.0").await.unwrap();
        assert!(!b_false.as_bool().unwrap());

        let chars = session.eval("random chars --length 16").await.unwrap();
        assert_eq!(chars.as_str().unwrap().len(), 16);

        let bin = session.eval("random binary 32").await.unwrap();
        assert_eq!(bin.as_binary().unwrap().len(), 32);

        let uuid_v4 = session.eval("random uuid").await.unwrap();
        assert_eq!(uuid_v4.as_str().unwrap().len(), 36);
        assert_eq!(&uuid_v4.as_str().unwrap()[14..15], "4");

        let uuid_v7 = session.eval("random uuid -v 7").await.unwrap();
        assert_eq!(uuid_v7.as_str().unwrap().len(), 36);
        assert_eq!(&uuid_v7.as_str().unwrap()[14..15], "7");
    });
}

#[test]
fn http_commands_use_real_zenwave_client_over_loopback() {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Serve 7 sequential HTTP exchanges concurrently with the shell session.
        let server = async {
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0_u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("GET");
                let path = parts.next().unwrap_or("/");

                let response = match (method, path) {
                    ("GET", "/json") => {
                        let body = r#"{"ok":true,"lang":"日本語"}"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                    ("POST", "/echo") | ("PUT", "/echo") | ("PATCH", "/echo") => {
                        let body_part = req.split("\r\n\r\n").nth(1).unwrap_or("");
                        let resp_body = format!(r#"{{"method":"{method}","echo":{body_part}}}"#);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp_body.len(),
                            resp_body
                        )
                    }
                    ("DELETE", "/item") => {
                        let body = r#"{"deleted":true}"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                    ("HEAD", "/head") => {
                        "HTTP/1.1 200 OK\r\nX-Helios-Test: yes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned()
                    }
                    ("OPTIONS", "/opts") => {
                        "HTTP/1.1 200 OK\r\nAllow: GET, POST, OPTIONS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned()
                    }
                    _ => {
                        let body = "not found";
                        format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                };
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.flush().await.unwrap();
            }
        };

        let client = async {
            let mut session = ShellSession::new(TestHeliosEnv::new()).await;
            let base = format!("http://{addr}");

            let lang = session
                .eval(&format!("http get {base}/json | get lang"))
                .await
                .unwrap();
            assert_eq!(lang.as_str().unwrap(), "日本語");

            let posted = session
                .eval(&format!(r#"http post {base}/echo {{n: 7}} | get echo.n"#))
                .await
                .unwrap();
            assert_eq!(posted.as_int().unwrap(), 7);

            let put_m = session
                .eval(&format!(r#"http put {base}/echo {{a: 1}} | get method"#))
                .await
                .unwrap();
            assert_eq!(put_m.as_str().unwrap(), "PUT");

            let patch_m = session
                .eval(&format!(r#"http patch {base}/echo {{a: 2}} | get method"#))
                .await
                .unwrap();
            assert_eq!(patch_m.as_str().unwrap(), "PATCH");

            let del = session
                .eval(&format!("http delete {base}/item | get deleted"))
                .await
                .unwrap();
            assert!(del.as_bool().unwrap());

            let head_hdr = session
                .eval(&format!(
                    r#"http head {base}/head | where name == "x-helios-test" | first | get value"#
                ))
                .await
                .unwrap();
            assert_eq!(head_hdr.as_str().unwrap(), "yes");

            let opts_full = session
                .eval(&format!("http options --full {base}/opts | get status"))
                .await
                .unwrap();
            assert_eq!(opts_full.as_int().unwrap(), 200);
        };

        let ((), ()) = futures_lite::future::zip(server, client).await;
    });
}

#[test]
fn ast_completion_core_covers_all_surfaces() {
    block_on(async {
        let env = TestHeliosEnv::new();
        env.insert_file("/etc/rc.nu", b"whoami\n".to_vec());
        env.insert_file("/etc/hosts", b"127.0.0.1 localhost\n".to_vec());
        let session = ShellSession::new(env).await;

        // 1. Command completion (built-ins + externals)
        let cmds = session.complete("with-", 5).await;
        assert!(
            cmds.iter()
                .any(|c| c.value == "with-grants" && c.kind == CompletionKind::Command)
        );
        assert!(
            cmds.iter()
                .any(|c| c.value == "with-scope" && c.kind == CompletionKind::Command)
        );

        // 2. Flag completion from Signature
        let flags = session.complete("http get --", 11).await;
        assert!(
            flags
                .iter()
                .any(|c| c.value == "--headers" && c.kind == CompletionKind::Flag)
        );
        assert!(
            flags
                .iter()
                .any(|c| c.value == "--max-time" && c.kind == CompletionKind::Flag)
        );

        // 3. Downstream pipeline Type::Table column completion
        let ps_cols = session.complete("ps | select ", 12).await;
        assert!(
            ps_cols
                .iter()
                .any(|c| c.value == "moniker" && c.kind == CompletionKind::Column)
        );
        assert!(
            ps_cols
                .iter()
                .any(|c| c.value == "pid" && c.kind == CompletionKind::Column)
        );

        let mem_cols = session.complete("sys mem | get ", 14).await;
        assert!(
            mem_cols
                .iter()
                .any(|c| c.value == "available" && c.kind == CompletionKind::Column)
        );

        // 4. Moniker completion (`with-scope`)
        let monikers = session.complete("with-scope /pl", 14).await;
        assert!(
            monikers
                .iter()
                .any(|c| c.value == "/plugins/http-client" && c.kind == CompletionKind::Moniker)
        );

        // 5. Inspect key completion (`inspect`)
        let keys = session.complete("inspect kernel/", 15).await;
        assert!(
            keys.iter().any(
                |c| c.value == "kernel/scheduler/tasks" && c.kind == CompletionKind::InspectKey
            )
        );

        // 6. Diagnostic target completion (`with-instruction-profile --target`)
        let targets = session
            .complete("with-instruction-profile --target plugins/", 42)
            .await;
        assert!(
            targets.iter().any(
                |c| c.value == "plugins/compiler" && c.kind == CompletionKind::DiagnosticTarget
            )
        );

        // 7. Granted directory entry completion (`open /etc/`)
        let paths = session.complete("open /etc/", 10).await;
        assert!(
            paths
                .iter()
                .any(|c| c.value == "/etc/rc.nu" && c.kind == CompletionKind::Path)
        );
        assert!(
            paths
                .iter()
                .any(|c| c.value == "/etc/hosts" && c.kind == CompletionKind::Path)
        );
    });
}

#[test]
fn parse_and_runtime_errors_surface_typed() {
    block_on(async {
        let mut session = ShellSession::new(TestHeliosEnv::new()).await;

        let parse_err = session.eval("if true { (1 + ").await.unwrap_err();
        assert!(matches!(parse_err, NuError::Parse { .. }));

        let not_found = session.eval("open /does/not/exist.txt").await.unwrap_err();
        assert!(matches!(not_found, NuError::Eval(_)));

        // Direct AsyncPipelineData streaming input into `each`
        let (tx, rx) = async_channel::bounded(4);
        let producer = async move {
            for i in 1..=4_i64 {
                tx.send(Value::test_int(i)).await.unwrap();
            }
        };
        let consumer = session.eval_pipeline(
            "each { |x| $x * 10 } | math sum",
            AsyncPipelineData::list_stream(rx, nu_protocol::Span::test_data(), None),
        );
        let ((), result) = futures_lite::future::zip(producer, consumer).await;
        let val = result
            .unwrap()
            .into_value_async(nu_protocol::Span::test_data())
            .await
            .unwrap();
        assert_eq!(val.as_int().unwrap(), 100);
    });
}

#[test]
fn save_unknown_extension_stderr_redirection_do_env_tilde_and_cancellation() {
    block_on(async {
        let env = TestHeliosEnv::new();
        let mut session = ShellSession::new(env.clone()).await;

        // 1. `save` with unknown extension preserves data instead of dropping it
        let _ = session
            .eval(r#"[1 2 3] | save /tmp/out.unknownext"#)
            .await
            .unwrap();
        let saved = env.read_vfs_bytes("/tmp/out.unknownext").unwrap();
        assert!(
            !saved.is_empty(),
            "save with unknown extension must not lose data"
        );

        // 2. `e>`, `e>>`, `o+e>`, and `o> ... e> ...` stderr/stdout file redirections
        let _ = session
            .eval(r#"run-external "fail-ext" e> /tmp/err.txt | ignore"#)
            .await
            .unwrap();
        assert_eq!(
            env.read_vfs_bytes("/tmp/err.txt").as_deref(),
            Some(b"boom-stderr".as_slice())
        );

        let _ = session
            .eval(r#"run-external "fail-ext" e>> /tmp/err.txt | ignore"#)
            .await
            .unwrap();
        assert_eq!(
            env.read_vfs_bytes("/tmp/err.txt").as_deref(),
            Some(b"boom-stderrboom-stderr".as_slice())
        );

        let _ = session
            .eval(r#"run-external "fail-ext" o+e> /tmp/both.txt"#)
            .await
            .unwrap();
        assert_eq!(
            env.read_vfs_bytes("/tmp/both.txt").as_deref(),
            Some(b"partial-outboom-stderr".as_slice())
        );

        let _ = session
            .eval(r#"run-external "fail-ext" o> /tmp/sep-out.txt e> /tmp/sep-err.txt"#)
            .await
            .unwrap();
        assert_eq!(
            env.read_vfs_bytes("/tmp/sep-out.txt").as_deref(),
            Some(b"partial-out".as_slice())
        );
        assert_eq!(
            env.read_vfs_bytes("/tmp/sep-err.txt").as_deref(),
            Some(b"boom-stderr".as_slice())
        );

        // 3. `do --env` propagates env changes; plain `do` isolates them
        let _ = session
            .eval(r#"do { $env.ISOLATED_VAR = "hidden" }"#)
            .await
            .unwrap();
        let isolated = session.eval("$env.ISOLATED_VAR?").await.unwrap();
        assert!(isolated.is_nothing());

        let _ = session
            .eval(r#"do --env { $env.CAPTURED_VAR = "persisted" }"#)
            .await
            .unwrap();
        let captured = session.eval("$env.CAPTURED_VAR").await.unwrap();
        assert_eq!(captured.as_str().unwrap(), "persisted");

        // 4. `~` expands strictly from `$env.HOME`, never ambient host OS HOME
        env.insert_file("/custom-home/hello.txt", b"vfs-home-ok".to_vec());
        let _ = session.eval(r#"$env.HOME = "/custom-home""#).await.unwrap();
        let tilde_content = session.eval("open ~/hello.txt").await.unwrap();
        assert_eq!(tilde_content.as_str().unwrap(), "vfs-home-ok");

        // 5. Dropping a pending `with-grants` / `with-scope` future mid-await leaks no frames
        {
            let fut = session.eval(
                r#"with-grants "virtualize" { with-scope "/plugins/http-client" { sleep 10ms; "done" } }"#,
            );
            let mut fut = Box::pin(fut);
            let waker = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
                core::task::Poll::Ready(cx.waker().clone())
            }));
            let mut cx = core::task::Context::from_waker(&waker);
            // First poll advances into `sleep` (which yields once), then drop `fut` mid-await.
            let poll = fut.as_mut().poll(&mut cx);
            assert!(poll.is_pending(), "sleep must yield before cancellation");
            drop(fut);
        }
        assert!(
            session.runtime_scope().active_grants().is_empty(),
            "cancelled with-grants must not leak grants onto session"
        );
        assert!(
            session.runtime_scope().current_scope().is_none(),
            "cancelled with-scope must not leak scope onto session"
        );

        // 6. Stderr file redirection drains stdout and stderr concurrently even when
        //    stdout exceeds `STREAM_CHANNEL_CAPACITY` chunks before stderr closes.
        let out_len = session
            .eval(r#"run-external "big-out-then-err" e> /tmp/big-err.txt | str length"#)
            .await
            .unwrap();
        assert_eq!(
            out_len.as_int().unwrap(),
            i64::try_from(helios_nu::STREAM_CHANNEL_CAPACITY * 4 * 4).unwrap()
        );
        assert_eq!(
            env.read_vfs_bytes("/tmp/big-err.txt").as_deref(),
            Some(b"late-stderr".as_slice())
        );

        // 7. Async `par-each` runs closures concurrently without OS threads
        let par = session
            .eval("[1 2 3 4] | par-each { |x| sleep 1ms; $x * 3 } | math sum")
            .await
            .unwrap();
        assert_eq!(par.as_int().unwrap(), 30);

        // 8. Non-zero external exit in a drained statement raises an error catchable by `try`,
        //    and its uncaptured stderr flows directly to inherited stderr (`stderr_log`).
        let failed = session
            .eval(r#"run-external "fail-ext"; "unreachable""#)
            .await;
        assert!(failed.is_err());
        let recovered = session
            .eval(r#"try { run-external "fail-ext"; "no" } catch { "caught" }"#)
            .await
            .unwrap();
        assert_eq!(recovered.as_str().unwrap(), "caught");
        assert_eq!(env.recorded_stderr(), "boom-stderrboom-stderr");

        // 9. Async `print` routes through `HeliosEnv::{write_stdout, write_stderr}`
        let _ = session
            .eval(r#"print "hello"; print -n "world"; print -e "errline""#)
            .await
            .unwrap();
        assert_eq!(env.recorded_stdout(), "hello\nworld");
        assert_eq!(env.recorded_stderr(), "boom-stderrboom-stderrerrline\n");

        // 9b. Non-piped `eval_pipeline` leaves stdout inherited (`capture_stdout = false`)
        //     and streams directly to `stdout_log` rather than buffering.
        let inherited = session
            .eval_pipeline(
                r#"run-external "echo-ext" "direct-stream""#,
                AsyncPipelineData::Empty,
            )
            .await
            .unwrap();
        let exit = inherited.drain_async().await.unwrap();
        assert_eq!(exit, Some(0));
        assert!(env.recorded_stdout().contains("direct-stream\n"));

        // 10. Every committed guest `.nu` script parses and compiles cleanly
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        for rel in [
            "tools/fs-smoke/bootfs/etc/rc.nu",
            "tools/fs-smoke/crash/bootfs/etc/rc.nu",
            "tools/cpu-lifecycle/guest.nu",
        ] {
            let source = std::fs::read_to_string(root.join(rel))
                .unwrap_or_else(|e| panic!("failed to read {rel}: {e}"));
            let (engine_state, _) = helios_nu::create_helios_context();
            let mut working_set = nu_protocol::engine::StateWorkingSet::new(&engine_state);
            let _ = nu_parser::parse(&mut working_set, Some(rel), source.as_bytes(), false);
            assert!(
                working_set.parse_errors.is_empty(),
                "{rel} parse errors: {:?}",
                working_set.parse_errors
            );
            assert!(
                working_set.compile_errors.is_empty(),
                "{rel} compile errors: {:?}",
                working_set.compile_errors
            );
        }
    });
}
