//! Disposable E0 worker. Only the fixture harness invokes this executable.
use anyhow::{Result, bail, ensure};
use std::{
    io::Write,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{
    WasiCtxBuilder,
    filesystem::FsPerms,
    p1::{self, WasiP1Ctx},
    p2::pipe::MemoryOutputPipe,
};

struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(
        args.len() == 3,
        "expected fixed guest and private snapshot paths"
    );
    let wasm = Path::new(&args[1]);
    let snapshot = Path::new(&args[2]);
    ensure!(
        std::fs::metadata(wasm)?.len() <= 64 * 1024 * 1024,
        "module size limit"
    );
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .max_wasm_stack(512 * 1024);
    let engine = Engine::new(&config)?;
    let compile_started = std::time::Instant::now();
    let module = Module::from_file(&engine, wasm)?;
    eprintln!(
        "module_compile_ms={}",
        compile_started.elapsed().as_millis()
    );
    // Exact core WASIp1 import allowlist, independent of crate feature names.
    const ALLOWED: &[&str] = &[
        "args_get",
        "args_sizes_get",
        "environ_get",
        "environ_sizes_get",
        "clock_time_get",
        "clock_res_get",
        "random_get",
        "proc_exit",
        "sched_yield",
        "fd_advise",
        "fd_allocate",
        "fd_close",
        "fd_datasync",
        "fd_fdstat_get",
        "fd_fdstat_set_flags",
        "fd_filestat_get",
        "fd_filestat_set_size",
        "fd_filestat_set_times",
        "fd_pread",
        "fd_prestat_get",
        "fd_prestat_dir_name",
        "fd_pwrite",
        "fd_read",
        "fd_readdir",
        "fd_renumber",
        "fd_seek",
        "fd_sync",
        "fd_tell",
        "fd_write",
        "path_create_directory",
        "path_filestat_get",
        "path_filestat_set_times",
        "path_link",
        "path_open",
        "path_readlink",
        "path_remove_directory",
        "path_rename",
        "path_symlink",
        "path_unlink_file",
        "poll_oneoff",
    ];
    let mut imports = Vec::new();
    for import in module.imports() {
        if import.module() != "wasi_snapshot_preview1" || !ALLOWED.contains(&import.name()) {
            bail!("disallowed import {}::{}", import.module(), import.name());
        }
        imports.push(import.name().to_owned());
    }
    imports.sort();
    eprintln!("allowed_imports={}", imports.join(","));
    let stdout = MemoryOutputPipe::new(64 * 1024);
    let stderr = MemoryOutputPipe::new(4096);
    let mut builder = WasiCtxBuilder::new();
    builder
        .stdout(stdout.clone())
        .stderr(stderr.clone())
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false)
        .preopened_dir(snapshot, "/snapshot", FsPerms::ReadOnly)?;
    // No inherited environment, stdin, args, directories or socket capabilities.
    let limits = StoreLimitsBuilder::new()
        .memory_size(128 * 1024 * 1024)
        .table_elements(100_000)
        .instances(1)
        .tables(1)
        .memories(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        &engine,
        State {
            wasi: builder.build_p1(),
            limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    store.set_fuel(100_000_000)?;
    store.set_epoch_deadline(1);
    let done = Arc::new(AtomicBool::new(false));
    let timer_done = done.clone();
    let timer = std::thread::spawn(move || {
        for _ in 0..100 {
            if timer_done.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        engine.increment_epoch();
    });
    let result = (|| -> Result<()> {
        let mut linker = Linker::new(store.engine());
        p1::add_to_linker_sync(&mut linker, |state: &mut State| &mut state.wasi)?;
        let instance = linker.instantiate(&mut store, &module)?;
        instance
            .get_typed_func::<(), ()>(&mut store, "_start")?
            .call(&mut store, ())?;
        Ok(())
    })();
    done.store(true, Ordering::Relaxed);
    timer.join().expect("epoch timer");
    std::io::stdout().write_all(&stdout.contents())?;
    std::io::stderr().write_all(&stderr.contents())?;
    result
}
