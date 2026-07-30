// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// multi_program_strings: launch one live Ghidra headless project, import and
// analyze one or more binaries, count defined strings for each active program,
// save the project, and shut down.
//
// Usage:
//   cargo run --example multi_program_strings -- <ghidra_dir> <project_dir> <project_name> <binary> [binary...]

use std::time::Duration;

use libghidra as ghidra;

fn usage(program: &str) {
    eprintln!("Usage: {program} <ghidra_dir> <project_dir> <project_name> <binary> [binary...]");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        usage(&args[0]);
        std::process::exit(1);
    }

    let ghidra_dir = args[1].clone();
    let project_dir = args[2].clone();
    let project_name = args[3].clone();

    let opts = ghidra::HeadlessProjectOptions {
        ghidra_dir,
        project_dir: project_dir.clone(),
        project_name: project_name.clone(),
        port: 0,
        shutdown: "save".to_string(),
        bind_attempts: 5,
        startup_timeout: Duration::from_secs(600),
        read_timeout: Duration::from_secs(300),
        ..Default::default()
    };

    let mut host = match ghidra::launch_headless_project(opts) {
        Ok(host) => host,
        Err(err) => {
            eprintln!("ERROR: {err}");
            std::process::exit(1);
        }
    };

    let mut failed = false;

    for binary in &args[4..] {
        let imported = match host.import_program(&ghidra::ImportProgramRequest {
            source_path: binary.clone(),
            overwrite: true,
            analyze: true,
            ..Default::default()
        }) {
            Ok(imported) => imported,
            Err(err) => {
                eprintln!("ImportProgram failed for {binary}: {err}");
                failed = true;
                break;
            }
        };

        let program_path = imported.primary_program_path;
        if program_path.is_empty() {
            eprintln!("ImportProgram returned no primary program path for {binary}");
            failed = true;
            break;
        }

        println!("imported  {program_path}  source={binary}");

        let opened = match host.open_program(&ghidra::OpenProgramRequest {
            project_path: project_dir.clone(),
            project_name: project_name.clone(),
            program_path: program_path.clone(),
            analyze: false,
            read_only: false,
            ..Default::default()
        }) {
            Ok(opened) => opened,
            Err(err) => {
                eprintln!("OpenProgram failed for {program_path}: {err}");
                failed = true;
                break;
            }
        };

        let strings = match host.list_defined_strings(0, u64::MAX, 0, 0) {
            Ok(strings) => strings,
            Err(err) => {
                eprintln!("ListDefinedStrings failed for {program_path}: {err}");
                failed = true;
                break;
            }
        };

        println!(
            "strings   {program_path}  program={}  count={}",
            opened.program_name,
            strings.strings.len()
        );

        match host.close_program(ghidra::ShutdownPolicy::Save) {
            Ok(closed) if closed.closed => {}
            Ok(_) => {
                eprintln!("CloseProgram did not close {program_path}");
                failed = true;
                break;
            }
            Err(err) => {
                eprintln!("CloseProgram failed for {program_path}: {err}");
                failed = true;
                break;
            }
        }
    }

    let ghidra_exit = host.close(true);
    if failed {
        std::process::exit(1);
    }
    if ghidra_exit != 0 {
        eprintln!("Ghidra exited with code {ghidra_exit}");
        std::process::exit(1);
    }

    println!("saved     project={project_name}");
}
