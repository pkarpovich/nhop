use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const LABEL: &str = "com.pavel-karpovich.nhop";
const HOME_TOKEN: &str = "{{HOME}}";

fn plist_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("packaging")
        .join(format!("{LABEL}.plist"))
}

fn parsed() -> Option<Value> {
    let file = plist_file();
    let run = Command::new("plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(&file)
        .output();
    let Ok(run) = run else {
        return None;
    };
    assert!(
        run.status.success(),
        "plutil rejected {}: {}",
        file.display(),
        String::from_utf8_lossy(&run.stderr)
    );
    Some(serde_json::from_slice(&run.stdout).unwrap())
}

#[test]
fn the_launch_agent_parses_with_the_label_the_file_is_named_after() {
    let Some(plist) = parsed() else {
        return;
    };
    assert_eq!(plist["Label"], json!(LABEL));
    assert_eq!(plist["RunAtLoad"], json!(true));
    assert_eq!(plist["KeepAlive"], json!(true));
}

#[test]
fn the_launch_agent_starts_the_daemon_and_redirects_into_the_state_directory() {
    let Some(plist) = parsed() else {
        return;
    };
    let arguments = plist["ProgramArguments"].as_array().unwrap();
    assert_eq!(arguments.len(), 2, "{arguments:?}");
    let program = arguments[0].as_str().unwrap();
    assert!(program.starts_with(HOME_TOKEN), "{program}");
    assert!(program.ends_with("/nhop"), "{program}");
    assert_eq!(arguments[1], json!("start"));

    for key in ["StandardOutPath", "StandardErrorPath"] {
        let redirect = plist[key].as_str().unwrap();
        assert!(
            redirect.starts_with(&format!("{HOME_TOKEN}/.local/state/nhop/")),
            "{key} is {redirect}"
        );
        assert!(!redirect.contains("/nhop.log"), "{key} is {redirect}");
    }
}

#[test]
fn the_only_placeholder_the_install_step_substitutes_is_the_home_token() {
    let plist = fs::read_to_string(plist_file()).unwrap();
    let mut placeholders = Vec::new();
    for fragment in plist.split("{{").skip(1) {
        let Some((placeholder, _rest)) = fragment.split_once("}}") else {
            panic!("an unterminated placeholder in {plist}");
        };
        placeholders.push(format!("{{{{{placeholder}}}}}"));
    }
    assert!(!placeholders.is_empty(), "{plist}");
    for placeholder in placeholders {
        assert_eq!(placeholder, HOME_TOKEN, "{plist}");
    }
}
