//! Test-only access to an exact Core checkout obtained from canonical GitHub.

use std::{path::PathBuf, process::Command};

const CANONICAL_CORE_REMOTE: &str =
    "https://github.com/CorniiDog/open-gpu-kernel-modules-steamos-support";

pub(crate) fn required_github_core_repository(required_commit: &str) -> PathBuf {
    github_core_repository(required_commit)
}

fn github_core_repository(required_commit: &str) -> PathBuf {
    let configured = std::env::var_os("OPEMOS_CORE_CONTRACT_ROOT")
        .expect("GitHub-derived Core cache root is required");
    let repository = PathBuf::from(configured);
    assert!(
        repository.is_absolute(),
        "GitHub-derived Core cache root is relative"
    );
    assert!(
        repository.join(".git").exists(),
        "GitHub-derived Core cache is not Git"
    );

    let expected_head = std::env::var("OPEMOS_CORE_EXPECTED_COMMIT")
        .expect("GitHub-derived Core cache requires its exact fetched commit");
    for commit in [&expected_head, required_commit] {
        assert!(
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Core commit identity is invalid"
        );
    }
    let origin = git_output(&repository, &["remote", "get-url", "origin"]);
    assert_eq!(
        origin.trim_end_matches('/'),
        CANONICAL_CORE_REMOTE,
        "Core cache origin is not canonical GitHub"
    );
    let head = git_output(&repository, &["rev-parse", "HEAD"]);
    assert_eq!(
        head, expected_head,
        "Core cache HEAD is not the expected fetched commit"
    );
    let resolved = git_output(
        &repository,
        &[
            "rev-parse",
            "--verify",
            &format!("{required_commit}^{{commit}}"),
        ],
    );
    assert_eq!(
        resolved, required_commit,
        "required immutable Core commit is absent"
    );
    repository
}

fn git_output(repository: &PathBuf, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()
        .expect("inspect GitHub-derived Core cache");
    assert!(
        output.status.success(),
        "GitHub-derived Core cache validation failed"
    );
    String::from_utf8(output.stdout)
        .expect("Core Git output is not UTF-8")
        .trim()
        .to_owned()
}
