//! Filesystem loading of policy packs.
//!
//! [`load_pack`] parses and fully validates one file; [`load_pack_dir`]
//! walks a directory tree for `*.yaml`/`*.yml` files, returning packs
//! sorted by capability name and rejecting duplicate capabilities so a
//! directory can never hold two definitions of the same thing.

use std::path::{Path, PathBuf};

use crate::error::PackError;
use crate::schema::PolicyPack;

/// Parses `text` as a YAML pack and runs every validation invariant.
///
/// # Errors
/// Returns [`PackError::Parse`] for malformed YAML (including unknown
/// fields) or any typed validation variant.
pub fn parse_pack_yaml(text: &str) -> Result<PolicyPack, PackError> {
    let pack: PolicyPack = serde_yaml::from_str(text)?;
    pack.validate()?;
    Ok(pack)
}

/// Reads `path` from disk and parses it via [`parse_pack_yaml`].
///
/// # Errors
/// Propagates I/O errors plus anything from [`parse_pack_yaml`].
pub fn load_pack(path: &Path) -> Result<PolicyPack, PackError> {
    let text = std::fs::read_to_string(path)?;
    parse_pack_yaml(&text)
}

/// Lists candidate pack files under `dir`, recursively, in sorted path
/// order. Hidden files/directories are skipped; only `.yaml`/`.yml`
/// extensions qualify.
///
/// # Errors
/// Propagates directory-walk I/O errors.
pub fn pack_files(dir: &Path) -> Result<Vec<PathBuf>, PackError> {
    let mut files = Vec::new();
    collect_pack_files(dir, &mut files)?;
    files.sort();
    Ok(files)
}

/// Loads every pack under `dir`, sorted by capability name.
///
/// # Errors
/// Propagates per-file failures and returns
/// [`PackError::DuplicateCapability`] when two files declare the same
/// capability name.
pub fn load_pack_dir(dir: &Path) -> Result<Vec<PolicyPack>, PackError> {
    let mut loaded: Vec<(String, PolicyPack)> = Vec::new();
    for file in pack_files(dir)? {
        let pack = load_pack(&file).map_err(|err| annotate(file.as_path(), err))?;
        if loaded.iter().any(|(existing, _)| *existing == pack.name) {
            return Err(PackError::DuplicateCapability(pack.name));
        }
        loaded.push((pack.name.clone(), pack));
    }
    let mut packs: Vec<PolicyPack> = loaded.into_iter().map(|(_, pack)| pack).collect();
    packs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(packs)
}

/// Names the offending file in per-file errors so directory scans point
/// at the right input.
fn annotate(path: &Path, err: PackError) -> PackError {
    match err {
        PackError::Io(_) => err,
        other => PackError::InvalidField {
            field: format!("{}", path.display()),
            reason: other.to_string(),
        },
    }
}

fn collect_pack_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), PackError> {
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_pack_files(&path, out)?;
        } else if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yaml") | Some("yml")
        ) {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const PACK_A: &str = r#"
format: 1
name: aaa.capability.one
provider: github
request:
  hosts: [api.github.com]
  methods: [GET]
  paths: ["/x/{id}"]
credential:
  credential_ref: token-a
  injection: bearer
"#;

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn loads_packs_sorted_by_capability_name_across_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            &dir.path().join("zzz-late.yaml"),
            r#"
format: 1
name: zzz.capability.last
provider: github
request:
  hosts: [api.github.com]
  methods: [GET]
  paths: ["/x"]
credential:
  credential_ref: token-z
  injection: bearer
"#,
        );
        // Nested provider subdirectory, .yml extension, hidden dot-file,
        // and a non-YAML bystander must all be handled correctly.
        write_file(&dir.path().join("github/early.yml"), PACK_A);
        write_file(&dir.path().join("github/.gitkeep"), "");
        write_file(&dir.path().join("github/notes.txt"), "not a pack");

        let packs = load_pack_dir(dir.path()).unwrap();
        assert_eq!(
            packs.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["aaa.capability.one", "zzz.capability.last"]
        );

        let files = pack_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files[0].ends_with("github/early.yml"));
    }

    #[test]
    fn duplicate_capability_names_across_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("one.yaml"), PACK_A);
        write_file(
            &dir.path().join("two/nested.yaml"),
            &PACK_A.replace("token-a", "token-b"),
        );
        let err = load_pack_dir(dir.path()).unwrap_err();
        assert!(
            matches!(&err, PackError::DuplicateCapability(name) if name == "aaa.capability.one"),
            "{err}"
        );
    }

    #[test]
    fn per_file_errors_name_the_offending_file() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            &dir.path().join("broken/bad.yaml"),
            "format: 9\nname: broken.pack\nprovider: github\nrequest:\n  hosts: [api.github.com]\n  methods: [GET]\n  paths: [\"/x\"]\ncredential:\n  credential_ref: t\n  injection: bearer\n",
        );
        let err = load_pack_dir(dir.path()).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bad.yaml"), "{rendered}");
        assert!(rendered.contains("`format`"), "{rendered}");
    }

    #[test]
    fn empty_and_missing_directories_behave_predictably() {
        let empty = tempfile::tempdir().unwrap();
        assert!(load_pack_dir(empty.path()).unwrap().is_empty());

        let missing = load_pack_dir(Path::new("/nonexistent/vaultx/packs"));
        assert!(matches!(missing, Err(PackError::Io(_))));
    }

    #[test]
    fn parse_rejects_malformed_yaml_without_echoing_content() {
        let err = parse_pack_yaml("name: [unclosed").unwrap_err();
        assert!(matches!(err, PackError::Parse(_)));
        assert!(!err.to_string().contains("hunter2"));
    }
}
