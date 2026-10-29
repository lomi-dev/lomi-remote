//! Fail-closed policy before gix sees repository configuration or attributes.
use std::path::Path;
pub fn validate_config(config: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut section = false;
    let mut keys = std::collections::BTreeSet::new();
    for line in config
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line == "[core]" && !section {
            section = true;
            continue;
        }
        if !section {
            return Err("unsupported Git config".into());
        }
        let (key, value) = line.split_once('=').ok_or("unsupported Git config")?;
        let pair = (key.trim(), value.trim());
        if !matches!(
            pair,
            ("repositoryformatversion", "0")
                | ("filemode", "true")
                | ("bare", "false")
                | ("logallrefupdates", "true")
                | ("ignorecase", "true")
                | ("precomposeunicode", "true")
        ) || !keys.insert(pair.0.to_owned())
        {
            return Err("unsupported Git config".into());
        }
    }
    if !section
        || !["repositoryformatversion", "filemode", "bare"]
            .iter()
            .all(|key| keys.contains(*key))
    {
        return Err("unsupported Git config".into());
    }
    Ok(())
}

pub fn check(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    validate_config(&std::fs::read_to_string(root.join(".git/config"))?)?;
    for name in [
        // Common repositories can redirect config, attributes and objects away
        // from the metadata checked here. This profile accepts ordinary repos.
        "commondir",
        "config.worktree",
        "objects/info/alternates",
        "objects/info/http-alternates",
        "info/attributes",
        "shallow",
    ] {
        if root.join(".git").join(name).try_exists()? {
            return Err("unsupported Git metadata".into());
        }
    }
    fn attributes(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        for item in std::fs::read_dir(path)? {
            let item = item?;
            if item.file_name() == ".gitattributes" || item.file_name() == ".gitmodules" {
                return Err("unsupported Git attributes or submodule".into());
            }
            if item.file_type()?.is_symlink() {
                return Err("unsupported symlink".into());
            }
            if item.file_type()?.is_dir() {
                attributes(&item.path())?;
            }
        }
        Ok(())
    }
    attributes(root)
}
