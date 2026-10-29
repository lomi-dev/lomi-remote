//! Fixed synthetic subset for E0. No user-controlled argv or general Git API.
use serde_json::{Value, json};
use std::collections::BTreeMap;
mod policy;

fn diff(before: &str, after: &str) -> Value {
    use gix::diff::blob::{Algorithm, InternedInput, diff_with_slider_heuristics};
    let input = InternedInput::new(before, after);
    let diff = diff_with_slider_heuristics(Algorithm::Histogram, &input);
    let hunks: Vec<_> = diff.hunks().map(|h| json!({"before": [h.before.start, h.before.end], "after": [h.after.start, h.after.end]})).collect();
    json!({"before": before, "after": after, "removals": diff.count_removals(), "additions": diff.count_additions(), "hunks": hunks})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    policy::check(std::path::Path::new("/snapshot"))?;
    let repo = gix::open("/snapshot")?;
    let index = repo.index()?;
    if index.entries().len() != 1 || index.entries()[0].path(&index) != "tracked.txt" {
        return Err("unsupported synthetic fixture shape".into());
    }
    let head = repo.head_commit()?;
    let tree = head.tree()?;
    let entries: Vec<_> = tree
        .iter()
        .collect::<Result<_, _>>()
        .map_err(|e| e.into_error())?;
    if entries.len() != 1 || entries[0].filename() != "tracked.txt" {
        return Err("unsupported synthetic fixture tree".into());
    }
    let before = String::from_utf8(entries[0].object()?.data.to_vec())?;
    let staged = String::from_utf8(repo.find_object(index.entries()[0].id)?.data.to_vec())?;
    let worktree = std::fs::read_to_string("/snapshot/tracked.txt")?;
    let mut status = BTreeMap::<String, (char, char)>::new();
    for item in repo
        .status(gix::progress::Discard)?
        .into_iter(Vec::<gix::bstr::BString>::new())?
    {
        let item = item?;
        let path = item.location().to_string();
        match item {
            gix::status::Item::TreeIndex(gix::diff::index::Change::Modification { .. }) => {
                status.entry(path).or_insert((' ', ' ')).0 = 'M';
            }
            gix::status::Item::IndexWorktree(change) => {
                use gix::status::index_worktree::iter::Summary;
                match change.summary() {
                    Some(Summary::Modified) => {
                        status.entry(path).or_insert((' ', ' ')).1 = 'M';
                    }
                    Some(Summary::Added) => {
                        status.insert(path, ('?', '?'));
                    }
                    None => {}
                    _ => return Err("unsupported synthetic status change".into()),
                }
            }
            _ => return Err("unsupported synthetic index change".into()),
        }
    }
    let status: Vec<_> = status.into_iter().map(|(path, (index, worktree))| json!({"path":path,"index":index.to_string(),"worktree":worktree.to_string()})).collect();
    let mut log = Vec::new();
    for info in repo.rev_walk([head.id]).all()?.take(8) {
        let commit = info?
            .id()
            .object()?
            .try_into_commit()
            .map_err(|e| e.into_error())?;
        log.push(json!({"id":commit.id.to_string(),"message":commit.message_raw().map_err(|e| e.into_error())?.to_string().trim_end_matches('\n')}));
    }
    println!(
        "{}",
        json!({"status":status,"diff":diff(&staged,&worktree),"staged_diff":diff(&before,&staged),"log":log,"show":before,"index_entries":index.entries().len()})
    );
    Ok(())
}
