#[path = "../policy.rs"]
mod policy;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    const GOOD: &str = "[core]\nrepositoryformatversion=0\nfilemode=true\nbare=false\n";
    policy::validate_config(GOOD)?;
    assert!(policy::validate_config("").is_err());
    assert!(policy::validate_config("[core]\n").is_err());
    assert!(policy::validate_config(&GOOD.replace("bare=false", "bare=true")).is_err());
    // Bare assignments keep GOOD's sole [core] header: rejection must test the
    // key/value allowlist, rather than the independent duplicate-header rule.
    for bad in [
        "fsmonitor=helper\n",
        "autocrlf=true\n",
        "eol=crlf\n",
        "attributesfile=/outside-canary\n",
        "workingtreeencoding=UTF-16\n",
    ] {
        assert!(
            policy::validate_config(&format!("{GOOD}{bad}")).is_err(),
            "{bad}"
        );
    }
    for bad in [
        "[filter \"x\"]\nclean=helper\nrequired=true\n",
        "[diff \"x\"]\ntextconv=helper\n",
        "[diff]\nexternal=helper\n",
        "[include]\npath=/outside-canary\n",
        "[includeIf \"gitdir:/\"]\npath=/outside-canary\n",
        "[extensions]\nworktreeConfig=true\n",
        "[credential]\nhelper=helper\n",
    ] {
        assert!(
            policy::validate_config(&format!("{GOOD}{bad}")).is_err(),
            "{bad}"
        );
    }
    assert!(policy::validate_config(&format!("{GOOD}[core]\n")).is_err());
    assert!(policy::validate_config(&format!("{GOOD}repositoryformatversion=0\n")).is_err());
    // Each root was copied before adding a single forbidden input. Attributes
    // are preserved, never erased to make gix report a false success.
    for name in ["attributes", "alternates", "metadata", "symlink"] {
        assert!(policy::check(&std::path::Path::new("/snapshot").join(name)).is_err());
    }
    policy::check(std::path::Path::new("/snapshot/ordinary"))?;
    assert_eq!(
        policy::check(std::path::Path::new("/snapshot/commondir"))
            .unwrap_err()
            .to_string(),
        "unsupported Git metadata"
    );
    println!("policy_probe_passed");
    Ok(())
}
