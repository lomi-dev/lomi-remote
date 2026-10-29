//! Shared filename policy for private native file staging entries.
//!
//! Keep these names hidden from public filesystem and Git snapshots while
//! leaving the publisher's own staging operations available.

#![forbid(unsafe_code)]

/// Returns whether `name` is an exact reserved native staging filename.
///
/// The check is byte-based so non-UTF-8 Unix filenames are handled without
/// lossy conversion. ASCII portions are compared case-insensitively because
/// APFS and NTFS can resolve differently-cased names to the same entry.
pub fn is_private_staging_name(name: &[u8]) -> bool {
    if let Some(payload) = strip_ascii_case_insensitive_prefix(name, b".lomi-desktop-")
        .and_then(|rest| strip_ascii_case_insensitive_suffix(rest, b".tmp"))
    {
        return payload.len() == 32 && payload.iter().all(|byte| byte.is_ascii_hexdigit());
    }
    if let Some(number) = strip_ascii_case_insensitive_prefix(name, b".lomi-native-") {
        return is_decimal(number, u64::MAX);
    }

    if let Some(payload) = strip_ascii_case_insensitive_prefix(name, b".lomi-object-")
        .and_then(|rest| strip_ascii_case_insensitive_suffix(rest, b".tmp"))
    {
        return payload.len() == 32 && payload.iter().all(|byte| byte.is_ascii_hexdigit());
    }

    if let Some(payload) = strip_ascii_case_insensitive_prefix(name, b".lomi-pull-")
        .and_then(|rest| strip_ascii_case_insensitive_suffix(rest, b".tmp"))
    {
        let Some(separator) = payload.iter().position(|byte| *byte == b'-') else {
            return false;
        };
        return is_decimal(&payload[..separator], u32::MAX as u64)
            && is_decimal(&payload[separator + 1..], u64::MAX);
    }

    if let Some(uuid) = strip_ascii_case_insensitive_prefix(name, b"lomi-temp-")
        .or_else(|| strip_ascii_case_insensitive_prefix(name, b"lomi-link-"))
        .and_then(|rest| strip_ascii_case_insensitive_suffix(rest, b".tmp"))
    {
        return is_uuid(uuid);
    }

    false
}

/// Absolute-path component expressions for the same private namespace.
///
/// Native process sandboxes need to deny access even after a Host operation
/// has finished staging a recoverable item. The numeric alternatives preserve
/// the parser's exact unsigned bounds and reject leading zeroes. Only fixed
/// ASCII policy data enters these expressions; no filesystem input is used.
pub fn private_staging_path_patterns() -> Vec<String> {
    let literal = |value: &str| {
        value
            .chars()
            .map(|ch| match ch {
                '.' => "[.]".to_owned(),
                ch if ch.is_ascii_alphabetic() => {
                    format!("[{}{}]", ch.to_ascii_lowercase(), ch.to_ascii_uppercase())
                }
                ch => ch.to_string(),
            })
            .collect::<String>()
    };
    let decimal = |max: u64| {
        let max = max.to_string();
        let mut alternatives = vec!["0".to_owned()];
        if max.len() > 1 {
            alternatives.push(format!("[1-9][0-9]{{0,{}}}", max.len() - 2));
        }
        for (index, digit) in max.bytes().enumerate() {
            let minimum = if index == 0 { b'1' } else { b'0' };
            if digit > minimum {
                let tail = max.len() - index - 1;
                alternatives.push(format!(
                    "{}[{}-{}][0-9]{{{tail}}}",
                    &max[..index],
                    minimum as char,
                    (digit - 1) as char
                ));
            }
        }
        alternatives.push(max);
        format!("({})", alternatives.join("|"))
    };
    let hex = "[0-9a-fA-F]";
    let uuid = format!("{hex}{{8}}-{hex}{{4}}-{hex}{{4}}-{hex}{{4}}-{hex}{{12}}");
    let native = format!("{}{}", literal(".lomi-native-"), decimal(u64::MAX));
    let object = format!("{}{hex}{{32}}{}", literal(".lomi-object-"), literal(".tmp"));
    let pull = format!(
        "{}{}-{}{}",
        literal(".lomi-pull-"),
        decimal(u32::MAX.into()),
        decimal(u64::MAX),
        literal(".tmp")
    );
    let temporary = format!("{}{uuid}{}", literal("lomi-temp-"), literal(".tmp"));
    let link = format!("{}{uuid}{}", literal("lomi-link-"), literal(".tmp"));
    let desktop = format!(
        "{}{hex}{{32}}{}",
        literal(".lomi-desktop-"),
        literal(".tmp")
    );
    [native, object, pull, temporary, link, desktop]
        .into_iter()
        .map(|name| format!("/({name})(/|$)"))
        .collect()
}

fn strip_ascii_case_insensitive_prefix<'a>(value: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let (candidate, rest) = value.split_at_checked(prefix.len())?;
    candidate.eq_ignore_ascii_case(prefix).then_some(rest)
}

fn strip_ascii_case_insensitive_suffix<'a>(value: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    let split = value.len().checked_sub(suffix.len())?;
    let (body, candidate) = value.split_at(split);
    candidate.eq_ignore_ascii_case(suffix).then_some(body)
}

fn is_decimal(value: &[u8], max: u64) -> bool {
    if value.is_empty() || (value.len() > 1 && value[0] == b'0') {
        return false;
    }

    let mut number = 0u64;
    for byte in value {
        if !byte.is_ascii_digit() {
            return false;
        }
        let Some(next) = number
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(*byte - b'0')))
        else {
            return false;
        };
        if next > max {
            return false;
        }
        number = next;
    }
    true
}

fn is_uuid(value: &[u8]) -> bool {
    value.len() == 36
        && value.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}
