//! Stable volume identity captured from an already-open macOS descriptor.

use std::{fs::File, io};

use std::os::fd::AsRawFd;

const UUID_SIZE: usize = 16;

#[repr(C)]
struct ReturnedAttributeSet {
    commonattr: libc::attrgroup_t,
    volattr: libc::attrgroup_t,
    dirattr: libc::attrgroup_t,
    fileattr: libc::attrgroup_t,
    forkattr: libc::attrgroup_t,
}

/// Read the mounted volume UUID associated with this exact descriptor.
///
/// This deliberately uses `fgetattrlist`, so a pathname lookup or a later
/// mount of the same path cannot silently change which volume is identified.
pub fn volume_uuid(file: &File) -> io::Result<String> {
    let mut attributes: libc::attrlist = unsafe { std::mem::zeroed() };
    attributes.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    attributes.commonattr = libc::ATTR_CMN_RETURNED_ATTRS;
    attributes.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID;

    let mut response = [0u8; 4 + std::mem::size_of::<ReturnedAttributeSet>() + UUID_SIZE];
    let result = unsafe {
        libc::fgetattrlist(
            file.as_raw_fd(),
            (&mut attributes as *mut libc::attrlist).cast(),
            response.as_mut_ptr().cast(),
            response.len(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> io::Result<String> {
    let expected_len = 4 + std::mem::size_of::<ReturnedAttributeSet>() + UUID_SIZE;
    if response.len() < 4 {
        return Err(invalid_data());
    }

    let length = u32::from_ne_bytes(response[..4].try_into().map_err(|_| invalid_data())?) as usize;
    if length != expected_len || length > response.len() {
        return Err(invalid_data());
    }
    let response = &response[..length];

    let returned =
        unsafe { std::ptr::read_unaligned(response[4..].as_ptr().cast::<ReturnedAttributeSet>()) };
    let requested_common = libc::ATTR_CMN_RETURNED_ATTRS;
    let returned_volume = libc::ATTR_VOL_UUID;
    if returned.commonattr & requested_common != requested_common
        || returned.volattr & returned_volume != returned_volume
    {
        return Err(invalid_data());
    }

    let uuid_offset = 4 + std::mem::size_of::<ReturnedAttributeSet>();
    let bytes: [u8; UUID_SIZE] = response[uuid_offset..]
        .try_into()
        .map_err(|_| invalid_data())?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(invalid_data());
    }

    let uuid = uuid::Uuid::from_bytes(bytes);
    if uuid.is_nil() {
        return Err(invalid_data());
    }
    Ok(uuid.to_string())
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid macOS volume UUID response",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_descriptor_returns_canonical_nonzero_volume_uuid() {
        let root = File::open("/").expect("open root directory");
        let volume = volume_uuid(&root).expect("read volume UUID from descriptor");
        let parsed = uuid::Uuid::parse_str(&volume).expect("canonical UUID");
        assert!(!parsed.is_nil());
        assert_eq!(parsed.to_string(), volume);
    }

    #[test]
    fn response_parser_rejects_missing_or_malformed_uuid_attributes() {
        let mut response = valid_response([1; UUID_SIZE]);
        let attrset = unsafe { &mut *response[4..].as_mut_ptr().cast::<ReturnedAttributeSet>() };
        attrset.volattr &= !libc::ATTR_VOL_UUID;
        assert_eq!(
            parse_response(&response).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut zero_uuid = valid_response([0; UUID_SIZE]);
        assert_eq!(
            parse_response(&zero_uuid).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        zero_uuid[0] = (zero_uuid.len() - 1) as u8;
        assert_eq!(
            parse_response(&zero_uuid).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn valid_response(uuid: [u8; UUID_SIZE]) -> Vec<u8> {
        let expected_len = 4 + std::mem::size_of::<ReturnedAttributeSet>() + UUID_SIZE;
        let mut response = vec![0; expected_len];
        response[..4].copy_from_slice(&(expected_len as u32).to_ne_bytes());
        let returned = ReturnedAttributeSet {
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS,
            volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        unsafe {
            std::ptr::write_unaligned(
                response[4..].as_mut_ptr().cast::<ReturnedAttributeSet>(),
                returned,
            );
        }
        let uuid_offset = 4 + std::mem::size_of::<ReturnedAttributeSet>();
        response[uuid_offset..].copy_from_slice(&uuid);
        response
    }
}
