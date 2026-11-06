//! Stable Btrfs identity captured from an already-open Linux descriptor.

use std::{fs::File, io, mem::size_of, os::fd::AsRawFd};

const BTRFS_IOCTL_MAGIC: u32 = 0x94;
const BTRFS_IOC_FS_INFO_NR: u32 = 31;
const BTRFS_IOC_GET_SUBVOL_INFO_NR: u32 = 60;
const IOC_READ: u32 = 2;
const IOC_DIRSHIFT: u32 = 30;
const IOC_TYPESHIFT: u32 = 8;
const IOC_SIZESHIFT: u32 = 16;
const BTRFS_FS_INFO_FLAG_METADATA_UUID: u64 = 1 << 2;

const fn ior(number: u32, size: usize) -> libc::c_ulong {
    ((IOC_READ << IOC_DIRSHIFT)
        | (BTRFS_IOCTL_MAGIC << IOC_TYPESHIFT)
        | (number & 0xff)
        | ((size as u32) << IOC_SIZESHIFT)) as libc::c_ulong
}

/// Stable Btrfs filesystem and subvolume UUIDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub filesystem_uuid: String,
    pub subvolume_uuid: String,
}

#[repr(C)]
#[allow(dead_code)]
struct FsInfoArgs {
    max_id: u64,
    num_devices: u64,
    fsid: [u8; 16],
    nodesize: u32,
    sectorsize: u32,
    clone_alignment: u32,
    csum_type: u16,
    csum_size: u16,
    flags: u64,
    generation: u64,
    metadata_uuid: [u8; 16],
    reserved: [u8; 944],
}

#[repr(C)]
#[allow(dead_code)]
struct KernelTimespec {
    sec: u64,
    nsec: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct GetSubvolInfoArgs {
    treeid: u64,
    name: [u8; 256],
    parent_id: u64,
    dirid: u64,
    generation: u64,
    flags: u64,
    uuid: [u8; 16],
    parent_uuid: [u8; 16],
    received_uuid: [u8; 16],
    ctransid: u64,
    otransid: u64,
    stransid: u64,
    rtransid: u64,
    ctime: KernelTimespec,
    otime: KernelTimespec,
    stime: KernelTimespec,
    rtime: KernelTimespec,
    reserved: [u64; 8],
}

const _: [(); 1024] = [(); size_of::<FsInfoArgs>()];
const _: [(); 504] = [(); size_of::<GetSubvolInfoArgs>()];

/// Read the filesystem and subvolume UUIDs associated with this exact
/// descriptor. `Ok(None)` means the descriptor is not on Btrfs; any other
/// ioctl failure is returned so callers fail closed for an identified Btrfs
/// filesystem.
pub(crate) fn read(file: &File) -> io::Result<Option<Identity>> {
    let mut fs_info: FsInfoArgs = unsafe { std::mem::zeroed() };
    // Request metadata_uuid as well for compatibility with the current UAPI.
    // The stable filesystem UUID recorded by callers is fsid.
    fs_info.flags = BTRFS_FS_INFO_FLAG_METADATA_UUID;
    let fs_info_request = ior(BTRFS_IOC_FS_INFO_NR, size_of::<FsInfoArgs>());
    if unsafe { libc::ioctl(file.as_raw_fd(), fs_info_request, &mut fs_info) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOTTY) {
            return Ok(None);
        }
        return Err(error);
    }

    let mut subvol_info: GetSubvolInfoArgs = unsafe { std::mem::zeroed() };
    let subvol_request = ior(BTRFS_IOC_GET_SUBVOL_INFO_NR, size_of::<GetSubvolInfoArgs>());
    if unsafe { libc::ioctl(file.as_raw_fd(), subvol_request, &mut subvol_info) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(Some(Identity {
        filesystem_uuid: canonical_nonzero_uuid(fs_info.fsid)?,
        subvolume_uuid: canonical_nonzero_uuid(subvol_info.uuid)?,
    }))
}

fn canonical_nonzero_uuid(bytes: [u8; 16]) -> io::Result<String> {
    let uuid = uuid::Uuid::from_bytes(bytes);
    if uuid.is_nil() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Btrfs UUID response",
        ));
    }
    Ok(uuid.hyphenated().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parser_requires_nonzero_uuids_and_uses_canonical_form() {
        let uuid = canonical_nonzero_uuid([1; 16]).unwrap();
        assert_eq!(uuid, "01010101-0101-0101-0101-010101010101");
        assert_eq!(
            canonical_nonzero_uuid([0; 16]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn retained_descriptor_probe_is_nonmutating() {
        let directory = File::open("/").expect("open root directory");
        let result = read(&directory).expect("read-only filesystem identity probe");
        if let Some(identity) = result {
            assert_eq!(
                uuid::Uuid::parse_str(&identity.filesystem_uuid)
                    .expect("canonical filesystem UUID")
                    .to_string(),
                identity.filesystem_uuid
            );
            assert_eq!(
                uuid::Uuid::parse_str(&identity.subvolume_uuid)
                    .expect("canonical subvolume UUID")
                    .to_string(),
                identity.subvolume_uuid
            );
        }
    }

    #[test]
    #[ignore = "run from a Btrfs-backed test workspace"]
    fn owner_lock_reads_filesystem_and_subvolume_from_its_retained_fd() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::current_dir()
            .expect("current test workspace")
            .join(format!(".btrfs-identity-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create private Btrfs test directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("make Btrfs test directory private");
        let lock = crate::unix::OwnerLock::acquire(&path).expect("acquire profile owner lock");
        let identity = lock
            .profile_btrfs_identity()
            .expect("query Btrfs identity from retained profile FD")
            .expect("test workspace is Btrfs-backed");
        assert_eq!(
            uuid::Uuid::parse_str(&identity.filesystem_uuid)
                .expect("canonical filesystem UUID")
                .to_string(),
            identity.filesystem_uuid
        );
        assert_eq!(
            uuid::Uuid::parse_str(&identity.subvolume_uuid)
                .expect("canonical subvolume UUID")
                .to_string(),
            identity.subvolume_uuid
        );
        drop(lock);
        std::fs::remove_dir_all(&path).expect("remove private Btrfs test directory");
    }
}
