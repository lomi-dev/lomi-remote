//! Runtime checks of the WASI-only adapter; invoked with a private fixture.
use memmap2::{Mmap, MmapMut, MmapOptions};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open("/snapshot/mmap-probe.bin")?;
    file.seek(SeekFrom::Start(2))?;
    let map = unsafe { MmapOptions::new().offset(2).len(3).map(&file)? };
    assert_eq!(&map[..], b"cde");
    let pointer = map.as_ptr();
    let moved = map;
    assert_eq!(pointer, moved.as_ptr());
    let mut next = [0];
    file.read_exact(&mut next)?;
    assert_eq!(&next, b"c");
    assert_eq!(
        &unsafe { MmapOptions::new().map_copy_read_only(&file)? }[..],
        b"abcdef"
    );
    assert!(unsafe { MmapOptions::new().offset(6).len(0).map(&file)? }.is_empty());
    assert!(unsafe { MmapOptions::new().offset(0).len(0).map(&file)? }.is_empty());
    for (offset, len) in [
        (7, 0),
        (u64::MAX, 1),
        (0, 16 * 1024 * 1024 + 1),
        (0, 7),
        (5, 2),
    ] {
        assert!(unsafe { MmapOptions::new().offset(offset).len(len).map(&file) }.is_err());
    }
    assert!(unsafe { MmapOptions::new().map_mut(&file) }.is_err());
    assert!(unsafe { MmapOptions::new().map_copy(&file) }.is_err());
    assert!(unsafe { MmapOptions::new().map_exec(&file) }.is_err());
    assert!(MmapMut::map_anon(1).is_err());
    assert!(unsafe { Mmap::map(&file)? }.make_mut().is_err());
    assert_eq!(file.metadata()?.len(), 6);
    let metadata = file.metadata()?;
    assert_eq!(
        filetime::FileTime::from_last_modification_time(&metadata),
        filetime::FileTime::from_system_time(metadata.modified()?)
    );
    assert_eq!(
        filetime::FileTime::from_last_access_time(&metadata),
        filetime::FileTime::from_system_time(metadata.accessed()?)
    );
    assert_eq!(
        filetime::FileTime::from_creation_time(&metadata),
        metadata
            .created()
            .ok()
            .map(filetime::FileTime::from_system_time)
    );
    let time = filetime::FileTime::from_unix_time(10, 0);
    assert_eq!(
        filetime::set_file_times("/snapshot/mmap-probe.bin", time, time)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(
        filetime::set_file_atime("/snapshot/mmap-probe.bin", time)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(
        filetime::set_file_mtime("/snapshot/mmap-probe.bin", time)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(
        filetime::set_symlink_file_times("/snapshot/mmap-probe.bin", time, time)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(
        filetime::set_file_handle_times(&file, Some(time), Some(time))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    println!("mmap_readonly_probe_passed");
    Ok(())
}
