//! eBPF-observer unit tests (decode / attribution), extracted from `observer.rs` to keep it
//! under the 1,000-line cap (CLAUDE.md). Included via `#[path]` inside `mod ebpf`, so `super`
//! resolves to the eBPF observer module.

use super::*;

const POD_CGROUP: &str = "/kubepods/besteffort/pod3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b/abc123";
const POD_SLICE: &str = "/sys/fs/cgroup/kubepods.slice/\
    kubepods-besteffort-pod3f5e1a2b_4c6d_7e8f_9a0b_1c2d3e4f5a6b.slice";
const POD_UID: &str = "3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b";

fn attr(pid: u32, cgroup_id: u64) -> EventAttr {
    EventAttr { pid, cgroup_id }
}

#[test]
fn resolve_uses_the_table_and_never_reads_proc_on_a_cgroup_id_hit() {
    // hot path: a cgroup_id table hit resolves with NO `/proc` read and NO
    // fallback-cache entry — which is what lets an already-exited process attribute.
    let table = crate::pod::build_cgroup_table([(100u64, POD_SLICE.to_string())]);
    let mut cache = HashMap::new();
    assert_eq!(
        EbpfObserver::resolve(&table, &mut cache, attr(4321, 100)),
        PodAttribution::Pod(POD_UID.to_string())
    );
    assert!(
        cache.is_empty(),
        "a table hit must not touch the /proc cache"
    );
}

#[test]
fn resolve_falls_back_to_proc_and_memoizes_on_a_table_miss() {
    // A table miss falls through to the `/proc` read; a flood from one pid must not
    // re-read it (the fallback cache).
    let table = CgroupTable::default();
    // Seed the fallback cache as the worker would, then confirm a repeat is cached.
    let mut cache = HashMap::new();
    let resolved = EbpfObserver::resolve(&table, &mut cache, attr(7, 0));
    // pid 7 / cgroup_id 0 → table miss → /proc read of /proc/7/cgroup (absent in the
    // test env) → Unreadable, and it's cached.
    assert_eq!(resolved, PodAttribution::Unreadable);
    assert!(cache.contains_key(&7), "fallback result should be cached");
}

#[test]
fn resolve_clears_fallback_cache_at_cap() {
    let table = CgroupTable::default();
    let mut cache = HashMap::new();
    // Fill the fallback cache to capacity (each distinct miss pid inserts once).
    for pid in 0..PID_CACHE_CAP as u32 {
        EbpfObserver::resolve(&table, &mut cache, attr(pid, 0));
    }
    assert_eq!(cache.len(), PID_CACHE_CAP);
    EbpfObserver::resolve(&table, &mut cache, attr(PID_CACHE_CAP as u32, 0));
    assert_eq!(cache.len(), 1, "cache should clear wholesale at the cap");
}

#[test]
fn proc_fallback_classifies_pod_cgroup_text() {
    // The injected `/proc` reader path (via pod::resolve_attribution) still maps a
    // pod cgroup text to its UID — the fallback for a table miss is unchanged.
    assert_eq!(
        crate::pod::resolve_attribution(&CgroupTable::default(), 0, 42, |_| Some(
            POD_CGROUP.to_string()
        )),
        PodAttribution::Pod(POD_UID.to_string())
    );
}

#[test]
fn decode_connect_parses_without_proc() {
    let ev = ConnEvent {
        header: EventHeader {
            kind: KIND_CONNECT,
            pid: 1234,
            cgroup_id: 777,
        },
        daddr: u32::from_ne_bytes([8, 8, 8, 8]),
        dport: 443,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&ev as *const ConnEvent).cast::<u8>(),
            std::mem::size_of::<ConnEvent>(),
        )
    };
    match EbpfObserver::decode(bytes) {
        Some(RawEvent::Connect { attr, daddr, dport }) => {
            assert_eq!(attr.pid, 1234);
            assert_eq!(attr.cgroup_id, 777);
            assert_eq!(daddr, ev.daddr);
            assert_eq!(dport, 443);
        }
        other => panic!("expected Connect, got something else: {}", other.is_none()),
    }
}

#[test]
fn decode_priv_change_parses_uids() {
    let ev = PrivEvent {
        header: EventHeader {
            kind: KIND_PRIV_CHANGE,
            pid: 4321,
            cgroup_id: 888,
        },
        old_uid: 1000,
        new_uid: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&ev as *const PrivEvent).cast::<u8>(),
            std::mem::size_of::<PrivEvent>(),
        )
    };
    match EbpfObserver::decode(bytes) {
        Some(RawEvent::PrivChange {
            attr,
            old_uid,
            new_uid,
        }) => {
            assert_eq!(attr.pid, 4321);
            assert_eq!(attr.cgroup_id, 888);
            assert_eq!(old_uid, 1000);
            assert_eq!(new_uid, 0);
        }
        _ => panic!("expected PrivChange"),
    }
    // And the raw event maps to the PrivilegeChange behavior with from/to uids.
    let raw = EbpfObserver::decode(bytes).unwrap();
    assert_eq!(
        raw.into_behavior(),
        Behavior::PrivilegeChange {
            from_uid: 1000,
            to_uid: 0,
        }
    );
}

/// Build an [`ExecEvent`] with a NUL-terminated `path` and the given `exe_anon_inode` byte
/// (Route A).
fn exec_event(kind_pid_cgroup: (u32, u32, u64), bin: &[u8], exe_anon_inode: u8) -> ExecEvent {
    let (kind, pid, cgroup_id) = kind_pid_cgroup;
    let mut path = [0u8; PATH_CAP];
    path[..bin.len()].copy_from_slice(bin);
    ExecEvent {
        header: EventHeader {
            kind,
            pid,
            cgroup_id,
        },
        len: bin.len() as u32,
        path,
        exe_anon_inode,
    }
}

#[test]
fn decode_exec_parses_path_and_maps_to_process_exec() {
    // A KIND_EXEC ExecEvent carrying a NUL-terminated exec path must decode to a
    // RawEvent::Exec, and into_behavior must map it to Behavior::ProcessExec whose
    // fingerprint coarsens to the basename. exe_anon_inode == 0 here — the
    // ordinary, non-anonymous case.
    let ev = exec_event((KIND_EXEC, 4321, 999), b"/usr/bin/bash\0", 0);
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&ev as *const ExecEvent).cast::<u8>(),
            std::mem::size_of::<ExecEvent>(),
        )
    };
    let raw = EbpfObserver::decode(bytes).expect("KIND_EXEC should decode");
    match &raw {
        RawEvent::Exec {
            attr,
            path,
            exe_anon_inode,
        } => {
            assert_eq!(attr.pid, 4321);
            assert_eq!(attr.cgroup_id, 999);
            assert_eq!(path, "/usr/bin/bash");
            assert!(!exe_anon_inode);
        }
        _ => panic!("expected RawEvent::Exec"),
    }
    assert_eq!(raw.attr().pid, 4321);
    match raw.into_behavior() {
        Behavior::ProcessExec {
            path,
            exe_anon_inode,
        } => {
            assert_eq!(path, "/usr/bin/bash");
            assert!(!exe_anon_inode);
            assert_eq!(
                Behavior::ProcessExec {
                    path,
                    exe_anon_inode
                }
                .fingerprint_key(),
                "exec:bash"
            );
        }
        other => panic!("expected ProcessExec, got {other:?}"),
    }
}

#[test]
fn decode_exec_carries_the_anon_inode_flag_through() {
    // A KIND_EXEC ExecEvent with exe_anon_inode == 1 (Route A: the kernel's own
    // f_inode read, not a path-shape guess) must decode and map the flag through verbatim
    // — never inferred from the path, which here looks like an ordinary on-disk binary.
    let ev = exec_event((KIND_EXEC, 1, 2), b"/bin/bash\0", 1);
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&ev as *const ExecEvent).cast::<u8>(),
            std::mem::size_of::<ExecEvent>(),
        )
    };
    let raw = EbpfObserver::decode(bytes).expect("KIND_EXEC should decode");
    match &raw {
        RawEvent::Exec { exe_anon_inode, .. } => assert!(exe_anon_inode),
        _ => panic!("expected RawEvent::Exec"),
    }
    match raw.into_behavior() {
        Behavior::ProcessExec { exe_anon_inode, .. } => assert!(exe_anon_inode),
        other => panic!("expected ProcessExec, got {other:?}"),
    }
}

#[test]
fn decode_file_write_parses_path_and_maps_to_file_write() {
    // A KIND_FILE_WRITE FileEvent carrying a NUL-terminated path must decode to a
    // RawEvent::FileWrite with attribution, and into_behavior must map it to
    // Behavior::FileWrite whose fingerprint coarsens to the dirname.
    let mut path = [0u8; PATH_CAP];
    let file = b"/etc/cron.d/dropper\0";
    path[..file.len()].copy_from_slice(file);
    let ev = FileEvent {
        header: EventHeader {
            kind: KIND_FILE_WRITE,
            pid: 555,
            cgroup_id: 4242,
        },
        len: file.len() as u32,
        path,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&ev as *const FileEvent).cast::<u8>(),
            std::mem::size_of::<FileEvent>(),
        )
    };
    let raw = EbpfObserver::decode(bytes).expect("KIND_FILE_WRITE should decode");
    match &raw {
        RawEvent::FileWrite { attr, path } => {
            assert_eq!(attr.pid, 555);
            assert_eq!(attr.cgroup_id, 4242);
            assert_eq!(path, "/etc/cron.d/dropper");
        }
        _ => panic!("expected RawEvent::FileWrite"),
    }
    assert_eq!(raw.attr().cgroup_id, 4242);
    match raw.into_behavior() {
        Behavior::FileWrite { path } => {
            assert_eq!(path, "/etc/cron.d/dropper");
            assert_eq!(
                Behavior::FileWrite { path }.fingerprint_key(),
                "write:/etc/cron.d"
            );
        }
        other => panic!("expected FileWrite, got {other:?}"),
    }
}

#[test]
fn decode_ptrace_attach_parses_with_no_body_beyond_the_header() {
    // a KIND_PTRACE_ATTACH event IS an EventHeader — no extra bytes, unlike every
    // other kind's body. Decode must still succeed on exactly `size_of::<EventHeader>()`
    // bytes and attribute + map it to Behavior::PtraceAttach.
    let header = EventHeader {
        kind: KIND_PTRACE_ATTACH,
        pid: 4321,
        cgroup_id: 999,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const EventHeader).cast::<u8>(),
            std::mem::size_of::<EventHeader>(),
        )
    };
    let raw = EbpfObserver::decode(bytes).expect("KIND_PTRACE_ATTACH should decode");
    match &raw {
        RawEvent::PtraceAttach { attr } => {
            assert_eq!(attr.pid, 4321);
            assert_eq!(attr.cgroup_id, 999);
        }
        _ => panic!("expected RawEvent::PtraceAttach"),
    }
    assert_eq!(raw.attr().pid, 4321);
    assert_eq!(raw.into_behavior(), Behavior::PtraceAttach);
}

#[test]
fn decode_module_load_parses_with_no_body_beyond_the_header() {
    // same header-only shape as KIND_PTRACE_ATTACH, distinct kind + behavior.
    let header = EventHeader {
        kind: KIND_MODULE_LOAD,
        pid: 555,
        cgroup_id: 4242,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const EventHeader).cast::<u8>(),
            std::mem::size_of::<EventHeader>(),
        )
    };
    let raw = EbpfObserver::decode(bytes).expect("KIND_MODULE_LOAD should decode");
    match &raw {
        RawEvent::ModuleLoad { attr } => {
            assert_eq!(attr.pid, 555);
            assert_eq!(attr.cgroup_id, 4242);
        }
        _ => panic!("expected RawEvent::ModuleLoad"),
    }
    assert_eq!(raw.attr().cgroup_id, 4242);
    assert_eq!(raw.into_behavior(), Behavior::ModuleLoad);
}

#[test]
fn decode_drops_a_truncated_event_shorter_than_the_header() {
    // A byte slice shorter than EventHeader itself must never be parsed — regardless of
    // kind, since decode() reads the header before it can even dispatch.
    let too_short = [0u8; 4];
    assert!(EbpfObserver::decode(&too_short).is_none());
}
