//! Native Win32 FFI helpers for zero-process-spawn process, service, and registry management.
//! Uses built-in Windows system DLLs (`kernel32`, `advapi32`, `shell32`) with no external crates.

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
pub const HKEY_CURRENT_USER: isize = 0x80000001u32 as i32 as isize;
#[cfg(windows)]
pub const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as i32 as isize;

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[cfg(windows)]
impl Default for ProcessEntry32W {
    fn default() -> Self {
        Self {
            dw_size: std::mem::size_of::<Self>() as u32,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0u16; 260],
        }
    }
}

#[cfg(windows)]
fn snapshot_processes<F>(mut visitor: F)
where
    F: FnMut(u32, &str),
{
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> isize;
        fn Process32FirstW(hSnapshot: isize, lppe: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(hSnapshot: isize, lppe: *mut ProcessEntry32W) -> i32;
        fn CloseHandle(hObject: isize) -> i32;
    }

    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const INVALID_HANDLE_VALUE: isize = -1;

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == 0 || snap == INVALID_HANDLE_VALUE {
        return;
    }

    let mut entry = ProcessEntry32W::default();
    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        loop {
            let end = entry
                .sz_exe_file
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.sz_exe_file.len());
            let name = String::from_utf16_lossy(&entry.sz_exe_file[..end]);
            visitor(entry.th32_process_id, &name);
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snap) };
}

/// Returns `true` if any running process has the exact executable filename (case-insensitive).
pub fn is_process_running(exe_name: &str) -> bool {
    #[cfg(windows)]
    {
        let mut found = false;
        snapshot_processes(|_, name| {
            if !found && name.eq_ignore_ascii_case(exe_name) {
                found = true;
            }
        });
        found
    }
    #[cfg(not(windows))]
    {
        let _ = exe_name;
        false
    }
}

/// Returns matching executable names from `candidates` currently running in a single snapshot pass.
pub fn find_running_exes<'a>(candidates: &[&'a str]) -> Vec<&'a str> {
    #[cfg(windows)]
    {
        let mut present = vec![false; candidates.len()];
        snapshot_processes(|_, name| {
            for (i, cand) in candidates.iter().enumerate() {
                if !present[i] && name.eq_ignore_ascii_case(cand) {
                    present[i] = true;
                }
            }
        });
        candidates
            .iter()
            .enumerate()
            .filter_map(|(i, cand)| if present[i] { Some(*cand) } else { None })
            .collect()
    }
    #[cfg(not(windows))]
    {
        let _ = candidates;
        Vec::new()
    }
}

/// Terminates a single process by PID via `TerminateProcess`.
pub fn kill_pid(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;
            fn TerminateProcess(hProcess: isize, uExitCode: u32) -> i32;
            fn CloseHandle(hObject: isize) -> i32;
        }
        const PROCESS_TERMINATE: u32 = 0x0001;
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle == 0 {
            return false;
        }
        let ok = unsafe { TerminateProcess(handle, 1) } != 0;
        unsafe { CloseHandle(handle) };
        ok
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        false
    }
}

/// Terminates all processes matching `exe_name` (case-insensitive), optionally skipping `exclude_pid`.
pub fn kill_by_name(exe_name: &str, exclude_pid: Option<u32>) -> usize {
    #[cfg(windows)]
    {
        let mut pids = Vec::new();
        snapshot_processes(|pid, name| {
            if Some(pid) != exclude_pid && name.eq_ignore_ascii_case(exe_name) {
                pids.push(pid);
            }
        });
        let mut killed = 0;
        for pid in pids {
            if kill_pid(pid) {
                killed += 1;
            }
        }
        killed
    }
    #[cfg(not(windows))]
    {
        let _ = (exe_name, exclude_pid);
        0
    }
}

/// Opens a URL or file in the default shell handler without spawning `cmd.exe`.
pub fn open_url(url: &str) {
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: isize,
                lpOperation: *const u16,
                lpFile: *const u16,
                lpParameters: *const u16,
                lpDirectory: *const u16,
                nShowCmd: i32,
            ) -> isize;
        }
        let op = to_wide("open");
        let target = to_wide(url);
        unsafe {
            ShellExecuteW(
                0,
                op.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            );
        }
    }
    #[cfg(not(windows))]
    {
        let _ = url;
    }
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        hKey: isize,
        lpSubKey: *const u16,
        Reserved: u32,
        lpClass: *const u16,
        dwOptions: u32,
        samDesired: u32,
        lpSecurityAttributes: *const std::ffi::c_void,
        phkResult: *mut isize,
        lpdwDisposition: *mut u32,
    ) -> i32;
    fn RegOpenKeyExW(
        hKey: isize,
        lpSubKey: *const u16,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut isize,
    ) -> i32;
    fn RegQueryValueExW(
        hKey: isize,
        lpValueName: *const u16,
        lpReserved: *const u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        hKey: isize,
        lpValueName: *const u16,
        Reserved: u32,
        dwType: u32,
        lpData: *const u8,
        cbData: u32,
    ) -> i32;
    fn RegDeleteValueW(hKey: isize, lpValueName: *const u16) -> i32;
    fn RegCloseKey(hKey: isize) -> i32;
}

/// Checks if a registry value exists under `root\subkey`.
pub fn reg_value_exists(root: isize, subkey: &str, value_name: &str) -> bool {
    #[cfg(windows)]
    {
        const KEY_QUERY_VALUE: u32 = 0x0001;
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let mut hkey: isize = 0;
        if unsafe { RegOpenKeyExW(root, sub_w.as_ptr(), 0, KEY_QUERY_VALUE, &mut hkey) } != 0
            || hkey == 0
        {
            return false;
        }
        let mut cb_data: u32 = 0;
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                val_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut cb_data,
            )
        };
        unsafe { RegCloseKey(hkey) };
        rc == 0
    }
    #[cfg(not(windows))]
    {
        let _ = (root, subkey, value_name);
        false
    }
}

/// Sets a `REG_SZ` string value in the Windows registry.
pub fn reg_set_sz(root: isize, subkey: &str, value_name: &str, data: &str) -> bool {
    #[cfg(windows)]
    {
        const KEY_SET_VALUE: u32 = 0x0002;
        const REG_SZ: u32 = 1;
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let data_w = to_wide(data);
        let mut hkey: isize = 0;
        let mut disp: u32 = 0;
        if unsafe {
            RegCreateKeyExW(
                root,
                sub_w.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut hkey,
                &mut disp,
            )
        } != 0
            || hkey == 0
        {
            return false;
        }
        let rc = unsafe {
            RegSetValueExW(
                hkey,
                val_w.as_ptr(),
                0,
                REG_SZ,
                data_w.as_ptr() as *const u8,
                (data_w.len() * 2) as u32,
            )
        };
        unsafe { RegCloseKey(hkey) };
        rc == 0
    }
    #[cfg(not(windows))]
    {
        let _ = (root, subkey, value_name, data);
        false
    }
}

/// Sets a `REG_DWORD` value in the Windows registry.
pub fn reg_set_dword(root: isize, subkey: &str, value_name: &str, data: u32) -> bool {
    #[cfg(windows)]
    {
        const KEY_SET_VALUE: u32 = 0x0002;
        const REG_DWORD: u32 = 4;
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let mut hkey: isize = 0;
        let mut disp: u32 = 0;
        if unsafe {
            RegCreateKeyExW(
                root,
                sub_w.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut hkey,
                &mut disp,
            )
        } != 0
            || hkey == 0
        {
            return false;
        }
        let bytes = data.to_le_bytes();
        let rc = unsafe {
            RegSetValueExW(hkey, val_w.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4)
        };
        unsafe { RegCloseKey(hkey) };
        rc == 0
    }
    #[cfg(not(windows))]
    {
        let _ = (root, subkey, value_name, data);
        false
    }
}

/// Deletes a registry value if present.
pub fn reg_delete_value(root: isize, subkey: &str, value_name: &str) -> bool {
    #[cfg(windows)]
    {
        const KEY_SET_VALUE: u32 = 0x0002;
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let mut hkey: isize = 0;
        if unsafe { RegOpenKeyExW(root, sub_w.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) } != 0
            || hkey == 0
        {
            return false;
        }
        let rc = unsafe { RegDeleteValueW(hkey, val_w.as_ptr()) };
        unsafe { RegCloseKey(hkey) };
        rc == 0
    }
    #[cfg(not(windows))]
    {
        let _ = (root, subkey, value_name);
        false
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct ServiceStatus {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(
        lpMachineName: *const u16,
        lpDatabaseName: *const u16,
        dwDesiredAccess: u32,
    ) -> isize;
    fn OpenServiceW(hSCManager: isize, lpServiceName: *const u16, dwDesiredAccess: u32) -> isize;
    fn StartServiceW(
        hService: isize,
        dwNumServiceArgs: u32,
        lpServiceArgVectors: *const *const u16,
    ) -> i32;
    fn ControlService(
        hService: isize,
        dwControl: u32,
        lpServiceStatus: *mut ServiceStatus,
    ) -> i32;
    fn DeleteService(hService: isize) -> i32;
    fn CloseServiceHandle(hSCObject: isize) -> i32;
}

#[cfg(windows)]
fn with_service<F, R>(name: &str, access: u32, f: F) -> Option<R>
where
    F: FnOnce(isize) -> R,
{
    const SC_MANAGER_CONNECT: u32 = 0x0001;
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm == 0 {
        return None;
    }
    let name_w = to_wide(name);
    let svc = unsafe { OpenServiceW(scm, name_w.as_ptr(), access) };
    if svc == 0 {
        unsafe { CloseServiceHandle(scm) };
        return None;
    }
    let out = f(svc);
    unsafe {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
    Some(out)
}

/// Starts an installed Windows service (`true` if started or already running).
pub fn service_start(name: &str) -> bool {
    #[cfg(windows)]
    {
        const SERVICE_START: u32 = 0x0010;
        const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
        with_service(name, SERVICE_START, |svc| {
            let ok = unsafe { StartServiceW(svc, 0, std::ptr::null()) } != 0;
            if ok {
                true
            } else {
                std::io::Error::last_os_error().raw_os_error()
                    == Some(ERROR_SERVICE_ALREADY_RUNNING)
            }
        })
        .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        false
    }
}

/// Sends `SERVICE_CONTROL_STOP` to a Windows service via SCM.
pub fn service_stop(name: &str) -> bool {
    #[cfg(windows)]
    {
        const SERVICE_STOP: u32 = 0x0020;
        const SERVICE_CONTROL_STOP: u32 = 1;
        with_service(name, SERVICE_STOP, |svc| {
            let mut st = ServiceStatus::default();
            unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut st) != 0 }
        })
        .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        false
    }
}

/// Marks a Windows service for deletion via `DeleteService`.
pub fn service_delete(name: &str) -> bool {
    #[cfg(windows)]
    {
        const DELETE: u32 = 0x00010000;
        with_service(name, DELETE, |svc| unsafe { DeleteService(svc) != 0 }).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_entry_layout_and_live_snapshot() {
        #[cfg(all(windows, target_pointer_width = "64"))]
        assert_eq!(std::mem::size_of::<ProcessEntry32W>(), 568);

        #[cfg(windows)]
        {
            // System process / svchost is always running on Windows
            assert!(is_process_running("svchost.exe"));
            let found = find_running_exes(&["svchost.exe", "nonexistent_proc_xyz_123.exe"]);
            assert_eq!(found, vec!["svchost.exe"]);
        }
    }

    #[test]
    fn test_reg_value_exists_safe_read() {
        #[cfg(windows)]
        {
            assert!(reg_value_exists(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "ProductName"
            ));
            assert!(!reg_value_exists(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "DefinitelyNonExistentValueXYZ123"
            ));
        }
    }
}
