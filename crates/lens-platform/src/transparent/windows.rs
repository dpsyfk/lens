//! Windows WFP management and redirect-context adapter.

use std::io;
use std::ptr::{null, null_mut};

use windows_sys::core::{w, GUID, PWSTR};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSAIoctl, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::Win32::System::IO::DeviceIoControl;

use super::{
    RedirectContext, TransparentConfig, TransparentDriverStatus, TransparentError, CONFIG_SIZE,
    REDIRECT_CONTEXT_SIZE, STATUS_SIZE,
};

const PROVIDER_KEY: GUID = GUID::from_u128(0x5623e61b_b8d4_4c98_a379_6fee58f42c10);
const CALLOUT_V4_KEY: GUID = GUID::from_u128(0xc3aefc98_e967_45bf_9cda_86b6d84369f4);
const CALLOUT_V6_KEY: GUID = GUID::from_u128(0x6c557e87_754d_4dc9_86cf_c2131ce8c0d5);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x4d34a992_6aed_4d70_9bd8_3e75f3c42239);
const FILTER_V4_KEY: GUID = GUID::from_u128(0x5d1fa442_480a_4e06_b8a5_7a195d724ab9);
const FILTER_V6_KEY: GUID = GUID::from_u128(0x04ab74ba_d224_4ed2_bee1_53e5e1d7c8af);

const FILE_READ_WRITE_ACCESS: u32 = 3;
const METHOD_BUFFERED: u32 = 0;
const DEVICE_TYPE: u32 = 0x8337;
const fn ctl_code(function: u32) -> u32 {
    (DEVICE_TYPE << 16) | (FILE_READ_WRITE_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
}
const IOCTL_CONFIGURE: u32 = ctl_code(0x900);
const IOCTL_DISABLE: u32 = ctl_code(0x901);
const IOCTL_STATUS: u32 = (DEVICE_TYPE << 16) | (1 << 14) | (0x902 << 2) | METHOD_BUFFERED;

/// Owns both the driver control handle and a dynamic WFP engine session.
pub(super) struct WindowsWfpSession {
    device: HANDLE,
    engine: HANDLE,
}

impl WindowsWfpSession {
    pub(super) fn activate(config: TransparentConfig) -> Result<Self, TransparentError> {
        let device = open_device()?;
        let engine = match open_engine() {
            Ok(engine) => engine,
            Err(error) => {
                unsafe { CloseHandle(device) };
                return Err(error);
            }
        };
        let session = Self { device, engine };
        if let Err(error) = session.install_dynamic_policy() {
            return Err(error);
        }
        session.ioctl_input(IOCTL_CONFIGURE, &config.encode())?;
        let status = session.driver_status()?;
        if !status.active || status.generation != u64::from(config.generation) {
            return Err(TransparentError::new(
                "WFP driver did not acknowledge the active generation",
            ));
        }
        Ok(session)
    }

    fn install_dynamic_policy(&self) -> Result<(), TransparentError> {
        win32("begin WFP transaction", unsafe {
            FwpmTransactionBegin0(self.engine, 0)
        })?;
        let result = self.add_policy_objects();
        if let Err(error) = result {
            unsafe { FwpmTransactionAbort0(self.engine) };
            return Err(error);
        }
        win32("commit WFP transaction", unsafe {
            FwpmTransactionCommit0(self.engine)
        })
    }

    fn add_policy_objects(&self) -> Result<(), TransparentError> {
        let mut provider_name = wide("Lens transparent provider");
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display(&mut provider_name),
            ..Default::default()
        };
        win32("add WFP provider", unsafe {
            FwpmProviderAdd0(self.engine, &provider, null_mut())
        })?;

        let mut provider_key = PROVIDER_KEY;
        let mut sublayer_name = wide("Lens transparent redirect");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display(&mut sublayer_name),
            providerKey: &mut provider_key,
            weight: 0x100,
            ..Default::default()
        };
        win32("add WFP sublayer", unsafe {
            FwpmSubLayerAdd0(self.engine, &sublayer, null_mut())
        })?;

        self.add_callout(
            CALLOUT_V4_KEY,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
            "Lens IPv4 connect redirect",
        )?;
        self.add_callout(
            CALLOUT_V6_KEY,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
            "Lens IPv6 connect redirect",
        )?;
        self.add_filter(
            FILTER_V4_KEY,
            CALLOUT_V4_KEY,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
            "Lens IPv4 transparent TCP",
        )?;
        self.add_filter(
            FILTER_V6_KEY,
            CALLOUT_V6_KEY,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
            "Lens IPv6 transparent TCP",
        )
    }

    fn add_callout(&self, key: GUID, layer: GUID, name: &str) -> Result<(), TransparentError> {
        let mut provider_key = PROVIDER_KEY;
        let mut name = wide(name);
        let callout = FWPM_CALLOUT0 {
            calloutKey: key,
            displayData: display(&mut name),
            providerKey: &mut provider_key,
            applicableLayer: layer,
            ..Default::default()
        };
        win32("add WFP callout", unsafe {
            FwpmCalloutAdd0(self.engine, &callout, null_mut(), null_mut())
        })
    }

    fn add_filter(
        &self,
        key: GUID,
        callout_key: GUID,
        layer: GUID,
        name: &str,
    ) -> Result<(), TransparentError> {
        let mut provider_key = PROVIDER_KEY;
        let mut name = wide(name);
        let mut condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 6 },
            },
        };
        let filter = FWPM_FILTER0 {
            filterKey: key,
            displayData: display(&mut name),
            flags: FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED,
            providerKey: &mut provider_key,
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            numFilterConditions: 1,
            filterCondition: &mut condition,
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: callout_key,
                },
            },
            ..Default::default()
        };
        win32("add WFP filter", unsafe {
            FwpmFilterAdd0(self.engine, &filter, null_mut(), null_mut())
        })
    }

    fn driver_status(&self) -> Result<TransparentDriverStatus, TransparentError> {
        let mut bytes = [0_u8; STATUS_SIZE as usize];
        self.ioctl_output(IOCTL_STATUS, &mut bytes)?;
        TransparentDriverStatus::decode(&bytes)
    }

    fn ioctl_input(&self, code: u32, bytes: &[u8]) -> Result<(), TransparentError> {
        debug_assert_eq!(bytes.len(), CONFIG_SIZE as usize);
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device,
                code,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        bool_result("configure WFP driver", ok)
    }

    fn ioctl_output(&self, code: u32, bytes: &mut [u8]) -> Result<(), TransparentError> {
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device,
                code,
                null(),
                0,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                &mut returned,
                null_mut(),
            )
        };
        bool_result("query WFP driver", ok)?;
        if returned as usize != bytes.len() {
            return Err(TransparentError::new(
                "WFP driver returned an unexpected record size",
            ));
        }
        Ok(())
    }
}

impl Drop for WindowsWfpSession {
    fn drop(&mut self) {
        let mut returned = 0;
        unsafe {
            DeviceIoControl(
                self.device,
                IOCTL_DISABLE,
                null(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            );
            CloseHandle(self.device);
            FwpmEngineClose0(self.engine);
        }
    }
}

pub(super) fn redirect_context(raw_socket: usize) -> Result<RedirectContext, TransparentError> {
    let mut bytes = [0_u8; REDIRECT_CONTEXT_SIZE as usize];
    let mut returned = 0;
    let result = unsafe {
        WSAIoctl(
            raw_socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            null(),
            0,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            &mut returned,
            null_mut(),
            None,
        )
    };
    if result != 0 {
        return Err(TransparentError::new(format!(
            "query WFP redirect context failed ({})",
            unsafe { WSAGetLastError() }
        )));
    }
    if returned as usize != bytes.len() {
        return Err(TransparentError::new(
            "WFP redirect context has an unexpected size",
        ));
    }
    RedirectContext::decode(&bytes)
}

fn open_device() -> Result<HANDLE, TransparentError> {
    let handle = unsafe {
        CreateFileW(
            w!(r"\\.\LensWfp"),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error(
            "open Lens WFP driver; install and start the signed driver first",
        ));
    }
    Ok(handle)
}

fn open_engine() -> Result<HANDLE, TransparentError> {
    let mut name = wide("Lens transparent session");
    let session = FWPM_SESSION0 {
        displayData: display(&mut name),
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        txnWaitTimeoutInMSec: 5_000,
        ..Default::default()
    };
    let mut handle = null_mut();
    win32("open WFP engine", unsafe {
        FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle)
    })?;
    Ok(handle)
}

fn display(name: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr() as PWSTR,
        description: null_mut(),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn win32(operation: &str, code: u32) -> Result<(), TransparentError> {
    if code == 0 {
        Ok(())
    } else {
        Err(TransparentError::new(format!(
            "{operation} failed (0x{code:08x})"
        )))
    }
}

fn bool_result(operation: &str, ok: i32) -> Result<(), TransparentError> {
    if ok != 0 {
        Ok(())
    } else {
        Err(last_error(operation))
    }
}

fn last_error(operation: &str) -> TransparentError {
    let code = unsafe { GetLastError() };
    TransparentError::new(format!(
        "{operation} failed ({})",
        io::Error::from_raw_os_error(code as i32)
    ))
}
