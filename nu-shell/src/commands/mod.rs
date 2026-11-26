//! Helios-native async commands and async-aware Nushell combinators.

pub mod component;
pub mod container;
pub mod external;
pub mod fs;
pub mod http;
pub mod linux;
pub mod oci;
pub mod process;
pub mod random;
pub mod storage;
pub mod sys;
pub mod vm;

use core::future::Future;
use core::pin::Pin;

use nu_engine::CallExt;
use nu_protocol::engine::{Closure, StateWorkingSet};
use nu_protocol::{Category, Record, ShellError, Signature, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext, AsyncCommandRegistry};
use crate::env::HeliosEnv;
use crate::eval::eval_closure_async;
use crate::pipeline::{AsyncPipelineData, collect_byte_receiver};

/// Concrete dispatch enum of every built-in Helios async command (no dynamic dispatch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncBuiltin {
    // External execution & grants
    RunExternal,
    WithGrants,
    Which,
    // System telemetry
    Sys,
    SysCpu,
    SysMem,
    SysNet,
    SysDisks,
    SysHost,
    // Processes, inspection, scopes, snapshots, profiling
    Inspect,
    Ps,
    Kill,
    Whoami,
    Sleep,
    Clear,
    WithScope,
    WithSnapshot,
    WithInstructionProfile,
    // Capability-bounded VFS
    Cd,
    Ls,
    Open,
    Save,
    Mkdir,
    Rm,
    Cp,
    Mv,
    Touch,
    Glob,
    Watch,
    // HTTP (zenwave)
    Http,
    HttpGet,
    HttpPost,
    HttpPut,
    HttpPatch,
    HttpDelete,
    HttpHead,
    HttpOptions,
    // CSPRNG random
    Random,
    RandomInt,
    RandomFloat,
    RandomBool,
    RandomChars,
    RandomBinary,
    RandomUuid,
    // Linux default image
    Linux,
    LinuxImage,
    LinuxImageGet,
    LinuxImageSet,
    LinuxImageClear,
    // Component topology
    Component,
    ComponentLs,
    ComponentStatus,
    ComponentStart,
    ComponentStop,
    ComponentRestart,
    ComponentAdd,
    ComponentRm,
    // OCI image store
    Oci,
    OciPull,
    OciLs,
    OciInspect,
    OciRm,
    // Linux containers
    Container,
    ContainerCreate,
    ContainerLs,
    ContainerExec,
    ContainerSpawn,
    ContainerRm,
    WithContainer,
    // Storage: mount, umount, btrfs
    Mount,
    Umount,
    Btrfs,
    BtrfsSubvolume,
    BtrfsSubvolumeCreate,
    BtrfsSubvolumeDelete,
    BtrfsSubvolumeSnapshot,
    BtrfsSubvolumeList,
    BtrfsSubvolumeShow,
    BtrfsSubvolumeSetRo,
    BtrfsSubvolumeSend,
    BtrfsSubvolumeReceive,
    // Micro-VMs
    Vm,
    VmRun,
    VmLs,
    // Async-capable combinators so closures can call async commands without block_on
    Do,
    Each,
    ParEach,
    Where,
    WithEnv,
    Complete,
    Print,
}

impl AsyncBuiltin {
    /// All built-in async commands registered into a Helios Nushell [`EngineState`].
    pub const ALL: &'static [Self] = &[
        Self::RunExternal,
        Self::WithGrants,
        Self::Which,
        Self::Sys,
        Self::SysCpu,
        Self::SysMem,
        Self::SysNet,
        Self::SysDisks,
        Self::SysHost,
        Self::Inspect,
        Self::Ps,
        Self::Kill,
        Self::Whoami,
        Self::Sleep,
        Self::Clear,
        Self::WithScope,
        Self::WithSnapshot,
        Self::WithInstructionProfile,
        Self::Cd,
        Self::Ls,
        Self::Open,
        Self::Save,
        Self::Mkdir,
        Self::Rm,
        Self::Cp,
        Self::Mv,
        Self::Touch,
        Self::Glob,
        Self::Watch,
        Self::Http,
        Self::HttpGet,
        Self::HttpPost,
        Self::HttpPut,
        Self::HttpPatch,
        Self::HttpDelete,
        Self::HttpHead,
        Self::HttpOptions,
        Self::Random,
        Self::RandomInt,
        Self::RandomFloat,
        Self::RandomBool,
        Self::RandomChars,
        Self::RandomBinary,
        Self::RandomUuid,
        Self::Linux,
        Self::LinuxImage,
        Self::LinuxImageGet,
        Self::LinuxImageSet,
        Self::LinuxImageClear,
        Self::Component,
        Self::ComponentLs,
        Self::ComponentStatus,
        Self::ComponentStart,
        Self::ComponentStop,
        Self::ComponentRestart,
        Self::ComponentAdd,
        Self::ComponentRm,
        Self::Oci,
        Self::OciPull,
        Self::OciLs,
        Self::OciInspect,
        Self::OciRm,
        Self::Container,
        Self::ContainerCreate,
        Self::ContainerLs,
        Self::ContainerExec,
        Self::ContainerSpawn,
        Self::ContainerRm,
        Self::WithContainer,
        Self::Mount,
        Self::Umount,
        Self::Btrfs,
        Self::BtrfsSubvolume,
        Self::BtrfsSubvolumeCreate,
        Self::BtrfsSubvolumeDelete,
        Self::BtrfsSubvolumeSnapshot,
        Self::BtrfsSubvolumeList,
        Self::BtrfsSubvolumeShow,
        Self::BtrfsSubvolumeSetRo,
        Self::BtrfsSubvolumeSend,
        Self::BtrfsSubvolumeReceive,
        Self::Vm,
        Self::VmRun,
        Self::VmLs,
        Self::Do,
        Self::Each,
        Self::ParEach,
        Self::Where,
        Self::WithEnv,
        Self::Complete,
        Self::Print,
    ];

    /// Command name as registered in Nushell.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RunExternal => "run-external",
            Self::WithGrants => "with-grants",
            Self::Which => "which",
            Self::Sys => "sys",
            Self::SysCpu => "sys cpu",
            Self::SysMem => "sys mem",
            Self::SysNet => "sys net",
            Self::SysDisks => "sys disks",
            Self::SysHost => "sys host",
            Self::Inspect => "inspect",
            Self::Ps => "ps",
            Self::Kill => "kill",
            Self::Whoami => "whoami",
            Self::Sleep => "sleep",
            Self::Clear => "clear",
            Self::WithScope => "with-scope",
            Self::WithSnapshot => "with-snapshot",
            Self::WithInstructionProfile => "with-instruction-profile",
            Self::Cd => "cd",
            Self::Ls => "ls",
            Self::Open => "open",
            Self::Save => "save",
            Self::Mkdir => "mkdir",
            Self::Rm => "rm",
            Self::Cp => "cp",
            Self::Mv => "mv",
            Self::Touch => "touch",
            Self::Glob => "glob",
            Self::Watch => "watch",
            Self::Http => "http",
            Self::HttpGet => "http get",
            Self::HttpPost => "http post",
            Self::HttpPut => "http put",
            Self::HttpPatch => "http patch",
            Self::HttpDelete => "http delete",
            Self::HttpHead => "http head",
            Self::HttpOptions => "http options",
            Self::Random => "random",
            Self::RandomInt => "random int",
            Self::RandomFloat => "random float",
            Self::RandomBool => "random bool",
            Self::RandomChars => "random chars",
            Self::RandomBinary => "random binary",
            Self::RandomUuid => "random uuid",
            Self::Linux => "linux",
            Self::LinuxImage => "linux image",
            Self::LinuxImageGet => "linux image get",
            Self::LinuxImageSet => "linux image set",
            Self::LinuxImageClear => "linux image clear",
            Self::Component => "component",
            Self::ComponentLs => "component ls",
            Self::ComponentStatus => "component status",
            Self::ComponentStart => "component start",
            Self::ComponentStop => "component stop",
            Self::ComponentRestart => "component restart",
            Self::ComponentAdd => "component add",
            Self::ComponentRm => "component rm",
            Self::Oci => "oci",
            Self::OciPull => "oci pull",
            Self::OciLs => "oci ls",
            Self::OciInspect => "oci inspect",
            Self::OciRm => "oci rm",
            Self::Container => "container",
            Self::ContainerCreate => "container create",
            Self::ContainerLs => "container ls",
            Self::ContainerExec => "container exec",
            Self::ContainerSpawn => "container spawn",
            Self::ContainerRm => "container rm",
            Self::WithContainer => "with-container",
            Self::Mount => "mount",
            Self::Umount => "umount",
            Self::Btrfs => "btrfs",
            Self::BtrfsSubvolume => "btrfs subvolume",
            Self::BtrfsSubvolumeCreate => "btrfs subvolume create",
            Self::BtrfsSubvolumeDelete => "btrfs subvolume delete",
            Self::BtrfsSubvolumeSnapshot => "btrfs subvolume snapshot",
            Self::BtrfsSubvolumeList => "btrfs subvolume list",
            Self::BtrfsSubvolumeShow => "btrfs subvolume show",
            Self::BtrfsSubvolumeSetRo => "btrfs subvolume set-ro",
            Self::BtrfsSubvolumeSend => "btrfs subvolume send",
            Self::BtrfsSubvolumeReceive => "btrfs subvolume receive",
            Self::Vm => "vm",
            Self::VmRun => "vm run",
            Self::VmLs => "vm ls",
            Self::Do => "do",
            Self::Each => "each",
            Self::ParEach => "par-each",
            Self::Where => "where",
            Self::WithEnv => "with-env",
            Self::Complete => "complete",
            Self::Print => "print",
        }
    }

    /// Signature of this built-in command.
    #[must_use]
    pub fn signature(self) -> Signature {
        // Dispatch via a zero-sized marker env type because signatures are env-independent.
        self.signature_for::<SignatureOnlyEnv>()
    }

    fn signature_for<E: HeliosEnv>(self) -> Signature {
        match self {
            Self::RunExternal => {
                <external::RunExternal as AsyncCommand<E>>::signature(&external::RunExternal)
            }
            Self::WithGrants => {
                <external::WithGrants as AsyncCommand<E>>::signature(&external::WithGrants)
            }
            Self::Which => <external::Which as AsyncCommand<E>>::signature(&external::Which),
            Self::Sys => <sys::Sys as AsyncCommand<E>>::signature(&sys::Sys),
            Self::SysCpu => <sys::SysCpu as AsyncCommand<E>>::signature(&sys::SysCpu),
            Self::SysMem => <sys::SysMem as AsyncCommand<E>>::signature(&sys::SysMem),
            Self::SysNet => <sys::SysNet as AsyncCommand<E>>::signature(&sys::SysNet),
            Self::SysDisks => <sys::SysDisks as AsyncCommand<E>>::signature(&sys::SysDisks),
            Self::SysHost => <sys::SysHost as AsyncCommand<E>>::signature(&sys::SysHost),
            Self::Inspect => {
                <process::HeliosInspect as AsyncCommand<E>>::signature(&process::HeliosInspect)
            }
            Self::Ps => <process::Ps as AsyncCommand<E>>::signature(&process::Ps),
            Self::Kill => <process::Kill as AsyncCommand<E>>::signature(&process::Kill),
            Self::Whoami => <process::Whoami as AsyncCommand<E>>::signature(&process::Whoami),
            Self::Sleep => <process::Sleep as AsyncCommand<E>>::signature(&process::Sleep),
            Self::Clear => <process::Clear as AsyncCommand<E>>::signature(&process::Clear),
            Self::WithScope => {
                <process::WithScope as AsyncCommand<E>>::signature(&process::WithScope)
            }
            Self::WithSnapshot => {
                <process::WithSnapshot as AsyncCommand<E>>::signature(&process::WithSnapshot)
            }
            Self::WithInstructionProfile => {
                <process::WithInstructionProfile as AsyncCommand<E>>::signature(
                    &process::WithInstructionProfile,
                )
            }
            Self::Cd => <fs::Cd as AsyncCommand<E>>::signature(&fs::Cd),
            Self::Ls => <fs::Ls as AsyncCommand<E>>::signature(&fs::Ls),
            Self::Open => <fs::Open as AsyncCommand<E>>::signature(&fs::Open),
            Self::Save => <fs::Save as AsyncCommand<E>>::signature(&fs::Save),
            Self::Mkdir => <fs::Mkdir as AsyncCommand<E>>::signature(&fs::Mkdir),
            Self::Rm => <fs::Rm as AsyncCommand<E>>::signature(&fs::Rm),
            Self::Cp => <fs::Cp as AsyncCommand<E>>::signature(&fs::Cp),
            Self::Mv => <fs::Mv as AsyncCommand<E>>::signature(&fs::Mv),
            Self::Touch => <fs::Touch as AsyncCommand<E>>::signature(&fs::Touch),
            Self::Glob => <fs::Glob as AsyncCommand<E>>::signature(&fs::Glob),
            Self::Watch => <fs::Watch as AsyncCommand<E>>::signature(&fs::Watch),
            Self::Http => <http::Http as AsyncCommand<E>>::signature(&http::Http),
            Self::HttpGet => <http::HttpGet as AsyncCommand<E>>::signature(&http::HttpGet),
            Self::HttpPost => <http::HttpPost as AsyncCommand<E>>::signature(&http::HttpPost),
            Self::HttpPut => <http::HttpPut as AsyncCommand<E>>::signature(&http::HttpPut),
            Self::HttpPatch => <http::HttpPatch as AsyncCommand<E>>::signature(&http::HttpPatch),
            Self::HttpDelete => <http::HttpDelete as AsyncCommand<E>>::signature(&http::HttpDelete),
            Self::HttpHead => <http::HttpHead as AsyncCommand<E>>::signature(&http::HttpHead),
            Self::HttpOptions => {
                <http::HttpOptions as AsyncCommand<E>>::signature(&http::HttpOptions)
            }
            Self::Random => <random::Random as AsyncCommand<E>>::signature(&random::Random),
            Self::RandomInt => {
                <random::RandomInt as AsyncCommand<E>>::signature(&random::RandomInt)
            }
            Self::RandomFloat => {
                <random::RandomFloat as AsyncCommand<E>>::signature(&random::RandomFloat)
            }
            Self::RandomBool => {
                <random::RandomBool as AsyncCommand<E>>::signature(&random::RandomBool)
            }
            Self::RandomChars => {
                <random::RandomChars as AsyncCommand<E>>::signature(&random::RandomChars)
            }
            Self::RandomBinary => {
                <random::RandomBinary as AsyncCommand<E>>::signature(&random::RandomBinary)
            }
            Self::RandomUuid => {
                <random::RandomUuid as AsyncCommand<E>>::signature(&random::RandomUuid)
            }
            Self::Linux => <linux::Linux as AsyncCommand<E>>::signature(&linux::Linux),
            Self::LinuxImage => {
                <linux::LinuxImage as AsyncCommand<E>>::signature(&linux::LinuxImage)
            }
            Self::LinuxImageGet => {
                <linux::LinuxImageGet as AsyncCommand<E>>::signature(&linux::LinuxImageGet)
            }
            Self::LinuxImageSet => {
                <linux::LinuxImageSet as AsyncCommand<E>>::signature(&linux::LinuxImageSet)
            }
            Self::LinuxImageClear => {
                <linux::LinuxImageClear as AsyncCommand<E>>::signature(&linux::LinuxImageClear)
            }
            Self::Component => {
                <component::Component as AsyncCommand<E>>::signature(&component::Component)
            }
            Self::ComponentLs => {
                <component::ComponentLs as AsyncCommand<E>>::signature(&component::ComponentLs)
            }
            Self::ComponentStatus => <component::ComponentStatus as AsyncCommand<E>>::signature(
                &component::ComponentStatus,
            ),
            Self::ComponentStart => <component::ComponentStart as AsyncCommand<E>>::signature(
                &component::ComponentStart,
            ),
            Self::ComponentStop => {
                <component::ComponentStop as AsyncCommand<E>>::signature(&component::ComponentStop)
            }
            Self::ComponentRestart => <component::ComponentRestart as AsyncCommand<E>>::signature(
                &component::ComponentRestart,
            ),
            Self::ComponentAdd => {
                <component::ComponentAdd as AsyncCommand<E>>::signature(&component::ComponentAdd)
            }
            Self::ComponentRm => {
                <component::ComponentRm as AsyncCommand<E>>::signature(&component::ComponentRm)
            }
            Self::Oci => <oci::Oci as AsyncCommand<E>>::signature(&oci::Oci),
            Self::OciPull => <oci::OciPull as AsyncCommand<E>>::signature(&oci::OciPull),
            Self::OciLs => <oci::OciLs as AsyncCommand<E>>::signature(&oci::OciLs),
            Self::OciInspect => <oci::OciInspect as AsyncCommand<E>>::signature(&oci::OciInspect),
            Self::OciRm => <oci::OciRm as AsyncCommand<E>>::signature(&oci::OciRm),
            Self::Container => {
                <container::Container as AsyncCommand<E>>::signature(&container::Container)
            }
            Self::ContainerCreate => <container::ContainerCreate as AsyncCommand<E>>::signature(
                &container::ContainerCreate,
            ),
            Self::ContainerLs => {
                <container::ContainerLs as AsyncCommand<E>>::signature(&container::ContainerLs)
            }
            Self::ContainerExec => {
                <container::ContainerExec as AsyncCommand<E>>::signature(&container::ContainerExec)
            }
            Self::ContainerSpawn => <container::ContainerSpawn as AsyncCommand<E>>::signature(
                &container::ContainerSpawn,
            ),
            Self::ContainerRm => {
                <container::ContainerRm as AsyncCommand<E>>::signature(&container::ContainerRm)
            }
            Self::WithContainer => {
                <container::WithContainer as AsyncCommand<E>>::signature(&container::WithContainer)
            }
            Self::Mount => <storage::Mount as AsyncCommand<E>>::signature(&storage::Mount),
            Self::Umount => <storage::Umount as AsyncCommand<E>>::signature(&storage::Umount),
            Self::Btrfs => <storage::Btrfs as AsyncCommand<E>>::signature(&storage::Btrfs),
            Self::BtrfsSubvolume => {
                <storage::BtrfsSubvolume as AsyncCommand<E>>::signature(&storage::BtrfsSubvolume)
            }
            Self::BtrfsSubvolumeCreate => {
                <storage::BtrfsSubvolumeCreate as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeCreate,
                )
            }
            Self::BtrfsSubvolumeDelete => {
                <storage::BtrfsSubvolumeDelete as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeDelete,
                )
            }
            Self::BtrfsSubvolumeSnapshot => {
                <storage::BtrfsSubvolumeSnapshot as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeSnapshot,
                )
            }
            Self::BtrfsSubvolumeList => {
                <storage::BtrfsSubvolumeList as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeList,
                )
            }
            Self::BtrfsSubvolumeShow => {
                <storage::BtrfsSubvolumeShow as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeShow,
                )
            }
            Self::BtrfsSubvolumeSetRo => {
                <storage::BtrfsSubvolumeSetRo as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeSetRo,
                )
            }
            Self::BtrfsSubvolumeSend => {
                <storage::BtrfsSubvolumeSend as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeSend,
                )
            }
            Self::BtrfsSubvolumeReceive => {
                <storage::BtrfsSubvolumeReceive as AsyncCommand<E>>::signature(
                    &storage::BtrfsSubvolumeReceive,
                )
            }
            Self::Vm => <vm::Vm as AsyncCommand<E>>::signature(&vm::Vm),
            Self::VmRun => <vm::VmRun as AsyncCommand<E>>::signature(&vm::VmRun),
            Self::VmLs => <vm::VmLs as AsyncCommand<E>>::signature(&vm::VmLs),
            Self::Do => <AsyncDo as AsyncCommand<E>>::signature(&AsyncDo),
            Self::Each => <AsyncEach as AsyncCommand<E>>::signature(&AsyncEach),
            Self::ParEach => <AsyncParEach as AsyncCommand<E>>::signature(&AsyncParEach),
            Self::Where => <AsyncWhere as AsyncCommand<E>>::signature(&AsyncWhere),
            Self::WithEnv => <AsyncWithEnv as AsyncCommand<E>>::signature(&AsyncWithEnv),
            Self::Complete => <AsyncComplete as AsyncCommand<E>>::signature(&AsyncComplete),
            Self::Print => <AsyncPrint as AsyncCommand<E>>::signature(&AsyncPrint),
        }
    }

    #[must_use]
    pub fn description(self) -> &'static str {
        self.description_for::<SignatureOnlyEnv>()
    }

    fn description_for<E: HeliosEnv>(self) -> &'static str {
        match self {
            Self::RunExternal => {
                <external::RunExternal as AsyncCommand<E>>::description(&external::RunExternal)
            }
            Self::WithGrants => {
                <external::WithGrants as AsyncCommand<E>>::description(&external::WithGrants)
            }
            Self::Which => <external::Which as AsyncCommand<E>>::description(&external::Which),
            Self::Sys => <sys::Sys as AsyncCommand<E>>::description(&sys::Sys),
            Self::SysCpu => <sys::SysCpu as AsyncCommand<E>>::description(&sys::SysCpu),
            Self::SysMem => <sys::SysMem as AsyncCommand<E>>::description(&sys::SysMem),
            Self::SysNet => <sys::SysNet as AsyncCommand<E>>::description(&sys::SysNet),
            Self::SysDisks => <sys::SysDisks as AsyncCommand<E>>::description(&sys::SysDisks),
            Self::SysHost => <sys::SysHost as AsyncCommand<E>>::description(&sys::SysHost),
            Self::Inspect => {
                <process::HeliosInspect as AsyncCommand<E>>::description(&process::HeliosInspect)
            }
            Self::Ps => <process::Ps as AsyncCommand<E>>::description(&process::Ps),
            Self::Kill => <process::Kill as AsyncCommand<E>>::description(&process::Kill),
            Self::Whoami => <process::Whoami as AsyncCommand<E>>::description(&process::Whoami),
            Self::Sleep => <process::Sleep as AsyncCommand<E>>::description(&process::Sleep),
            Self::Clear => <process::Clear as AsyncCommand<E>>::description(&process::Clear),
            Self::WithScope => {
                <process::WithScope as AsyncCommand<E>>::description(&process::WithScope)
            }
            Self::WithSnapshot => {
                <process::WithSnapshot as AsyncCommand<E>>::description(&process::WithSnapshot)
            }
            Self::WithInstructionProfile => {
                <process::WithInstructionProfile as AsyncCommand<E>>::description(
                    &process::WithInstructionProfile,
                )
            }
            Self::Cd => <fs::Cd as AsyncCommand<E>>::description(&fs::Cd),
            Self::Ls => <fs::Ls as AsyncCommand<E>>::description(&fs::Ls),
            Self::Open => <fs::Open as AsyncCommand<E>>::description(&fs::Open),
            Self::Save => <fs::Save as AsyncCommand<E>>::description(&fs::Save),
            Self::Mkdir => <fs::Mkdir as AsyncCommand<E>>::description(&fs::Mkdir),
            Self::Rm => <fs::Rm as AsyncCommand<E>>::description(&fs::Rm),
            Self::Cp => <fs::Cp as AsyncCommand<E>>::description(&fs::Cp),
            Self::Mv => <fs::Mv as AsyncCommand<E>>::description(&fs::Mv),
            Self::Touch => <fs::Touch as AsyncCommand<E>>::description(&fs::Touch),
            Self::Glob => <fs::Glob as AsyncCommand<E>>::description(&fs::Glob),
            Self::Watch => <fs::Watch as AsyncCommand<E>>::description(&fs::Watch),
            Self::Http => <http::Http as AsyncCommand<E>>::description(&http::Http),
            Self::HttpGet => <http::HttpGet as AsyncCommand<E>>::description(&http::HttpGet),
            Self::HttpPost => <http::HttpPost as AsyncCommand<E>>::description(&http::HttpPost),
            Self::HttpPut => <http::HttpPut as AsyncCommand<E>>::description(&http::HttpPut),
            Self::HttpPatch => <http::HttpPatch as AsyncCommand<E>>::description(&http::HttpPatch),
            Self::HttpDelete => {
                <http::HttpDelete as AsyncCommand<E>>::description(&http::HttpDelete)
            }
            Self::HttpHead => <http::HttpHead as AsyncCommand<E>>::description(&http::HttpHead),
            Self::HttpOptions => {
                <http::HttpOptions as AsyncCommand<E>>::description(&http::HttpOptions)
            }
            Self::Random => <random::Random as AsyncCommand<E>>::description(&random::Random),
            Self::RandomInt => {
                <random::RandomInt as AsyncCommand<E>>::description(&random::RandomInt)
            }
            Self::RandomFloat => {
                <random::RandomFloat as AsyncCommand<E>>::description(&random::RandomFloat)
            }
            Self::RandomBool => {
                <random::RandomBool as AsyncCommand<E>>::description(&random::RandomBool)
            }
            Self::RandomChars => {
                <random::RandomChars as AsyncCommand<E>>::description(&random::RandomChars)
            }
            Self::RandomBinary => {
                <random::RandomBinary as AsyncCommand<E>>::description(&random::RandomBinary)
            }
            Self::RandomUuid => {
                <random::RandomUuid as AsyncCommand<E>>::description(&random::RandomUuid)
            }
            Self::Linux => <linux::Linux as AsyncCommand<E>>::description(&linux::Linux),
            Self::LinuxImage => {
                <linux::LinuxImage as AsyncCommand<E>>::description(&linux::LinuxImage)
            }
            Self::LinuxImageGet => {
                <linux::LinuxImageGet as AsyncCommand<E>>::description(&linux::LinuxImageGet)
            }
            Self::LinuxImageSet => {
                <linux::LinuxImageSet as AsyncCommand<E>>::description(&linux::LinuxImageSet)
            }
            Self::LinuxImageClear => {
                <linux::LinuxImageClear as AsyncCommand<E>>::description(&linux::LinuxImageClear)
            }
            Self::Component => {
                <component::Component as AsyncCommand<E>>::description(&component::Component)
            }
            Self::ComponentLs => {
                <component::ComponentLs as AsyncCommand<E>>::description(&component::ComponentLs)
            }
            Self::ComponentStatus => <component::ComponentStatus as AsyncCommand<E>>::description(
                &component::ComponentStatus,
            ),
            Self::ComponentStart => <component::ComponentStart as AsyncCommand<E>>::description(
                &component::ComponentStart,
            ),
            Self::ComponentStop => <component::ComponentStop as AsyncCommand<E>>::description(
                &component::ComponentStop,
            ),
            Self::ComponentRestart => {
                <component::ComponentRestart as AsyncCommand<E>>::description(
                    &component::ComponentRestart,
                )
            }
            Self::ComponentAdd => {
                <component::ComponentAdd as AsyncCommand<E>>::description(&component::ComponentAdd)
            }
            Self::ComponentRm => {
                <component::ComponentRm as AsyncCommand<E>>::description(&component::ComponentRm)
            }
            Self::Oci => <oci::Oci as AsyncCommand<E>>::description(&oci::Oci),
            Self::OciPull => <oci::OciPull as AsyncCommand<E>>::description(&oci::OciPull),
            Self::OciLs => <oci::OciLs as AsyncCommand<E>>::description(&oci::OciLs),
            Self::OciInspect => <oci::OciInspect as AsyncCommand<E>>::description(&oci::OciInspect),
            Self::OciRm => <oci::OciRm as AsyncCommand<E>>::description(&oci::OciRm),
            Self::Container => {
                <container::Container as AsyncCommand<E>>::description(&container::Container)
            }
            Self::ContainerCreate => <container::ContainerCreate as AsyncCommand<E>>::description(
                &container::ContainerCreate,
            ),
            Self::ContainerLs => {
                <container::ContainerLs as AsyncCommand<E>>::description(&container::ContainerLs)
            }
            Self::ContainerExec => <container::ContainerExec as AsyncCommand<E>>::description(
                &container::ContainerExec,
            ),
            Self::ContainerSpawn => <container::ContainerSpawn as AsyncCommand<E>>::description(
                &container::ContainerSpawn,
            ),
            Self::ContainerRm => {
                <container::ContainerRm as AsyncCommand<E>>::description(&container::ContainerRm)
            }
            Self::WithContainer => <container::WithContainer as AsyncCommand<E>>::description(
                &container::WithContainer,
            ),
            Self::Mount => <storage::Mount as AsyncCommand<E>>::description(&storage::Mount),
            Self::Umount => <storage::Umount as AsyncCommand<E>>::description(&storage::Umount),
            Self::Btrfs => <storage::Btrfs as AsyncCommand<E>>::description(&storage::Btrfs),
            Self::BtrfsSubvolume => {
                <storage::BtrfsSubvolume as AsyncCommand<E>>::description(&storage::BtrfsSubvolume)
            }
            Self::BtrfsSubvolumeCreate => {
                <storage::BtrfsSubvolumeCreate as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeCreate,
                )
            }
            Self::BtrfsSubvolumeDelete => {
                <storage::BtrfsSubvolumeDelete as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeDelete,
                )
            }
            Self::BtrfsSubvolumeSnapshot => {
                <storage::BtrfsSubvolumeSnapshot as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeSnapshot,
                )
            }
            Self::BtrfsSubvolumeList => {
                <storage::BtrfsSubvolumeList as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeList,
                )
            }
            Self::BtrfsSubvolumeShow => {
                <storage::BtrfsSubvolumeShow as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeShow,
                )
            }
            Self::BtrfsSubvolumeSetRo => {
                <storage::BtrfsSubvolumeSetRo as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeSetRo,
                )
            }
            Self::BtrfsSubvolumeSend => {
                <storage::BtrfsSubvolumeSend as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeSend,
                )
            }
            Self::BtrfsSubvolumeReceive => {
                <storage::BtrfsSubvolumeReceive as AsyncCommand<E>>::description(
                    &storage::BtrfsSubvolumeReceive,
                )
            }
            Self::Vm => <vm::Vm as AsyncCommand<E>>::description(&vm::Vm),
            Self::VmRun => <vm::VmRun as AsyncCommand<E>>::description(&vm::VmRun),
            Self::VmLs => <vm::VmLs as AsyncCommand<E>>::description(&vm::VmLs),
            Self::Do => <AsyncDo as AsyncCommand<E>>::description(&AsyncDo),
            Self::Each => <AsyncEach as AsyncCommand<E>>::description(&AsyncEach),
            Self::ParEach => <AsyncParEach as AsyncCommand<E>>::description(&AsyncParEach),
            Self::Where => <AsyncWhere as AsyncCommand<E>>::description(&AsyncWhere),
            Self::WithEnv => <AsyncWithEnv as AsyncCommand<E>>::description(&AsyncWithEnv),
            Self::Complete => <AsyncComplete as AsyncCommand<E>>::description(&AsyncComplete),
            Self::Print => <AsyncPrint as AsyncCommand<E>>::description(&AsyncPrint),
        }
    }

    #[must_use]
    pub fn extra_description(self) -> &'static str {
        ""
    }

    #[must_use]
    pub const fn pipe_redirection(
        self,
    ) -> (Option<nu_protocol::OutDest>, Option<nu_protocol::OutDest>) {
        match self {
            Self::Complete => (
                Some(nu_protocol::OutDest::PipeSeparate),
                Some(nu_protocol::OutDest::PipeSeparate),
            ),
            _ => (None, None),
        }
    }

    #[must_use]
    pub fn search_terms(self) -> Vec<&'static str> {
        match self {
            Self::RunExternal => vec!["exec", "spawn", "external", "process"],
            Self::Inspect => vec!["telemetry", "diagnostics", "state", "moniker"],
            Self::Open => vec!["load", "read", "cat"],
            Self::HttpGet
            | Self::HttpPost
            | Self::HttpPut
            | Self::HttpPatch
            | Self::HttpDelete
            | Self::HttpHead
            | Self::HttpOptions => vec!["network", "http", "zenwave", "request"],
            _ => Vec::new(),
        }
    }

    /// Execute this command asynchronously against `ctx`.
    ///
    /// Each arm is boxed individually so the 53-command dispatch boundary stays
    /// 16 bytes on the caller's stack rather than combining every command
    /// future into a single state machine.
    pub fn run_async<'a, E: HeliosEnv>(
        self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Pin<Box<dyn Future<Output = Result<AsyncPipelineData, ShellError>> + Send + 'a>> {
        match self {
            Self::RunExternal => Box::pin(external::RunExternal.run_async(ctx, input)),
            Self::WithGrants => Box::pin(external::WithGrants.run_async(ctx, input)),
            Self::Which => Box::pin(external::Which.run_async(ctx, input)),
            Self::Sys => Box::pin(sys::Sys.run_async(ctx, input)),
            Self::SysCpu => Box::pin(sys::SysCpu.run_async(ctx, input)),
            Self::SysMem => Box::pin(sys::SysMem.run_async(ctx, input)),
            Self::SysNet => Box::pin(sys::SysNet.run_async(ctx, input)),
            Self::SysDisks => Box::pin(sys::SysDisks.run_async(ctx, input)),
            Self::SysHost => Box::pin(sys::SysHost.run_async(ctx, input)),
            Self::Inspect => Box::pin(process::HeliosInspect.run_async(ctx, input)),
            Self::Ps => Box::pin(process::Ps.run_async(ctx, input)),
            Self::Kill => Box::pin(process::Kill.run_async(ctx, input)),
            Self::Whoami => Box::pin(process::Whoami.run_async(ctx, input)),
            Self::Sleep => Box::pin(process::Sleep.run_async(ctx, input)),
            Self::Clear => Box::pin(process::Clear.run_async(ctx, input)),
            Self::WithScope => Box::pin(process::WithScope.run_async(ctx, input)),
            Self::WithSnapshot => Box::pin(process::WithSnapshot.run_async(ctx, input)),
            Self::WithInstructionProfile => {
                Box::pin(process::WithInstructionProfile.run_async(ctx, input))
            }
            Self::Cd => Box::pin(fs::Cd.run_async(ctx, input)),
            Self::Ls => Box::pin(fs::Ls.run_async(ctx, input)),
            Self::Open => Box::pin(fs::Open.run_async(ctx, input)),
            Self::Save => Box::pin(fs::Save.run_async(ctx, input)),
            Self::Mkdir => Box::pin(fs::Mkdir.run_async(ctx, input)),
            Self::Rm => Box::pin(fs::Rm.run_async(ctx, input)),
            Self::Cp => Box::pin(fs::Cp.run_async(ctx, input)),
            Self::Mv => Box::pin(fs::Mv.run_async(ctx, input)),
            Self::Touch => Box::pin(fs::Touch.run_async(ctx, input)),
            Self::Glob => Box::pin(fs::Glob.run_async(ctx, input)),
            Self::Watch => Box::pin(fs::Watch.run_async(ctx, input)),
            Self::Http => Box::pin(http::Http.run_async(ctx, input)),
            Self::HttpGet => Box::pin(http::HttpGet.run_async(ctx, input)),
            Self::HttpPost => Box::pin(http::HttpPost.run_async(ctx, input)),
            Self::HttpPut => Box::pin(http::HttpPut.run_async(ctx, input)),
            Self::HttpPatch => Box::pin(http::HttpPatch.run_async(ctx, input)),
            Self::HttpDelete => Box::pin(http::HttpDelete.run_async(ctx, input)),
            Self::HttpHead => Box::pin(http::HttpHead.run_async(ctx, input)),
            Self::HttpOptions => Box::pin(http::HttpOptions.run_async(ctx, input)),
            Self::Random => Box::pin(random::Random.run_async(ctx, input)),
            Self::RandomInt => Box::pin(random::RandomInt.run_async(ctx, input)),
            Self::RandomFloat => Box::pin(random::RandomFloat.run_async(ctx, input)),
            Self::RandomBool => Box::pin(random::RandomBool.run_async(ctx, input)),
            Self::RandomChars => Box::pin(random::RandomChars.run_async(ctx, input)),
            Self::RandomBinary => Box::pin(random::RandomBinary.run_async(ctx, input)),
            Self::RandomUuid => Box::pin(random::RandomUuid.run_async(ctx, input)),
            Self::Linux => Box::pin(linux::Linux.run_async(ctx, input)),
            Self::LinuxImage => Box::pin(linux::LinuxImage.run_async(ctx, input)),
            Self::LinuxImageGet => Box::pin(linux::LinuxImageGet.run_async(ctx, input)),
            Self::LinuxImageSet => Box::pin(linux::LinuxImageSet.run_async(ctx, input)),
            Self::LinuxImageClear => Box::pin(linux::LinuxImageClear.run_async(ctx, input)),
            Self::Component => Box::pin(component::Component.run_async(ctx, input)),
            Self::ComponentLs => Box::pin(component::ComponentLs.run_async(ctx, input)),
            Self::ComponentStatus => Box::pin(component::ComponentStatus.run_async(ctx, input)),
            Self::ComponentStart => Box::pin(component::ComponentStart.run_async(ctx, input)),
            Self::ComponentStop => Box::pin(component::ComponentStop.run_async(ctx, input)),
            Self::ComponentRestart => Box::pin(component::ComponentRestart.run_async(ctx, input)),
            Self::ComponentAdd => Box::pin(component::ComponentAdd.run_async(ctx, input)),
            Self::ComponentRm => Box::pin(component::ComponentRm.run_async(ctx, input)),
            Self::Oci => Box::pin(oci::Oci.run_async(ctx, input)),
            Self::OciPull => Box::pin(oci::OciPull.run_async(ctx, input)),
            Self::OciLs => Box::pin(oci::OciLs.run_async(ctx, input)),
            Self::OciInspect => Box::pin(oci::OciInspect.run_async(ctx, input)),
            Self::OciRm => Box::pin(oci::OciRm.run_async(ctx, input)),
            Self::Container => Box::pin(container::Container.run_async(ctx, input)),
            Self::ContainerCreate => Box::pin(container::ContainerCreate.run_async(ctx, input)),
            Self::ContainerLs => Box::pin(container::ContainerLs.run_async(ctx, input)),
            Self::ContainerExec => Box::pin(container::ContainerExec.run_async(ctx, input)),
            Self::ContainerSpawn => Box::pin(container::ContainerSpawn.run_async(ctx, input)),
            Self::ContainerRm => Box::pin(container::ContainerRm.run_async(ctx, input)),
            Self::WithContainer => Box::pin(container::WithContainer.run_async(ctx, input)),
            Self::Mount => Box::pin(storage::Mount.run_async(ctx, input)),
            Self::Umount => Box::pin(storage::Umount.run_async(ctx, input)),
            Self::Btrfs => Box::pin(storage::Btrfs.run_async(ctx, input)),
            Self::BtrfsSubvolume => Box::pin(storage::BtrfsSubvolume.run_async(ctx, input)),
            Self::BtrfsSubvolumeCreate => {
                Box::pin(storage::BtrfsSubvolumeCreate.run_async(ctx, input))
            }
            Self::BtrfsSubvolumeDelete => {
                Box::pin(storage::BtrfsSubvolumeDelete.run_async(ctx, input))
            }
            Self::BtrfsSubvolumeSnapshot => {
                Box::pin(storage::BtrfsSubvolumeSnapshot.run_async(ctx, input))
            }
            Self::BtrfsSubvolumeList => Box::pin(storage::BtrfsSubvolumeList.run_async(ctx, input)),
            Self::BtrfsSubvolumeShow => Box::pin(storage::BtrfsSubvolumeShow.run_async(ctx, input)),
            Self::BtrfsSubvolumeSetRo => {
                Box::pin(storage::BtrfsSubvolumeSetRo.run_async(ctx, input))
            }
            Self::BtrfsSubvolumeSend => Box::pin(storage::BtrfsSubvolumeSend.run_async(ctx, input)),
            Self::BtrfsSubvolumeReceive => {
                Box::pin(storage::BtrfsSubvolumeReceive.run_async(ctx, input))
            }
            Self::Vm => Box::pin(vm::Vm.run_async(ctx, input)),
            Self::VmRun => Box::pin(vm::VmRun.run_async(ctx, input)),
            Self::VmLs => Box::pin(vm::VmLs.run_async(ctx, input)),
            Self::Do => Box::pin(AsyncDo.run_async(ctx, input)),
            Self::Each => Box::pin(AsyncEach.run_async(ctx, input)),
            Self::ParEach => Box::pin(AsyncParEach.run_async(ctx, input)),
            Self::Where => Box::pin(AsyncWhere.run_async(ctx, input)),
            Self::WithEnv => Box::pin(AsyncWithEnv.run_async(ctx, input)),
            Self::Complete => Box::pin(AsyncComplete.run_async(ctx, input)),
            Self::Print => Box::pin(AsyncPrint.run_async(ctx, input)),
        }
    }
}

/// Register every Helios async command into `working_set` and `registry`.
pub fn register_helios_commands(
    working_set: &mut StateWorkingSet<'_>,
    registry: &mut AsyncCommandRegistry,
) {
    for &cmd in AsyncBuiltin::ALL {
        registry.register(working_set, cmd);
    }
}

/// Async-aware `do` command so closures containing async Helios calls execute without `block_on`.
#[derive(Debug, Clone, Copy)]
pub struct AsyncDo;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncDo {
    fn name(&self) -> &str {
        "do"
    }

    fn description(&self) -> &str {
        "Run a closure asynchronously."
    }

    fn signature(&self) -> Signature {
        Signature::build("do")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .switch(
                "ignore-errors",
                "Ignore errors produced by the closure.",
                Some('i'),
            )
            .switch(
                "env",
                "Keep environment changes made by the closure.",
                Some('c'),
            )
            .required("block", SyntaxShape::Closure(None), "The closure to run.")
            .rest(
                "rest",
                SyntaxShape::Any,
                "Arguments to pass to the closure.",
            )
            .category(Category::Core)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let ignore_errors = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "ignore-errors")?;
        let capture_env = ctx.call.has_flag(ctx.engine_state, ctx.stack, "env")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let args: Vec<Value> = ctx.call.rest(ctx.engine_state, ctx.stack, 1)?;

        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        let result = if capture_env {
            crate::eval::eval_closure_redirect_env_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                args,
                input,
                &mut rt,
                head,
            )
            .await
        } else {
            eval_closure_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                args,
                input,
                &mut rt,
                head,
            )
            .await
        };

        match result {
            Ok(out) => Ok(out),
            Err(_) if ignore_errors => Ok(AsyncPipelineData::Empty),
            Err(err) => Err(err),
        }
    }
}

/// Async-aware `each` command supporting streaming async pipelines and async closures.
#[derive(Debug, Clone, Copy)]
pub struct AsyncEach;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncEach {
    fn name(&self) -> &str {
        "each"
    }

    fn description(&self) -> &str {
        "Run a closure on each row of the input list or stream asynchronously."
    }

    fn signature(&self) -> Signature {
        Signature::build("each")
            .input_output_types(vec![
                (Type::list(Type::Any), Type::list(Type::Any)),
                (Type::table(), Type::list(Type::Any)),
                (Type::Any, Type::Any),
            ])
            .switch(
                "keep-empty",
                "Keep empty/null results in output.",
                Some('k'),
            )
            .switch("flatten", "Flatten nested list outputs.", Some('f'))
            .required(
                "closure",
                SyntaxShape::Closure(Some(vec![SyntaxShape::Any])),
                "The closure to run on each element.",
            )
            .category(Category::Filters)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let keep_empty = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "keep-empty")?;
        let flatten = ctx.call.has_flag(ctx.engine_state, ctx.stack, "flatten")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let (rx, span, metadata) = input.into_list_stream_receiver(head).await?;
        let mut results = Vec::new();
        while let Ok(item) = rx.recv().await {
            if let Value::Error { error, .. } = item {
                return Err(*error);
            }
            let mut rt = crate::command::EvalRuntime {
                env: ctx.env,
                registry: ctx.registry,
                runtime_scope: ctx.runtime_scope,
            };
            let out = eval_closure_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                vec![item.clone()],
                AsyncPipelineData::value(item, None),
                &mut rt,
                head,
            )
            .await?;
            let val = out.into_value_async(head).await?;
            if val.is_nothing() && !keep_empty {
                continue;
            }
            if flatten {
                if let Value::List { vals, .. } = val {
                    results.extend(vals);
                } else {
                    results.push(val);
                }
            } else {
                results.push(val);
            }
        }

        Ok(AsyncPipelineData::value(
            Value::list(results, span),
            metadata,
        ))
    }
}

/// Async-native `par-each` command executing closures concurrently on the
/// active async executor without spawning OS threads (works on single-threaded
/// `wasm32-wasip3` as well as host targets).
#[derive(Debug, Clone, Copy)]
pub struct AsyncParEach;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncParEach {
    fn name(&self) -> &str {
        "par-each"
    }

    fn description(&self) -> &str {
        "Run a closure on each row of the input list concurrently via async tasks."
    }

    fn signature(&self) -> Signature {
        Signature::build("par-each")
            .input_output_types(vec![
                (Type::list(Type::Any), Type::list(Type::Any)),
                (Type::table(), Type::list(Type::Any)),
                (Type::Any, Type::Any),
            ])
            .switch(
                "keep-order",
                "Keep sequence of output same as the order of input.",
                Some('k'),
            )
            .named(
                "threads",
                SyntaxShape::Int,
                "Maximum number of concurrent tasks (advisory).",
                Some('t'),
            )
            .required(
                "closure",
                SyntaxShape::Closure(Some(vec![SyntaxShape::Any])),
                "The closure to run on each element.",
            )
            .category(Category::Filters)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        use core::future::Future;
        use core::pin::Pin;
        use core::task::Poll;

        let head = ctx.call.head;
        let _keep_order = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "keep-order")?;
        let max_concurrency: Option<i64> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "threads")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let (rx, span, metadata) = input.into_list_stream_receiver(head).await?;
        let mut items = Vec::new();
        while let Ok(item) = rx.recv().await {
            if let Value::Error { error, .. } = item {
                return Err(*error);
            }
            items.push(item);
        }

        if items.is_empty() {
            return Ok(AsyncPipelineData::value(
                Value::list(Vec::new(), span),
                metadata,
            ));
        }

        let engine_state = ctx.engine_state;
        let env = ctx.env;
        let registry = ctx.registry;
        let base_stack = ctx.stack.clone();
        let base_scope = ctx.runtime_scope.clone();
        let limit = max_concurrency
            .and_then(|n| usize::try_from(n).ok())
            .filter(|&n| n > 0)
            .unwrap_or(items.len());

        let total = items.len();
        let mut pending_items = items.into_iter().enumerate();
        let mut results: Vec<Option<Value>> = vec![None; total];
        type TaskFuture<'b> = Pin<Box<dyn Future<Output = Result<Value, ShellError>> + Send + 'b>>;
        let mut active: Vec<(usize, TaskFuture<'_>)> = Vec::with_capacity(limit.min(total));

        let spawn_next = |idx: usize, item: Value| -> (usize, TaskFuture<'_>) {
            let mut task_stack = base_stack.clone();
            let mut task_scope = base_scope.clone();
            let closure = closure.clone();
            let fut: TaskFuture<'_> = Box::pin(async move {
                let mut rt = crate::command::EvalRuntime {
                    env,
                    registry,
                    runtime_scope: &mut task_scope,
                };
                let out = eval_closure_async(
                    engine_state,
                    &mut task_stack,
                    &closure,
                    vec![item.clone()],
                    AsyncPipelineData::value(item, None),
                    &mut rt,
                    head,
                )
                .await?;
                out.into_value_async(head).await
            });
            (idx, fut)
        };

        for _ in 0..limit {
            if let Some((idx, item)) = pending_items.next() {
                active.push(spawn_next(idx, item));
            }
        }

        futures_lite::future::poll_fn(|cx| {
            let mut i = 0;
            while i < active.len() {
                match active[i].1.as_mut().poll(cx) {
                    Poll::Ready(Ok(val)) => {
                        let (idx, _) = active.swap_remove(i);
                        results[idx] = Some(val);
                        if let Some((next_idx, next_item)) = pending_items.next() {
                            active.push(spawn_next(next_idx, next_item));
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => i += 1,
                }
            }
            if active.is_empty() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;

        let collected: Vec<Value> = results
            .into_iter()
            .flatten()
            .filter(|val| !val.is_nothing())
            .collect();
        Ok(AsyncPipelineData::value(
            Value::list(collected, span),
            metadata,
        ))
    }
}

/// Async-aware `where` command supporting both row conditions (`where size > 10b`)
/// and async closures (`where { |r| (open $r.name) == "ok" }`).
#[derive(Debug, Clone, Copy)]
pub struct AsyncWhere;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncWhere {
    fn name(&self) -> &str {
        "where"
    }

    fn description(&self) -> &str {
        "Filter values based on a row condition or closure asynchronously."
    }

    fn signature(&self) -> Signature {
        Signature::build("where")
            .input_output_types(vec![
                (Type::list(Type::Any), Type::list(Type::Any)),
                (Type::table(), Type::table()),
            ])
            .required(
                "cond",
                SyntaxShape::OneOf(vec![
                    SyntaxShape::RowCondition,
                    SyntaxShape::Closure(Some(vec![SyntaxShape::Any])),
                ]),
                "Condition or closure returning a boolean.",
            )
            .category(Category::Filters)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let (rx, span, metadata) = input.into_list_stream_receiver(head).await?;
        let mut kept = Vec::new();
        while let Ok(item) = rx.recv().await {
            if let Value::Error { error, .. } = item {
                return Err(*error);
            }
            let mut rt = crate::command::EvalRuntime {
                env: ctx.env,
                registry: ctx.registry,
                runtime_scope: ctx.runtime_scope,
            };
            let out = eval_closure_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                vec![item.clone()],
                AsyncPipelineData::value(item.clone(), None),
                &mut rt,
                head,
            )
            .await?;
            let cond_val = out.into_value_async(head).await?;
            if cond_val.is_true() {
                kept.push(item);
            }
        }

        Ok(AsyncPipelineData::value(Value::list(kept, span), metadata))
    }
}

/// Async-aware `with-env` command.
#[derive(Debug, Clone, Copy)]
pub struct AsyncWithEnv;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncWithEnv {
    fn name(&self) -> &str {
        "with-env"
    }

    fn description(&self) -> &str {
        "Runs a closure with temporary environment variables set."
    }

    fn signature(&self) -> Signature {
        Signature::build("with-env")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .required(
                "assignment",
                SyntaxShape::Record(vec![].into()),
                "Record of environment variable names and values.",
            )
            .required("block", SyntaxShape::Closure(None), "The closure to run.")
            .category(Category::Env)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let env_rec: Record = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;

        let mut scoped_stack = ctx
            .stack
            .captures_to_stack_preserve_out_dest(closure.captures.clone());
        for (k, v) in env_rec {
            if v.is_nothing() {
                scoped_stack.hide_env_var(ctx.engine_state, &k);
            } else {
                scoped_stack.add_env_var(k, v);
            }
        }

        let block = ctx.engine_state.get_block(closure.block_id);
        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        crate::eval::eval_block_async(ctx.engine_state, &mut scoped_stack, block, input, &mut rt)
            .await
            .map(|exec| exec.body)
    }
}

/// Async-aware `complete` command: captures stdout, stderr, and exit_code from
/// an external command stream into a structured record.
#[derive(Debug, Clone, Copy)]
pub struct AsyncComplete;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncComplete {
    fn name(&self) -> &str {
        "complete"
    }

    fn description(&self) -> &str {
        "Capture the stdout, stderr, and exit code of an external command."
    }

    fn signature(&self) -> Signature {
        Signature::build("complete")
            .input_output_types(vec![(
                Type::Any,
                Type::Record(
                    vec![
                        ("stdout".into(), Type::String),
                        ("stderr".into(), Type::String),
                        ("exit_code".into(), Type::Int),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let (stdout, stderr, exit_code) = match input {
            AsyncPipelineData::ByteStream {
                stream,
                stderr,
                exit_code,
                upstream_exits,
                merge_stderr,
                ..
            } => {
                let (out_res, err_res) =
                    futures_lite::future::zip(collect_byte_receiver(stream), async move {
                        match stderr {
                            Some(rx) => collect_byte_receiver(rx).await,
                            None => Ok(Vec::new()),
                        }
                    })
                    .await;
                let mut out_bytes = out_res?;
                let mut err_bytes = err_res?;
                if merge_stderr {
                    out_bytes.extend_from_slice(&err_bytes);
                    err_bytes.clear();
                }
                let mut upstream_non_zero = None;
                for upstream in upstream_exits {
                    if let Ok(status) = upstream.exit_code.recv().await {
                        match status {
                            Ok(code) if code != 0 && upstream_non_zero.is_none() => {
                                upstream_non_zero = Some(code);
                            }
                            Ok(_) => {}
                            Err(err) => {
                                return Err(
                                    err.into_shell_error("external command failed", upstream.span)
                                );
                            }
                        }
                    }
                }
                let own_code = match exit_code {
                    Some(rx) => match rx.recv().await {
                        Ok(Ok(code)) => code,
                        Ok(Err(err)) => {
                            return Err(err.into_shell_error("external command failed", head));
                        }
                        Err(_) => 0,
                    },
                    None => 0,
                };
                let code = if own_code != 0 {
                    own_code
                } else {
                    upstream_non_zero.unwrap_or(0)
                };
                (
                    String::from_utf8_lossy(&out_bytes).into_owned(),
                    String::from_utf8_lossy(&err_bytes).into_owned(),
                    code,
                )
            }
            other => {
                let bytes = other.into_bytes_async(head).await?;
                (
                    String::from_utf8_lossy(&bytes).into_owned(),
                    String::new(),
                    0,
                )
            }
        };

        ctx.stack.set_last_exit_code(exit_code, head);
        let mut rec = Record::new();
        rec.push("stdout", Value::string(stdout, head));
        rec.push("stderr", Value::string(stderr, head));
        rec.push("exit_code", Value::int(i64::from(exit_code), head));
        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}

/// Async-native `print` command writing formatted values to stdout or stderr
/// through [`HeliosEnv::write_stdout`] / [`HeliosEnv::write_stderr`].
#[derive(Debug, Clone, Copy)]
pub struct AsyncPrint;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncPrint {
    fn name(&self) -> &str {
        "print"
    }

    fn description(&self) -> &str {
        "Print the given values to stdout (or stderr with -e)."
    }

    fn signature(&self) -> Signature {
        Signature::build("print")
            .input_output_types(vec![(Type::Any, Type::Nothing)])
            .switch("no-newline", "Print without a trailing newline.", Some('n'))
            .switch("stderr", "Print to stderr instead of stdout.", Some('e'))
            .switch(
                "raw",
                "Print raw string/binary bytes without formatting.",
                Some('r'),
            )
            .rest("rest", SyntaxShape::Any, "The values to print.")
            .category(Category::Strings)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let no_newline = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "no-newline")?;
        let to_stderr = ctx.call.has_flag(ctx.engine_state, ctx.stack, "stderr")?;
        let _raw = ctx.call.has_flag(ctx.engine_state, ctx.stack, "raw")?;
        let args: Vec<Value> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;

        let config = ctx.stack.get_config(ctx.engine_state);
        let mut payload = Vec::new();
        if args.is_empty() {
            if !input.is_empty_or_nothing() {
                let val = input.into_value_async(head).await?;
                append_printable(&mut payload, &val, &config);
                if !no_newline {
                    payload.push(b'\n');
                }
            } else if !no_newline {
                payload.push(b'\n');
            }
        } else {
            for (idx, val) in args.iter().enumerate() {
                if idx > 0 {
                    payload.push(b'\n');
                }
                append_printable(&mut payload, val, &config);
            }
            if !no_newline {
                payload.push(b'\n');
            }
        }

        if !payload.is_empty() {
            let res = if to_stderr {
                ctx.env.write_stderr(&payload).await
            } else {
                ctx.env.write_stdout(&payload).await
            };
            res.map_err(|err| err.into_shell_error("print failed", head))?;
        }

        Ok(AsyncPipelineData::Empty)
    }
}

fn append_printable(out: &mut Vec<u8>, value: &Value, config: &nu_protocol::Config) {
    match value {
        Value::Nothing { .. } => {}
        Value::String { val, .. } => out.extend_from_slice(val.as_bytes()),
        Value::Binary { val, .. } => out.extend_from_slice(val),
        other => out.extend_from_slice(other.to_expanded_string("\n", config).as_bytes()),
    }
}

/// Zero-sized marker type used solely to query env-independent signatures and
/// descriptions from [`AsyncCommand<E>`] implementations.
struct SignatureOnlyEnv;

impl HeliosEnv for SignatureOnlyEnv {
    async fn cwd(&self) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn set_cwd(&self, _: &str) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn spawn_external(
        &self,
        _: crate::env::ExternalSpawnRequest,
    ) -> Result<crate::env::ExternalProcess, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn resolve_executable(
        &self,
        _: &str,
        _: &[String],
    ) -> Result<Option<crate::env::ExecutableMatch>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_cpu(
        &self,
        _: bool,
    ) -> Result<Vec<crate::env::SysCpuInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_mem(&self) -> Result<crate::env::SysMemInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_net(&self) -> Result<Vec<crate::env::SysNetInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_disks(&self) -> Result<Vec<crate::env::SysDiskInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_host(&self) -> Result<crate::env::SysHostInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn inspect(
        &self,
        _: Option<&str>,
    ) -> Result<Vec<crate::env::InspectEntry>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn list_processes(&self) -> Result<Vec<crate::env::ProcessInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn kill_process(
        &self,
        _: u64,
        _: Option<&str>,
        _: bool,
    ) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn whoami(&self) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sleep(&self, _: core::time::Duration) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn clear(&self) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn enter_scope(&self, _: &str) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn leave_scope(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn take_snapshot(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<crate::env::SnapshotInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn begin_instruction_profile(
        &self,
        _: Option<&str>,
    ) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn end_instruction_profile(
        &self,
        _: &str,
    ) -> Result<crate::env::InstructionProfileSummary, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn list_dir(
        &self,
        _: &str,
    ) -> Result<Vec<crate::env::FileMetadata>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn stat(&self, _: &str) -> Result<crate::env::FileMetadata, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn read_file(&self, _: &str) -> Result<Vec<u8>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn write_file(
        &self,
        _: &str,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn mkdir(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn remove(&self, _: &str, _: bool, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn copy(&self, _: &str, _: &str, _: bool, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn rename(&self, _: &str, _: &str, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn touch(&self, _: &str, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn watch(
        &self,
        _: &str,
    ) -> Result<async_channel::Receiver<crate::env::WatchEvent>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn linux_image_get(&self) -> Result<crate::env::LinuxImageInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn linux_image_set(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<crate::env::LinuxImageInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn linux_image_clear(
        &self,
    ) -> Result<crate::env::LinuxImageClearResult, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn component_list(
        &self,
    ) -> Result<Vec<crate::env::ComponentInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn component_status(
        &self,
        _: &str,
    ) -> Result<crate::env::ComponentInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn component_start(
        &self,
        _: &str,
    ) -> Result<crate::env::ComponentInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn component_stop(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn component_restart(
        &self,
        _: &str,
    ) -> Result<crate::env::ComponentInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn component_add(
        &self,
        _: crate::env::ComponentAddRequest,
    ) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn component_remove(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn oci_pull(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<crate::env::OciImageSummary, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn oci_list(&self) -> Result<Vec<crate::env::OciImageSummary>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn oci_inspect(
        &self,
        _: &str,
    ) -> Result<crate::env::OciImageInspect, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn oci_remove(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn container_create(
        &self,
        _: crate::env::ContainerCreateRequest,
    ) -> Result<crate::env::ContainerInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn container_list(
        &self,
    ) -> Result<Vec<crate::env::ContainerInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn container_exec(
        &self,
        _: &str,
        _: crate::env::ContainerExecRequest,
    ) -> Result<crate::env::ContainerExecOutput, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn container_spawn(
        &self,
        _: &str,
        _: crate::env::ContainerSpawnRequest,
    ) -> Result<crate::env::ExternalProcess, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn container_remove(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn list_mounts(&self) -> Result<Vec<crate::env::MountEntryInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn mount(&self, _: crate::env::MountRequestSpec) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn umount(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_create(
        &self,
        _: &str,
    ) -> Result<crate::env::BtrfsSubvolumeInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_delete(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_snapshot(
        &self,
        _: &str,
        _: &str,
        _: bool,
    ) -> Result<crate::env::BtrfsSubvolumeInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_list(
        &self,
        _: &str,
    ) -> Result<Vec<crate::env::BtrfsSubvolumeInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_info(
        &self,
        _: &str,
    ) -> Result<crate::env::BtrfsSubvolumeInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_set_ro(&self, _: &str, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_send(
        &self,
        _: &str,
        _: Option<&str>,
        _: &[String],
    ) -> Result<Vec<u8>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn btrfs_subvolume_receive(
        &self,
        _: &str,
        _: Vec<u8>,
    ) -> Result<crate::env::BtrfsSubvolumeInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn vm_run(
        &self,
        _: crate::env::VmRunRequest,
    ) -> Result<crate::env::VmInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn vm_list(&self) -> Result<Vec<crate::env::VmInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
}
