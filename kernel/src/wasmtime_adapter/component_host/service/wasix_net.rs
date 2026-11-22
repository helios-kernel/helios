use super::*;

pub(super) fn add_wasix_port_imports<CpuImpl, Net, StorageImpl>(
    linker: &mut CoreLinker<Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
) -> Result<(), ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_bridge",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (network, network_len, token, token_len, security): (i32, i32, i32, i32, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_port_bridge(
                            &mut caller,
                            network as u32,
                            network_len as u32,
                            token as u32,
                            token_len as u32,
                            security,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_unbridge",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>, ()| {
                Box::new(async move { wasix_port_unbridge(&mut caller).await })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_dhcp_acquire",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>, ()| {
                Box::new(async move { wasix_port_dhcp_acquire(&mut caller).await })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_addr_add",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (addr,): (i32,)| {
                Box::new(
                    async move { p1_reply(wasix_port_addr_add(&mut caller, addr as u32).await) },
                )
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_addr_remove",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (addr,): (i32,)| {
                Box::new(
                    async move { p1_reply(wasix_port_addr_remove(&mut caller, addr as u32).await) },
                )
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_addr_clear",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>, ()| {
                Box::new(async move { wasix_port_addr_clear(&mut caller).await })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_mac",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (ret_mac,): (i32,)| {
                Box::new(async move { p1_reply(wasix_port_mac(&mut caller, ret_mac as u32).await) })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_addr_list",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (addrs, naddrs): (i32, i32)| {
                Box::new(async move {
                    p1_reply(wasix_port_addr_list(&mut caller, addrs as u32, naddrs as u32).await)
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_gateway_set",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (addr,): (i32,)| {
                Box::new(
                    async move { p1_reply(wasix_port_gateway_set(&mut caller, addr as u32).await) },
                )
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_route_add",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (cidr, router, preferred, expires): (i32, i32, i32, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_port_route_add(
                            &mut caller,
                            cidr as u32,
                            router as u32,
                            preferred as u32,
                            expires as u32,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_route_remove",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (cidr,): (i32,)| {
                Box::new(async move {
                    p1_reply(wasix_port_route_remove(&mut caller, cidr as u32).await)
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_route_clear",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>, ()| {
                Box::new(async move { wasix_port_route_clear(&mut caller).await })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "port_route_list",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (routes, nroutes): (i32, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_port_route_list(&mut caller, routes as u32, nroutes as u32).await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    Ok(())
}

pub(super) fn add_wasix_socket_imports<CpuImpl, Net, StorageImpl>(
    linker: &mut CoreLinker<Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
) -> Result<(), ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_status",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             ret_status: i32|
             -> i32 { wasix_sock_status(&mut caller, fd, ret_status as u32) },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_addr_local",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             ret_addr: i32|
             -> i32 { wasix_sock_addr_local(&mut caller, fd, ret_addr as u32) },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_addr_peer",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             ret_addr: i32|
             -> i32 { wasix_sock_addr_peer(&mut caller, fd, ret_addr as u32) },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_open",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             af: i32,
             socktype: i32,
             proto: i32,
             ret_fd: i32|
             -> i32 {
                wasix_sock_open(&mut caller, af, socktype, proto, ret_fd as u32)
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_pair",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             af: i32,
             socktype: i32,
             proto: i32,
             ret_fd0: i32,
             ret_fd1: i32|
             -> i32 {
                wasix_sock_pair(
                    &mut caller,
                    af,
                    socktype,
                    proto,
                    ret_fd0 as u32,
                    ret_fd1 as u32,
                )
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_set_opt_flag",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             option: i32,
             flag: i32|
             -> i32 { wasix_sock_set_opt_flag(&mut caller, fd, option, flag) },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_get_opt_flag",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             option: i32,
             ret_flag: i32|
             -> i32 {
                wasix_sock_get_opt_flag(&mut caller, fd, option, ret_flag as u32)
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_set_opt_time",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             option: i32,
             time: i32|
             -> i32 { wasix_sock_set_opt_time(&mut caller, fd, option, time as u32) },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_get_opt_time",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             option: i32,
             ret_time: i32|
             -> i32 {
                wasix_sock_get_opt_time(&mut caller, fd, option, ret_time as u32)
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_set_opt_size",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             option: i32,
             size: i64|
             -> i32 { wasix_sock_set_opt_size(&mut caller, fd, option, size) },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_get_opt_size",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             option: i32,
             ret_size: i32|
             -> i32 {
                wasix_sock_get_opt_size(&mut caller, fd, option, ret_size as u32)
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_join_multicast_v4",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, multiaddr, interface): (i32, i32, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_sock_multicast_v4(
                            &mut caller,
                            fd,
                            multiaddr as u32,
                            interface as u32,
                            true,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_leave_multicast_v4",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, multiaddr, interface): (i32, i32, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_sock_multicast_v4(
                            &mut caller,
                            fd,
                            multiaddr as u32,
                            interface as u32,
                            false,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_join_multicast_v6",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             multiaddr: i32,
             interface: i32|
             -> i32 {
                wasix_sock_multicast_v6(&mut caller, fd, multiaddr as u32, interface as u32)
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap(
            WASIX_MODULE,
            "sock_leave_multicast_v6",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             fd: i32,
             multiaddr: i32,
             interface: i32|
             -> i32 {
                wasix_sock_multicast_v6(&mut caller, fd, multiaddr as u32, interface as u32)
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_bind",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, addr): (i32, i32)| {
                Box::new(
                    async move { p1_reply(wasix_sock_bind(&mut caller, fd, addr as u32).await) },
                )
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_listen",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, backlog): (i32, i32)| {
                Box::new(async move { wasix_sock_listen(&mut caller, fd, backlog).await })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_accept_v2",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, flags, ret_fd, ret_addr): (i32, i32, i32, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_sock_accept_v2(
                            &mut caller,
                            fd,
                            flags,
                            ret_fd as u32,
                            ret_addr as u32,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_connect",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, addr): (i32, i32)| {
                Box::new(
                    async move { p1_reply(wasix_sock_connect(&mut caller, fd, addr as u32).await) },
                )
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_recv_from",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, iovs, iovs_len, flags, ret_size, ret_flags, ret_addr): (
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
            )| {
                Box::new(async move {
                    p1_reply(
                        wasix_sock_recv_from(
                            &mut caller,
                            fd,
                            iovs as u32,
                            iovs_len as u32,
                            flags,
                            ret_size as u32,
                            ret_flags as u32,
                            ret_addr as u32,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_send_to",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (fd, iovs, iovs_len, flags, addr, ret_size): (i32, i32, i32, i32, i32, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_sock_send_to(
                            &mut caller,
                            fd,
                            iovs as u32,
                            iovs_len as u32,
                            flags as u16,
                            addr as u32,
                            ret_size as u32,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    linker
        .func_wrap_async(
            WASIX_MODULE,
            "sock_send_file",
            |mut caller: Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
             (out_fd, in_fd, offset, count, ret_size): (i32, i32, i64, i64, i32)| {
                Box::new(async move {
                    p1_reply(
                        wasix_sock_send_file(
                            &mut caller,
                            out_fd,
                            in_fd,
                            offset,
                            count,
                            ret_size as u32,
                        )
                        .await,
                    )
                })
            },
        )
        .map_err(map_program_runtime_error)?;
    Ok(())
}

pub(super) async fn wasix_resolve<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    host: u32,
    host_len: u32,
    port: i32,
    addrs: u32,
    naddrs: u32,
    ret_naddrs: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let status = caller.data().require_dns_authority();
    if status != p1::errno::SUCCESS {
        return Ok(status);
    }
    if u16::try_from(port).is_err() {
        return Ok(p1::errno::INVAL);
    }
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let host = memory
        .read_path(GuestAddress::wasm32(host), host_len)
        .await?;
    let Some(service) = caller.data().runtime_state.network_service() else {
        return Ok(p1::errno::NETDOWN);
    };
    let resolved = match service.dns_resolve(&host, u64::MAX).await {
        Ok(resolved) => resolved,
        Err(error) => return Ok(p1_errno_from_dns_error(error)),
    };
    let returned = resolved.len().min(naddrs as usize);
    let addrs = GuestAddress::wasm32(addrs);
    for (index, address) in resolved.iter().take(returned).enumerate() {
        let entry = addrs.offset(index as u64 * u64::from(WASIX_ADDR_IP_SIZE));
        write_wasix_addr_ip(&memory, entry, *address).await?;
    }
    let returned = u32::try_from(returned).map_err(|_| P1Stop::Errno(p1::errno::OVERFLOW))?;
    memory
        .write_u32(GuestAddress::wasm32(ret_naddrs), returned)
        .await?;
    Ok(p1::errno::SUCCESS)
}

pub(super) fn wasix_network_admin_service<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
) -> Result<(crate::NetworkAdminCap, Net), i32>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let cap = caller
        .data()
        .authority
        .derive_network_admin_cap()
        .map_err(|_| p1::errno::NOTCAPABLE)?;
    let service = caller
        .data()
        .runtime_state
        .network_service()
        .ok_or(p1::errno::NETDOWN)?;
    Ok((cap, service))
}

pub(super) fn p1_errno_from_network_control_error(error: crate::NetworkControlError) -> i32 {
    match error {
        crate::NetworkControlError::PortUnavailable => p1::errno::NETDOWN,
        crate::NetworkControlError::BridgeUnavailable => p1::errno::NOTSUP,
        crate::NetworkControlError::InvalidBridgeRequest => p1::errno::INVAL,
        crate::NetworkControlError::InvalidAddress
        | crate::NetworkControlError::InvalidRoute
        | crate::NetworkControlError::RouteTimestampOutOfRange => p1::errno::INVAL,
        crate::NetworkControlError::BackendFault => p1::errno::IO,
    }
}

pub(super) fn wasix_bridge_security(raw: i32) -> Result<crate::NetworkBridgeSecurity, i32> {
    let raw = u8::try_from(raw).map_err(|_| p1::errno::INVAL)?;
    match raw {
        WASIX_STREAM_SECURITY_UNENCRYPTED
        | WASIX_STREAM_SECURITY_ANY_ENCRYPTION
        | WASIX_STREAM_SECURITY_CLASSIC_ENCRYPTION
        | WASIX_STREAM_SECURITY_DOUBLE_ENCRYPTION => {
            crate::NetworkBridgeSecurity::new(raw).map_err(p1_errno_from_network_control_error)
        }
        _ => Err(p1::errno::INVAL),
    }
}

pub(super) async fn wasix_port_bridge<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    network: u32,
    network_len: u32,
    token: u32,
    token_len: u32,
    security: i32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let security = match wasix_bridge_security(security) {
        Ok(security) => security,
        Err(status) => return Ok(status),
    };
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let network = wasix_read_exec_string(&memory, network, network_len).await?;
    let token = wasix_read_exec_string(&memory, token, token_len).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let request = crate::NetworkBridgeRequest::new(network, token, security);
    let control = crate::NetworkControl::new(service);
    Ok(
        match control
            .bridge_port(cap, crate::NetworkPortId::new(0), request)
            .await
        {
            Ok(()) => p1::errno::SUCCESS,
            Err(error) => p1_errno_from_network_control_error(error),
        },
    )
}

pub(super) async fn wasix_port_unbridge<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return status,
    };
    let control = crate::NetworkControl::new(service);
    match control
        .unbridge_port(cap, crate::NetworkPortId::new(0))
        .await
    {
        Ok(()) => p1::errno::SUCCESS,
        Err(error) => p1_errno_from_network_control_error(error),
    }
}

pub(super) async fn wasix_port_dhcp_acquire<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return status,
    };
    let control = crate::NetworkControl::new(service);
    match control
        .acquire_dhcp(cap, crate::NetworkPortId::new(0))
        .await
    {
        Ok(_) => p1::errno::SUCCESS,
        Err(error) => p1_errno_from_network_control_error(error),
    }
}

pub(super) async fn wasix_port_addr_add<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let cidr = wasix_read_addr_cidr_ip4(&memory, GuestAddress::wasm32(addr)).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    Ok(
        match control
            .add_address(cap, crate::NetworkPortId::new(0), cidr)
            .await
        {
            Ok(()) => p1::errno::SUCCESS,
            Err(error) => p1_errno_from_network_control_error(error),
        },
    )
}

pub(super) async fn wasix_port_addr_remove<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let address = wasix_read_addr_ip4(&memory, GuestAddress::wasm32(addr)).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    let cidr = crate::Ipv4Cidr::new(address, 32);
    Ok(
        match control
            .remove_address(cap, crate::NetworkPortId::new(0), cidr)
            .await
        {
            Ok(()) => p1::errno::SUCCESS,
            Err(error) => p1_errno_from_network_control_error(error),
        },
    )
}

pub(super) async fn wasix_port_addr_clear<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return status,
    };
    let control = crate::NetworkControl::new(service);
    match control
        .clear_addresses(cap, crate::NetworkPortId::new(0))
        .await
    {
        Ok(()) => p1::errno::SUCCESS,
        Err(error) => p1_errno_from_network_control_error(error),
    }
}

pub(super) async fn wasix_port_mac<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    ret_mac: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    let mac = match control.mac_address(cap, crate::NetworkPortId::new(0)).await {
        Ok(mac) => mac,
        Err(error) => return Ok(p1_errno_from_network_control_error(error)),
    };
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    memory
        .write_bytes(GuestAddress::wasm32(ret_mac), &mac.octets())
        .await?;
    Ok(p1::errno::SUCCESS)
}

pub(super) async fn wasix_port_addr_list<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    addrs: u32,
    naddrs: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let (addrs, naddrs) = (GuestAddress::wasm32(addrs), GuestAddress::wasm32(naddrs));
    let capacity = memory.read_u32(naddrs).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    let addresses = match control
        .list_addresses(cap, crate::NetworkPortId::new(0))
        .await
    {
        Ok(addresses) => addresses,
        Err(error) => return Ok(p1_errno_from_network_control_error(error)),
    };
    let needed = match u32::try_from(addresses.len()) {
        Ok(needed) => needed,
        Err(_) => return Ok(p1::errno::OVERFLOW),
    };
    if needed > capacity {
        memory.write_u32(naddrs, needed).await?;
        return Ok(p1::errno::OVERFLOW);
    };
    for (index, cidr) in addresses.iter().enumerate() {
        let entry = addrs.offset(index as u64 * u64::from(WASIX_ADDR_CIDR_SIZE));
        write_wasix_addr_cidr_ip4(&memory, entry, *cidr).await?;
    }
    memory.write_u32(naddrs, needed).await?;
    Ok(p1::errno::SUCCESS)
}

pub(super) async fn wasix_port_gateway_set<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let gateway = wasix_read_addr_ip4(&memory, GuestAddress::wasm32(addr)).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    Ok(
        match control
            .set_gateway(cap, crate::NetworkPortId::new(0), gateway)
            .await
        {
            Ok(()) => p1::errno::SUCCESS,
            Err(error) => p1_errno_from_network_control_error(error),
        },
    )
}

pub(super) async fn wasix_port_route_add<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    cidr: u32,
    router: u32,
    preferred: u32,
    expires: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let destination = wasix_read_addr_cidr_ip4(&memory, GuestAddress::wasm32(cidr)).await?;
    let gateway = wasix_read_addr_ip4(&memory, GuestAddress::wasm32(router)).await?;
    let preferred =
        wasix_read_optional_timestamp_async(&memory, GuestAddress::wasm32(preferred)).await?;
    let expires =
        wasix_read_optional_timestamp_async(&memory, GuestAddress::wasm32(expires)).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    let route = crate::Ipv4Route::with_lifetimes(destination, gateway, preferred, expires);
    Ok(
        match control
            .add_route(cap, crate::NetworkPortId::new(0), route)
            .await
        {
            Ok(()) => p1::errno::SUCCESS,
            Err(error) => p1_errno_from_network_control_error(error),
        },
    )
}

pub(super) async fn wasix_port_route_remove<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    cidr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let destination = wasix_read_addr_ip4(&memory, GuestAddress::wasm32(cidr)).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    let routes = match control.list_routes(cap, crate::NetworkPortId::new(0)).await {
        Ok(routes) => routes,
        Err(error) => return Ok(p1_errno_from_network_control_error(error)),
    };
    for route in routes {
        if route.destination().address() == destination {
            match control
                .remove_route(cap, crate::NetworkPortId::new(0), route)
                .await
            {
                Ok(()) => return Ok(p1::errno::SUCCESS),
                Err(error) => return Ok(p1_errno_from_network_control_error(error)),
            }
        }
    }
    Ok(p1::errno::NOENT)
}

pub(super) async fn wasix_port_route_clear<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return status,
    };
    let control = crate::NetworkControl::new(service);
    match control
        .clear_routes(cap, crate::NetworkPortId::new(0))
        .await
    {
        Ok(()) => p1::errno::SUCCESS,
        Err(error) => p1_errno_from_network_control_error(error),
    }
}

pub(super) async fn wasix_port_route_list<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    routes: u32,
    nroutes: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let (routes, nroutes) = (GuestAddress::wasm32(routes), GuestAddress::wasm32(nroutes));
    let capacity = memory.read_u32(nroutes).await?;
    let (cap, service) = match wasix_network_admin_service(caller) {
        Ok(parts) => parts,
        Err(status) => return Ok(status),
    };
    let control = crate::NetworkControl::new(service);
    let route_entries = match control.list_routes(cap, crate::NetworkPortId::new(0)).await {
        Ok(route_entries) => route_entries,
        Err(error) => return Ok(p1_errno_from_network_control_error(error)),
    };
    let needed = match u32::try_from(route_entries.len()) {
        Ok(needed) => needed,
        Err(_) => return Ok(p1::errno::OVERFLOW),
    };
    if needed > capacity {
        memory.write_u32(nroutes, needed).await?;
        return Ok(p1::errno::OVERFLOW);
    }
    for (index, route) in route_entries.iter().enumerate() {
        let entry = routes.offset(index as u64 * u64::from(WASIX_ROUTE_SIZE));
        write_wasix_route_ip4(&memory, entry, *route).await?;
    }
    memory.write_u32(nroutes, needed).await?;
    Ok(p1::errno::SUCCESS)
}

pub(super) fn wasix_sock_status<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    ret_status: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    let status = wasix_sock_descriptor_unavailable(caller, fd);
    if status != p1::errno::SUCCESS {
        return status;
    }
    p1_write_u8(
        caller,
        memory,
        GuestAddress::wasm32(ret_status),
        WASIX_SOCK_STATUS_OPENED,
    )
}

pub(super) fn wasix_sock_addr_local<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    ret_addr: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    let local = match caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(socket)) => {
                if let Some(UnixUdpSocket::Bound {
                    local_address,
                    local_port,
                    ..
                }) = socket.udp_state()
                {
                    Ok(Some((local_address, local_port)))
                } else if let Some(
                    UnixTcpSocket::Bound {
                        local_address,
                        local_port,
                        ..
                    }
                    | UnixTcpSocket::Listening {
                        local_address,
                        local_port,
                        ..
                    },
                ) = socket.tcp_state()
                {
                    Ok(Some((local_address, local_port)))
                } else {
                    Ok(None)
                }
            }
            Some(_) => Err(p1::errno::NOTSOCK),
            None => Err(p1::errno::BADF),
        }) {
        Ok(local) => local,
        Err(errno) => return errno,
    };
    match local {
        Some((local_address, local_port)) => write_wasix_addr_port(
            caller,
            memory,
            GuestAddress::wasm32(ret_addr),
            local_address,
            local_port,
        ),
        None => write_wasix_addr_port_unspec(caller, memory, GuestAddress::wasm32(ret_addr)),
    }
}

pub(super) fn wasix_sock_addr_peer<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    ret_addr: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    let peer = match caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(socket)) => {
                if let Some(UnixTcpSocket::Connected {
                    peer_address,
                    peer_port,
                    ..
                }) = socket.tcp_state()
                {
                    Ok(Some((peer_address, peer_port)))
                } else {
                    Ok(None)
                }
            }
            Some(_) => Err(p1::errno::NOTSOCK),
            None => Err(p1::errno::BADF),
        }) {
        Ok(peer) => peer,
        Err(errno) => return errno,
    };
    match peer {
        Some((peer_address, peer_port)) => write_wasix_addr_port(
            caller,
            memory,
            GuestAddress::wasm32(ret_addr),
            peer_address,
            peer_port,
        ),
        None => write_wasix_addr_port_unspec(caller, memory, GuestAddress::wasm32(ret_addr)),
    }
}

pub(super) fn wasix_validate_network_socket_request(
    af: i32,
    socktype: i32,
    proto: i32,
) -> Result<(), i32> {
    match af {
        WASIX_ADDRESS_FAMILY_UNSPEC_I32
        | WASIX_ADDRESS_FAMILY_IP_INET4_I32
        | WASIX_ADDRESS_FAMILY_IP_INET6_I32 => {}
        WASIX_ADDRESS_FAMILY_UNIX_I32 => {
            return Err(p1::errno::NOTSUP);
        }
        _ => return Err(p1::errno::INVAL),
    }
    match socktype {
        WASIX_SOCK_TYPE_STREAM if proto == 0 || proto == WASIX_IPPROTO_TCP_I32 => Ok(()),
        WASIX_SOCK_TYPE_DGRAM if proto == 0 || proto == WASIX_IPPROTO_UDP_I32 => Ok(()),
        WASIX_SOCK_TYPE_STREAM | WASIX_SOCK_TYPE_DGRAM => Err(p1::errno::INVAL),
        _ => Err(p1::errno::INVAL),
    }
}

pub(super) fn wasix_validate_socket_pair_request(
    af: i32,
    socktype: i32,
    proto: i32,
) -> Result<SocketKind, i32> {
    match af {
        WASIX_ADDRESS_FAMILY_UNSPEC_I32 | WASIX_ADDRESS_FAMILY_UNIX_I32 => {}
        WASIX_ADDRESS_FAMILY_IP_INET4_I32 | WASIX_ADDRESS_FAMILY_IP_INET6_I32 => {
            return Err(p1::errno::NOTSUP);
        }
        _ => return Err(p1::errno::INVAL),
    }
    if proto != 0 {
        return Err(p1::errno::INVAL);
    }
    wasix_socket_kind(socktype)
}

/// The socket kind a WASIX socket type names.
fn wasix_socket_kind(socktype: i32) -> Result<SocketKind, i32> {
    match socktype {
        WASIX_SOCK_TYPE_STREAM => Ok(SocketKind::Stream),
        WASIX_SOCK_TYPE_DGRAM => Ok(SocketKind::Datagram),
        _ => Err(p1::errno::INVAL),
    }
}

/// The WASIX socket type of a socket kind.
pub(super) const fn wasix_socket_type(kind: SocketKind) -> i32 {
    match kind {
        SocketKind::Stream => WASIX_SOCK_TYPE_STREAM,
        SocketKind::Datagram => WASIX_SOCK_TYPE_DGRAM,
    }
}

pub(super) fn wasix_sock_open<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    af: i32,
    socktype: i32,
    proto: i32,
    ret_fd: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Err(errno) = wasix_validate_network_socket_request(af, socktype, proto) {
        return errno;
    }
    // AF_UNSPEC keeps the historical IPv4 default, matching what a
    // `socket(0, SOCK_STREAM, 0)` caller gets from WASIX today.
    let family = match af {
        WASIX_ADDRESS_FAMILY_IP_INET6_I32 => SocketFamily::Ipv6,
        _ => SocketFamily::Ipv4,
    };
    let status = match socktype {
        WASIX_SOCK_TYPE_STREAM => caller.data().require_tcp_authority(),
        WASIX_SOCK_TYPE_DGRAM => caller.data().require_udp_authority(),
        _ => return p1::errno::INVAL,
    };
    if status != p1::errno::SUCCESS {
        return status;
    }
    if caller.data().runtime_state.network_service().is_none() {
        return p1::errno::NETDOWN;
    }
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    let descriptor = Preview1Descriptor::Socket(match wasix_socket_kind(socktype) {
        Ok(SocketKind::Stream) => UnixSocket::<Net>::tcp(family),
        Ok(SocketKind::Datagram) => UnixSocket::<Net>::udp(family),
        Err(errno) => return errno,
    });
    let fd = match caller.data_mut().descriptors.insert(descriptor) {
        Ok(fd) => fd,
        Err(errno) => return errno,
    };
    p1_write_u32(caller, memory, GuestAddress::wasm32(ret_fd), fd)
}

pub(super) fn wasix_sock_pair<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    af: i32,
    socktype: i32,
    proto: i32,
    ret_fd0: u32,
    ret_fd1: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let kind = match wasix_validate_socket_pair_request(af, socktype, proto) {
        Ok(kind) => kind,
        Err(errno) => return errno,
    };
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    let (first, second) = UnixSocket::<Net>::pair(kind);
    let (first, second) = (
        Preview1Descriptor::Socket(first),
        Preview1Descriptor::Socket(second),
    );
    let fd0 = match caller.data_mut().descriptors.insert(first) {
        Ok(fd) => fd,
        Err(errno) => return errno,
    };
    let fd1 = match caller.data_mut().descriptors.insert(second) {
        Ok(fd) => fd,
        Err(errno) => {
            let _ = caller.data_mut().descriptors.close(fd0 as i32);
            return errno;
        }
    };
    let status = p1_write_u32(caller, memory, GuestAddress::wasm32(ret_fd0), fd0);
    if status != p1::errno::SUCCESS {
        return status;
    }
    p1_write_u32(caller, memory, GuestAddress::wasm32(ret_fd1), fd1)
}

pub(super) fn wasix_sock_descriptor_unavailable<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(_)) => p1::errno::SUCCESS,
            Some(_) => p1::errno::NOTSOCK,
            None => p1::errno::BADF,
        })
}

pub(super) fn wasix_sock_recv_authority<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
) -> Result<WasixSocketAuthority, i32> {
    let Some(descriptor) = descriptor else {
        return Err(p1::errno::BADF);
    };
    let Preview1Descriptor::Socket(socket) = descriptor else {
        return Err(p1::errno::NOTSOCK);
    };
    if let Some(udp) = socket.udp_state() {
        return match udp {
            UnixUdpSocket::Bound { .. } => Ok(WasixSocketAuthority::Udp),
            UnixUdpSocket::Unbound { .. } => Err(p1::errno::INVAL),
        };
    }
    if let Some(tcp) = socket.tcp_state() {
        return match tcp {
            UnixTcpSocket::Connected { .. } => Ok(WasixSocketAuthority::Tcp),
            _ => Err(p1::errno::INVAL),
        };
    }
    Ok(WasixSocketAuthority::LocalOnly)
}

pub(super) fn wasix_sock_send_authority<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
) -> Result<WasixSocketAuthority, i32> {
    let Some(descriptor) = descriptor else {
        return Err(p1::errno::BADF);
    };
    let Preview1Descriptor::Socket(socket) = descriptor else {
        return Err(p1::errno::NOTSOCK);
    };
    if socket.is_udp() {
        return Ok(WasixSocketAuthority::Udp);
    }
    if let Some(tcp) = socket.tcp_state() {
        return match tcp {
            UnixTcpSocket::Connected { .. } => Ok(WasixSocketAuthority::Tcp),
            _ => Err(p1::errno::INVAL),
        };
    }
    Ok(WasixSocketAuthority::LocalOnly)
}

pub(super) fn wasix_sock_bind_authority<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
) -> Result<WasixSocketAuthority, i32> {
    let Some(descriptor) = descriptor else {
        return Err(p1::errno::BADF);
    };
    let Preview1Descriptor::Socket(socket) = descriptor else {
        return Err(p1::errno::NOTSOCK);
    };
    if let Some(udp) = socket.udp_state() {
        return match udp {
            UnixUdpSocket::Unbound { .. } => Ok(WasixSocketAuthority::Udp),
            UnixUdpSocket::Bound { .. } => Err(p1::errno::INVAL),
        };
    }
    if let Some(tcp) = socket.tcp_state() {
        return match tcp {
            UnixTcpSocket::Unconnected { .. } => Ok(WasixSocketAuthority::Tcp),
            _ => Err(p1::errno::INVAL),
        };
    }
    Err(p1::errno::INVAL)
}

pub(super) fn wasix_sock_listen_authority<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
) -> Result<WasixSocketAuthority, i32> {
    let Some(descriptor) = descriptor else {
        return Err(p1::errno::BADF);
    };
    let Preview1Descriptor::Socket(socket) = descriptor else {
        return Err(p1::errno::NOTSOCK);
    };
    if socket.is_tcp() {
        Ok(WasixSocketAuthority::Tcp)
    } else {
        Err(p1::errno::INVAL)
    }
}

pub(super) fn wasix_sock_set_opt_flag<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    option: i32,
    flag: i32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let flag = match flag {
        0 => false,
        1 => true,
        _ => return p1::errno::INVAL,
    };
    caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(descriptor)) => {
                wasix_socket_set_flag(descriptor, option, flag)
            }
            Some(_) => p1::errno::NOTSOCK,
            None => p1::errno::BADF,
        })
}

pub(super) fn wasix_sock_get_opt_flag<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    option: i32,
    ret_flag: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let flag = match caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(descriptor)) => wasix_socket_flag(descriptor, option),
            Some(_) => Err(p1::errno::NOTSOCK),
            None => Err(p1::errno::BADF),
        }) {
        Ok(flag) => flag,
        Err(errno) => return errno,
    };
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    p1_write_wasix_bool(caller, memory, GuestAddress::wasm32(ret_flag), flag)
}

pub(super) fn wasix_sock_set_opt_time<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    option: i32,
    time: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    let time = match wasix_read_optional_timestamp(caller, memory, GuestAddress::wasm32(time)) {
        Ok(time) => time,
        Err(errno) => return errno,
    };
    caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(descriptor)) => {
                wasix_socket_set_time(descriptor, option, time)
            }
            Some(_) => p1::errno::NOTSOCK,
            None => p1::errno::BADF,
        })
}

pub(super) fn wasix_sock_get_opt_time<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    option: i32,
    ret_time: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let time = match caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(descriptor)) => wasix_socket_time(descriptor, option),
            Some(_) => Err(p1::errno::NOTSOCK),
            None => Err(p1::errno::BADF),
        }) {
        Ok(time) => time,
        Err(errno) => return errno,
    };
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    p1_write_wasix_optional_timestamp(caller, memory, GuestAddress::wasm32(ret_time), time)
}

pub(super) fn wasix_sock_set_opt_size<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    option: i32,
    size: i64,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let size = match u64::try_from(size) {
        Ok(size) => size,
        Err(_) => return p1::errno::INVAL,
    };
    let descriptor = match caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(descriptor)) => Ok(descriptor.clone()),
            Some(_) => Err(p1::errno::NOTSOCK),
            None => Err(p1::errno::BADF),
        }) {
        Ok(descriptor) => descriptor,
        Err(errno) => return errno,
    };
    let status = wasix_socket_set_size(&descriptor, option, size);
    if status != p1::errno::SUCCESS || option != WASIX_SOCK_OPTION_TTL {
        return status;
    }
    // A socket that already exists in the netstack takes the new TTL now;
    // one that has not connected, listened, or bound yet gets it applied at
    // that point, so no packet ever leaves with a stale value.
    let hop_limit = descriptor.options().hop_limit();
    let target = descriptor.handle();
    let Some(service) = caller.data().runtime_state.network_service() else {
        return p1::errno::SUCCESS;
    };
    match target {
        Some(UnixSocketHandle::<Net>::TcpStream(stream)) => service
            .tcp_set_hop_limit(stream, hop_limit)
            .map_or_else(p1_errno_from_tcp_error, |()| p1::errno::SUCCESS),
        Some(UnixSocketHandle::<Net>::TcpListener(listener)) => service
            .tcp_listener_set_hop_limit(listener, hop_limit)
            .map_or_else(p1_errno_from_tcp_error, |()| p1::errno::SUCCESS),
        Some(UnixSocketHandle::<Net>::UdpSocket(socket)) => service
            .udp_set_hop_limit(socket, hop_limit)
            .map_or_else(p1_errno_from_udp_error, |()| p1::errno::SUCCESS),
        None => p1::errno::SUCCESS,
    }
}

pub(super) fn wasix_sock_get_opt_size<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    option: i32,
    ret_size: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let size = match caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::Socket(descriptor)) => match option {
                WASIX_SOCK_OPTION_TYPE => Ok(wasix_socket_type(descriptor.kind()) as u64),
                WASIX_SOCK_OPTION_PROTO => Ok(descriptor
                    .protocol()
                    .map_or(0, |protocol| u64::from(protocol.number()))),
                _ => wasix_socket_size(descriptor, option),
            },
            Some(_) => Err(p1::errno::NOTSOCK),
            None => Err(p1::errno::BADF),
        }) {
        Ok(size) => size,
        Err(errno) => return errno,
    };
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    p1_write_u64(caller, memory, GuestAddress::wasm32(ret_size), size)
}

pub(super) fn wasix_sock_multicast_v6<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    multiaddr: u32,
    interface: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let status = caller.data().require_multicast_authority();
    if status != p1::errno::SUCCESS {
        return status;
    }
    let status = caller.data().require_udp_authority();
    if status != p1::errno::SUCCESS {
        return status;
    }
    let status = caller
        .data()
        .descriptors
        .with(|descriptors| wasix_udp_socket_descriptor_status(descriptors.get(fd)));
    if status != p1::errno::SUCCESS {
        return status;
    }
    let Some(memory) = p1_memory(caller) else {
        return p1::errno::FAULT;
    };
    if let Err(errno) = wasix_validate_addr_ip6(caller, memory, GuestAddress::wasm32(multiaddr)) {
        return errno;
    }
    if let Err(errno) = wasix_validate_addr_ip6(caller, memory, GuestAddress::wasm32(interface)) {
        return errno;
    }
    p1::errno::NOTSUP
}

pub(super) async fn wasix_sock_multicast_v4<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    multiaddr: u32,
    interface: u32,
    join: bool,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let status = caller.data().require_multicast_authority();
    if status != p1::errno::SUCCESS {
        return Ok(status);
    }
    let status = caller.data().require_udp_authority();
    if status != p1::errno::SUCCESS {
        return Ok(status);
    }
    let status = caller
        .data()
        .descriptors
        .with(|descriptors| wasix_udp_socket_descriptor_status(descriptors.get(fd)));
    if status != p1::errno::SUCCESS {
        return Ok(status);
    }
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let group = wasix_read_addr_ip4(&memory, GuestAddress::wasm32(multiaddr)).await?;
    let interface = wasix_read_addr_ip4(&memory, GuestAddress::wasm32(interface)).await?;
    let Some(service) = caller.data().runtime_state.network_service() else {
        return Ok(p1::errno::NETDOWN);
    };
    let result = if join {
        service.udp_join_multicast_v4(group, interface).await
    } else {
        service.udp_leave_multicast_v4(group, interface).await
    };
    Ok(match result {
        Ok(()) => p1::errno::SUCCESS,
        Err(error) => p1_errno_from_udp_error(error),
    })
}

pub(super) fn wasix_udp_socket_descriptor_status<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
) -> i32 {
    match descriptor {
        Some(Preview1Descriptor::Socket(socket)) if socket.is_udp() => p1::errno::SUCCESS,
        Some(Preview1Descriptor::Socket(_)) => p1::errno::INVAL,
        Some(_) => p1::errno::NOTSOCK,
        None => p1::errno::BADF,
    }
}

pub(super) async fn wasix_sock_bind<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let (Some(address), port) = wasix_read_addr_port(&memory, GuestAddress::wasm32(addr)).await?
    else {
        return Ok(p1::errno::INVAL);
    };
    Ok(wasix_sock_bind_address(caller, fd, address, port).await)
}

async fn wasix_sock_bind_address<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    address: crate::NetworkIpAddress,
    port: u16,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let descriptor = caller.data().descriptors.get_cloned(fd);
    let authority = match wasix_sock_bind_authority(descriptor.as_ref()) {
        Ok(authority) => authority,
        Err(errno) => return errno,
    };
    let status = caller.data().require_socket_bind_authority(authority, port);
    if status != p1::errno::SUCCESS {
        return status;
    }
    let Some(Preview1Descriptor::Socket(socket)) = descriptor else {
        return p1::errno::BADF;
    };
    if let Some(UnixUdpSocket::Unbound { family, .. }) = socket.udp_state() {
        if !crate::unix::family_accepts(family, address) {
            return p1::errno::AFNOSUPPORT;
        }
        let Some(service) = caller.data().runtime_state.network_service() else {
            return p1::errno::NETDOWN;
        };
        let binding = match service.udp_bind(address, port).await {
            Ok(binding) => binding,
            Err(error) => return p1_errno_from_udp_error(error),
        };
        let owned = OwnedUdpSocket::new(crate::UnixNetwork::new(service.clone()), binding.socket);
        // Nothing can leave a datagram socket before its bind completes,
        // so applying the descriptor's TTL here covers every packet.
        let hop_limit = socket.options().hop_limit();
        if let Err(error) = service.udp_set_hop_limit(binding.socket, hop_limit) {
            return p1_errno_from_udp_error(error);
        }
        return socket
            .with_udp_mut(|slot| match *slot {
                UnixUdpSocket::Unbound { family, options } => {
                    *slot = UnixUdpSocket::Bound {
                        family,
                        socket: owned,
                        local_address: address,
                        local_port: binding.local_port,
                        options,
                    };
                    p1::errno::SUCCESS
                }
                UnixUdpSocket::Bound { .. } => p1::errno::INVAL,
            })
            .unwrap_or(p1::errno::INVAL);
    }
    if let Some(UnixTcpSocket::Unconnected { family, .. }) = socket.tcp_state() {
        if !crate::unix::family_accepts(family, address) {
            return p1::errno::AFNOSUPPORT;
        }
        let Some(service) = caller.data().runtime_state.network_service() else {
            return p1::errno::NETDOWN;
        };
        if !address.is_unspecified() && !service.owns_ip_address(address) {
            return p1::errno::ADDRNOTAVAIL;
        }
        return socket
            .with_tcp_mut(|slot| match *slot {
                UnixTcpSocket::Unconnected { family, options } => {
                    *slot = UnixTcpSocket::Bound {
                        family,
                        local_address: address,
                        local_port: port,
                        options,
                    };
                    p1::errno::SUCCESS
                }
                _ => p1::errno::INVAL,
            })
            .unwrap_or(p1::errno::INVAL);
    }
    p1::errno::BADF
}

pub(super) async fn wasix_sock_listen<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    backlog: i32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if backlog < 0 {
        return p1::errno::INVAL;
    }
    let descriptor = caller.data().descriptors.get_cloned(fd);
    let authority = match wasix_sock_listen_authority(descriptor.as_ref()) {
        Ok(authority) => authority,
        Err(errno) => return errno,
    };
    let status = caller.data().require_socket_authority(authority);
    if status != p1::errno::SUCCESS {
        return status;
    }
    let Some(service) = caller.data().runtime_state.network_service() else {
        return p1::errno::NETDOWN;
    };
    let backlog = match u16::try_from(backlog) {
        Ok(backlog) => backlog,
        Err(_) => return p1::errno::OVERFLOW,
    };
    let Some(Preview1Descriptor::Socket(socket)) = descriptor else {
        return p1::errno::BADF;
    };
    let (local_address, local_port, hop_limit) = match socket.tcp_state() {
        Some(UnixTcpSocket::Unconnected { options, family }) => (
            crate::unix::unspecified_address(family),
            0,
            options.hop_limit(),
        ),
        Some(UnixTcpSocket::Bound {
            local_address,
            local_port,
            options,
            ..
        }) => (local_address, local_port, options.hop_limit()),
        Some(_) => return p1::errno::INVAL,
        None => return p1::errno::INVAL,
    };
    let listener = match service
        .tcp_listen(local_address, local_port, backlog, hop_limit)
        .await
    {
        Ok(listener) => listener,
        Err(error) => return p1_errno_from_tcp_error(error),
    };
    let owned = OwnedTcpListener::new(crate::UnixNetwork::new(service.clone()), listener.listener);
    socket
        .with_tcp_mut(|slot| match *slot {
            UnixTcpSocket::Unconnected { family, options }
            | UnixTcpSocket::Bound {
                family, options, ..
            } => {
                *slot = UnixTcpSocket::Listening {
                    family,
                    listener: owned,
                    local_address,
                    local_port: listener.local_port,
                    options,
                };
                p1::errno::SUCCESS
            }
            _ => p1::errno::INVAL,
        })
        .unwrap_or(p1::errno::INVAL)
}

pub(super) async fn wasix_sock_accept_v2<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    flags: i32,
    ret_fd: u32,
    ret_addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(accepted_fdflags) = u16::try_from(flags)
        .ok()
        .filter(|fdflags| p1_socket_fdflags_supported(*fdflags))
    else {
        return Ok(p1::errno::INVAL);
    };
    let (accepted_fd, peer_address, peer_port) =
        match wasix_sock_accepted(caller, fd, accepted_fdflags).await {
            Ok(accepted) => accepted,
            Err(errno) => return Ok(errno),
        };
    // The accept awaited, so the guest's pages are checked again as they
    // are written. A descriptor the guest never learned of is closed again.
    let written = async {
        let Some(memory) = p1_async_memory(caller) else {
            return Err(P1Stop::Errno(p1::errno::FAULT));
        };
        memory
            .write_u32(GuestAddress::wasm32(ret_fd), accepted_fd)
            .await?;
        if ret_addr != 0 {
            write_wasix_addr_port_async(
                &memory,
                GuestAddress::wasm32(ret_addr),
                Some(peer_address),
                peer_port,
            )
            .await?;
        }
        Ok(p1::errno::SUCCESS)
    }
    .await;
    if written.is_err() {
        let _ = caller.data_mut().descriptors.close(accepted_fd as i32);
    }
    written
}

/// Accepts a connection on the listening socket `fd` and installs it as a
/// descriptor: its number, and the address and port of its peer.
async fn wasix_sock_accepted<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    accepted_fdflags: u16,
) -> Result<(u32, crate::NetworkIpAddress, u16), i32>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let descriptor = caller.data().descriptors.get_cloned(fd);
    let authority = wasix_sock_listen_authority(descriptor.as_ref())?;
    let status = caller.data().require_socket_authority(authority);
    if status != p1::errno::SUCCESS {
        return Err(status);
    }
    let (listener, accept_timeout, family) = match descriptor {
        Some(Preview1Descriptor::Socket(socket)) => match socket.tcp_state() {
            Some(UnixTcpSocket::Listening {
                listener,
                options,
                family,
                ..
            }) => (
                listener.id(),
                options.time(SocketTime::AcceptTimeout),
                family,
            ),
            _ => return Err(p1::errno::INVAL),
        },
        Some(_) => return Err(p1::errno::NOTSOCK),
        None => return Err(p1::errno::BADF),
    };
    let Some(service) = caller.data().runtime_state.network_service() else {
        return Err(p1::errno::NETDOWN);
    };
    let fdflags = caller.data().descriptors.fdflags(fd)?;
    let timeout = wasix_effective_socket_timeout(accept_timeout, fdflags);
    let accepted = service
        .tcp_accept(listener, timeout)
        .await
        .map_err(|error| p1_errno_from_tcp_error_for_fdflags(error, fdflags))?;
    let peer_address = accepted.address;
    let descriptor = Preview1Descriptor::Socket(UnixSocket::from_tcp(UnixTcpSocket::Connected {
        family,
        stream: OwnedTcpStream::new(crate::UnixNetwork::new(service.clone()), accepted.stream),
        peer_address,
        peer_port: accepted.port,
        options: unix_socket_options::<Net>(),
    }));
    let accepted_fd =
        caller
            .data_mut()
            .descriptors
            .insert_with_fdflags(descriptor, false, accepted_fdflags)?;
    Ok((accepted_fd, peer_address, accepted.port))
}

pub(super) async fn wasix_sock_connect<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let started = caller
        .data()
        .runtime_state
        .profiling_enabled()
        .then(|| caller.data().cpu.now().ticks());
    let result = wasix_sock_connect_inner(caller, fd, addr).await;
    if let Some(started) = started {
        p1_record_kernel_profile(caller.data(), "wasix_sock_connect", started);
    }
    result
}

pub(super) async fn wasix_sock_connect_inner<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let (Some(address), port) = wasix_read_addr_port(&memory, GuestAddress::wasm32(addr)).await?
    else {
        return Ok(p1::errno::INVAL);
    };
    Ok(wasix_sock_connect_to(caller, fd, address, port).await)
}

async fn wasix_sock_connect_to<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    address: crate::NetworkIpAddress,
    port: u16,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let status = caller.data().require_tcp_authority();
    if status != p1::errno::SUCCESS {
        return status;
    }
    let socket = match caller.data().descriptors.get_cloned(fd) {
        Some(Preview1Descriptor::Socket(socket)) => socket,
        Some(_) => return p1::errno::NOTSOCK,
        None => return p1::errno::BADF,
    };
    let Some(tcp) = socket.tcp_state() else {
        return p1::errno::NOTSOCK;
    };
    let (local_port, connect_timeout, hop_limit, family) = match tcp {
        UnixTcpSocket::Unconnected { options, family } => (
            0,
            options.time(SocketTime::ConnectTimeout),
            options.hop_limit(),
            family,
        ),
        UnixTcpSocket::Bound {
            local_port,
            options,
            family,
            ..
        } => (
            local_port,
            options.time(SocketTime::ConnectTimeout),
            options.hop_limit(),
            family,
        ),
        UnixTcpSocket::Connected { .. } | UnixTcpSocket::Listening { .. } => {
            return p1::errno::INVAL;
        }
    };
    if !crate::unix::family_accepts(family, address) {
        return p1::errno::AFNOSUPPORT;
    }
    let Some(service) = caller.data().runtime_state.network_service() else {
        return p1::errno::NETDOWN;
    };
    let fdflags = match caller.data().descriptors.fdflags(fd) {
        Ok(fdflags) => fdflags,
        Err(errno) => return errno,
    };
    let timeout = wasix_effective_socket_timeout(connect_timeout, fdflags);
    // The typed address entry point keeps the family intact; formatting
    // it back into a host string would lose IPv6 outright.
    let stream = match service
        .tcp_connect_address(address, port, local_port, hop_limit, timeout)
        .await
    {
        Ok(stream) => stream,
        Err(error) => return p1_errno_from_tcp_error_for_fdflags(error, fdflags),
    };
    let owned = OwnedTcpStream::new(crate::UnixNetwork::new(service.clone()), stream);
    socket
        .with_tcp_mut(|slot| match *slot {
            UnixTcpSocket::Unconnected { family, options }
            | UnixTcpSocket::Bound {
                family, options, ..
            } => {
                *slot = UnixTcpSocket::Connected {
                    family,
                    stream: owned,
                    peer_address: address,
                    peer_port: port,
                    options,
                };
                p1::errno::SUCCESS
            }
            UnixTcpSocket::Connected { .. } | UnixTcpSocket::Listening { .. } => p1::errno::INVAL,
        })
        .unwrap_or(p1::errno::INVAL)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the parameter list is the guest ABI of this call, so grouping it would hide the contract and break the one-to-one match with the linker registration"
)]
pub(super) async fn wasix_sock_recv_from<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    iovs: u32,
    iovs_len: u32,
    flags: i32,
    ret_size: u32,
    ret_flags: u32,
    ret_addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let started = caller
        .data()
        .runtime_state
        .profiling_enabled()
        .then(|| caller.data().cpu.now().ticks());
    let result = wasix_sock_recv_from_inner(
        caller, fd, iovs, iovs_len, flags, ret_size, ret_flags, ret_addr,
    )
    .await;
    if let Some(started) = started {
        p1_record_kernel_profile(caller.data(), "wasix_sock_recv_from", started);
    }
    result
}

#[expect(
    clippy::too_many_arguments,
    reason = "the parameter list is the guest ABI of this call, so grouping it would hide the contract and break the one-to-one match with the linker registration"
)]
pub(super) async fn wasix_sock_recv_from_inner<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    iovs: u32,
    iovs_len: u32,
    flags: i32,
    ret_size: u32,
    ret_flags: u32,
    ret_addr: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(flags) = u16::try_from(flags)
        .ok()
        .filter(|flags| flags & !WASIX_RIFLAGS_SUPPORTED == 0)
    else {
        return Ok(p1::errno::INVAL);
    };
    let peek = flags & WASIX_RIFLAGS_RECV_PEEK != 0;
    let dont_wait = flags & WASIX_RIFLAGS_RECV_DONT_WAIT != 0;
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let (iovs, ret_size, ret_flags, ret_addr) = (
        GuestAddress::wasm32(iovs),
        GuestAddress::wasm32(ret_size),
        GuestAddress::wasm32(ret_flags),
        GuestAddress::wasm32(ret_addr),
    );
    let layout = p1_read_iovs_with_byte_len(&memory, iovs, iovs_len).await?;
    let capacity = layout.byte_len;
    let descriptor = caller.data().descriptors.get_cloned(fd);
    let authority = match wasix_sock_recv_authority(descriptor.as_ref()) {
        Ok(authority) => authority,
        Err(errno) => return Ok(errno),
    };
    let status = caller.data().require_socket_authority(authority);
    if status != p1::errno::SUCCESS {
        return Ok(status);
    }
    let Some(Preview1Descriptor::Socket(socket)) = descriptor else {
        return Ok(p1::errno::BADF);
    };
    if let Some(udp) = socket.udp_state() {
        return match udp {
            UnixUdpSocket::Bound {
                socket, options, ..
            } => {
                let Some(service) = caller.data().runtime_state.network_service() else {
                    return Ok(p1::errno::NETDOWN);
                };
                let fdflags = caller.data().descriptors.fdflags(fd)?;
                let effective_fdflags = fdflags | if dont_wait { P1_FDFLAG_NONBLOCK } else { 0 };
                let timeout = wasix_effective_socket_timeout(
                    options.time(SocketTime::ReceiveTimeout),
                    effective_fdflags,
                );
                let received = if peek {
                    service.udp_peek(socket.id(), capacity, timeout).await
                } else {
                    service.udp_receive(socket.id(), capacity, timeout).await
                };
                let datagram = match received {
                    Ok(Some(datagram)) => datagram,
                    Ok(None) => return Ok(p1::errno::AGAIN),
                    Err(error) => {
                        return Ok(p1_errno_from_udp_error_for_fdflags(
                            error,
                            effective_fdflags,
                        ));
                    }
                };
                memory
                    .write_iovs_from_bytes(&layout.iovs, &datagram.bytes, ret_size)
                    .await?;
                let ro_flags = if datagram.original_len > capacity as usize {
                    WASIX_ROFLAGS_DATA_TRUNCATED
                } else {
                    0
                };
                memory.write_u16(ret_flags, ro_flags).await?;
                write_wasix_addr_port_async(
                    &memory,
                    ret_addr,
                    Some(datagram.address),
                    datagram.port,
                )
                .await?;
                Ok(p1::errno::SUCCESS)
            }
            UnixUdpSocket::Unbound { .. } => Ok(p1::errno::INVAL),
        };
    }
    if socket.is_pair() {
        let fdflags = caller.data().descriptors.fdflags(fd)?;
        let effective_fdflags = fdflags | if dont_wait { P1_FDFLAG_NONBLOCK } else { 0 };
        let bytes = caller
            .data_mut()
            .recv_socket_pair(
                fd,
                capacity as usize,
                p1_fdflags_nonblocking(effective_fdflags),
                peek,
            )
            .await?;
        memory
            .write_iovs_from_bytes(&layout.iovs, &bytes, ret_size)
            .await?;
        memory.write_u16(ret_flags, 0).await?;
        write_wasix_addr_port_async(&memory, ret_addr, None, 0).await?;
        return Ok(p1::errno::SUCCESS);
    }
    if let Some(tcp) = socket.tcp_state() {
        return match tcp {
            UnixTcpSocket::Connected {
                stream, options, ..
            } => {
                let Some(service) = caller.data().runtime_state.network_service() else {
                    return Ok(p1::errno::NETDOWN);
                };
                let fdflags = caller.data().descriptors.fdflags(fd)?;
                let effective_fdflags = fdflags | if dont_wait { P1_FDFLAG_NONBLOCK } else { 0 };
                let timeout = wasix_effective_socket_timeout(
                    options.time(SocketTime::ReceiveTimeout),
                    effective_fdflags,
                );
                // The stack copies straight out of its receive queue into the
                // guest's buffers, on this call's own poll, each page checked
                // present in the step that writes it.
                let ranges = memory.iov_ranges(&layout.iovs)?;
                let mut buffer = memory.tcp_receive_buffer(&ranges);
                let read = if peek {
                    service
                        .tcp_peek_into(stream.id(), &mut buffer, timeout)
                        .await
                } else {
                    service
                        .tcp_read_into(stream.id(), &mut buffer, timeout)
                        .await
                };
                let received = match p1_tcp_received(read)? {
                    Ok(received) => received,
                    Err(error) => {
                        return Ok(p1_errno_from_tcp_error_for_fdflags(
                            error,
                            effective_fdflags,
                        ));
                    }
                };
                memory.write_u32(ret_size, received).await?;
                memory.write_u16(ret_flags, 0).await?;
                Ok(p1::errno::SUCCESS)
            }
            _ => Ok(p1::errno::INVAL),
        };
    }
    Ok(p1::errno::INVAL)
}

pub(super) async fn wasix_sock_send_to<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    iovs: u32,
    iovs_len: u32,
    _flags: u16,
    addr: u32,
    ret_size: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let started = caller
        .data()
        .runtime_state
        .profiling_enabled()
        .then(|| caller.data().cpu.now().ticks());
    let result = wasix_sock_send_to_inner(caller, fd, iovs, iovs_len, _flags, addr, ret_size).await;
    if let Some(started) = started {
        p1_record_kernel_profile(caller.data(), "wasix_sock_send_to", started);
    }
    result
}

pub(super) async fn wasix_sock_send_to_inner<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    iovs: u32,
    iovs_len: u32,
    _flags: u16,
    addr: u32,
    ret_size: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let (iovs, ret_size) = (GuestAddress::wasm32(iovs), GuestAddress::wasm32(ret_size));
    let layout = p1_read_iovs_with_byte_len(&memory, iovs, iovs_len).await?;
    let mut gather = Preview1Gather::new(&memory, &layout)?;
    let descriptor = caller.data().descriptors.get_cloned(fd);
    let authority = match wasix_sock_send_authority(descriptor.as_ref()) {
        Ok(authority) => authority,
        Err(errno) => return Ok(errno),
    };
    let status = caller.data().require_socket_authority(authority);
    if status != p1::errno::SUCCESS {
        return Ok(status);
    }
    let Some(Preview1Descriptor::Socket(socket)) = descriptor else {
        return Ok(p1::errno::BADF);
    };
    if let Some(udp) = socket.udp_state() {
        let (Some(address), port) =
            wasix_read_addr_port(&memory, GuestAddress::wasm32(addr)).await?
        else {
            return Ok(p1::errno::INVAL);
        };
        let (udp_id, send_timeout) = match udp {
            UnixUdpSocket::Bound {
                socket, options, ..
            } => (socket.id(), options.time(SocketTime::SendTimeout)),
            UnixUdpSocket::Unbound { options, family } => {
                let Some(service) = caller.data().runtime_state.network_service() else {
                    return Ok(p1::errno::NETDOWN);
                };
                let local_address = crate::unix::unspecified_address(family);
                let binding = match service.udp_bind(local_address, 0).await {
                    Ok(binding) => binding,
                    Err(error) => return Ok(p1_errno_from_udp_error(error)),
                };
                let owned =
                    OwnedUdpSocket::new(crate::UnixNetwork::new(service.clone()), binding.socket);
                if let Err(error) = service.udp_set_hop_limit(binding.socket, options.hop_limit()) {
                    return Ok(p1_errno_from_udp_error(error));
                }
                socket
                    .with_udp_mut(|slot| match *slot {
                        UnixUdpSocket::Unbound { family, options } => {
                            let id = owned.id();
                            let send_timeout = options.time(SocketTime::SendTimeout);
                            *slot = UnixUdpSocket::Bound {
                                family,
                                socket: owned,
                                local_address,
                                local_port: binding.local_port,
                                options,
                            };
                            (id, send_timeout)
                        }
                        UnixUdpSocket::Bound {
                            ref socket,
                            options,
                            ..
                        } => (socket.id(), options.time(SocketTime::SendTimeout)),
                    })
                    .expect("UDP socket state kind cannot change")
            }
        };
        let Some(service) = caller.data().runtime_state.network_service() else {
            return Ok(p1::errno::NETDOWN);
        };
        let fdflags = caller.data().descriptors.fdflags(fd)?;
        let timeout = wasix_effective_socket_timeout(send_timeout, fdflags);
        let bytes = gather
            .datagram(
                &memory,
                crate::wasmtime_adapter::wasi::MAX_WASI_UDP_DATAGRAM_BYTES,
            )
            .await?;
        let sent = match service
            .udp_send_address(udp_id, address, port, &bytes, timeout)
            .await
        {
            Ok(sent) => sent,
            Err(error) => return Ok(p1_errno_from_udp_error_for_fdflags(error, fdflags)),
        };
        let sent = u32::try_from(sent).map_err(|_| P1Stop::Errno(p1::errno::OVERFLOW))?;
        memory.write_u32(ret_size, sent).await?;
        return Ok(p1::errno::SUCCESS);
    }
    if let Some(tcp) = socket.tcp_state() {
        return match tcp {
            UnixTcpSocket::Connected {
                stream, options, ..
            } => {
                let Some(service) = caller.data().runtime_state.network_service() else {
                    return Ok(p1::errno::NETDOWN);
                };
                let fdflags = caller.data().descriptors.fdflags(fd)?;
                let timeout =
                    wasix_effective_socket_timeout(options.time(SocketTime::SendTimeout), fdflags);
                let written = p1_send_gathered(&memory, &mut gather, |chunk| {
                    let (service, stream) = (&service, stream.id());
                    async move {
                        service
                            .tcp_write_all_bytes(stream, Bytes::from(chunk), timeout)
                            .await
                            .map_err(|error| p1_errno_from_tcp_error_for_fdflags(error, fdflags))
                    }
                })
                .await?;
                memory.write_u32(ret_size, written).await?;
                Ok(p1::errno::SUCCESS)
            }
            _ => Ok(p1::errno::INVAL),
        };
    }
    if let Some(writer) = socket.pair_writer() {
        let fdflags = caller.data().descriptors.fdflags(fd)?;
        let written = p1_send_gathered(&memory, &mut gather, |chunk| {
            p1_send_to_socketpair(&writer, chunk, fdflags)
        })
        .await?;
        memory.write_u32(ret_size, written).await?;
        return Ok(p1::errno::SUCCESS);
    }
    Ok(p1::errno::INVAL)
}

/// Reads one range of a `sock_send_file` source descriptor.
async fn wasix_read_send_file_range<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    file: &crate::wasmtime_adapter::wasi::FsDescriptor,
    offset: u64,
    count: usize,
) -> Result<Bytes, i32>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let namespace = p1_namespace(caller);
    wasi_fs::read(&namespace, p1_grant(file)?, offset, count)
        .await
        .map_err(p1_errno_from_fs)
}

pub(super) async fn wasix_sock_send_file<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    out_fd: i32,
    in_fd: i32,
    offset: i64,
    count: i64,
    ret_size: u32,
) -> Result<i32, P1Stop>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(memory) = p1_async_memory(caller) else {
        return Ok(p1::errno::FAULT);
    };
    let written = match wasix_send_file_bytes(caller, out_fd, in_fd, offset, count).await {
        Ok(written) => written,
        Err(errno) => return Ok(errno),
    };
    // The send awaited, so the guest's page is checked again as the count
    // is written.
    memory
        .write_u64(GuestAddress::wasm32(ret_size), written)
        .await?;
    Ok(p1::errno::SUCCESS)
}

/// Reads `count` bytes of the file `in_fd` from `offset` and sends them
/// to the socket `out_fd`, and answers how many went.
async fn wasix_send_file_bytes<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    out_fd: i32,
    in_fd: i32,
    offset: i64,
    count: i64,
) -> Result<u64, i32>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let file = caller
        .data()
        .descriptors
        .with(|descriptors| match descriptors.get(in_fd) {
            Some(Preview1Descriptor::File(file)) => Ok(file.node().clone()),
            Some(_) => Err(p1::errno::BADF),
            None => Err(p1::errno::BADF),
        })?;
    let offset = u64::try_from(offset).map_err(|_| p1::errno::INVAL)?;
    let count = u64::try_from(count).map_err(|_| p1::errno::INVAL)?;
    let count = usize::try_from(count).map_err(|_| p1::errno::OVERFLOW)?;
    // `sendfile` reads its source the same way `fd_pread` does: a host-share
    // file is pulled over 9p for the requested range, everything else comes
    // from the embedded node list.
    let bytes = wasix_read_send_file_range(caller, &file, offset, count).await?;
    let written = u64::try_from(bytes.len()).map_err(|_| p1::errno::OVERFLOW)?;
    match caller.data().descriptors.get_cloned(out_fd) {
        Some(Preview1Descriptor::Socket(socket)) => {
            if let Some(tcp) = socket.tcp_state() {
                return match tcp {
                    UnixTcpSocket::Connected {
                        stream, options, ..
                    } => {
                        let status = caller
                            .data()
                            .require_socket_authority(WasixSocketAuthority::Tcp);
                        if status != p1::errno::SUCCESS {
                            return Err(status);
                        }
                        let Some(service) = caller.data().runtime_state.network_service() else {
                            return Err(p1::errno::NETDOWN);
                        };
                        let fdflags = caller.data().descriptors.fdflags(out_fd)?;
                        let timeout = wasix_effective_socket_timeout(
                            options.time(SocketTime::SendTimeout),
                            fdflags,
                        );
                        service
                            .tcp_write_all_bytes(stream.id(), bytes, timeout)
                            .await
                            .map_err(|error| p1_errno_from_tcp_error_for_fdflags(error, fdflags))?;
                        Ok(written)
                    }
                    _ => Err(p1::errno::INVAL),
                };
            }
            if let Some(writer) = socket.pair_writer() {
                let fdflags = caller.data().descriptors.fdflags(out_fd)?;
                if p1_fdflags_nonblocking(fdflags) {
                    match writer.try_write(bytes) {
                        crate::TryWrite::Written => {}
                        crate::TryWrite::Full(_) => return Err(p1::errno::AGAIN),
                        crate::TryWrite::Closed => return Err(p1::errno::IO),
                    }
                } else if writer.write(bytes).await.is_err() {
                    return Err(p1::errno::IO);
                }
                Ok(written)
            } else {
                Err(p1::errno::INVAL)
            }
        }
        Some(_) => Err(p1::errno::NOTSOCK),
        None => Err(p1::errno::BADF),
    }
}

/// Reads a `__wasi_addr_port_t`, which carries the address family in
/// its tag, so both `AF_INET` and `AF_INET6` peers arrive through the
/// same entry point.
pub(super) async fn wasix_read_addr_port(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
) -> Result<(Option<crate::NetworkIpAddress>, u16), P1Stop> {
    let tag = memory.read_u8(ptr).await?;
    match tag {
        WASIX_ADDRESS_FAMILY_UNSPEC => Ok((None, 0)),
        WASIX_ADDRESS_FAMILY_IP_INET4 => {
            let port = memory
                .read_u16(ptr.offset(u64::from(WASIX_ADDR_PORT_UNION_OFFSET)))
                .await?;
            let octets = memory
                .read_array(ptr.offset(u64::from(WASIX_ADDR_PORT_IP4_ADDRESS_OFFSET)))
                .await?;
            Ok((
                Some(crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new(
                    octets,
                ))),
                port,
            ))
        }
        WASIX_ADDRESS_FAMILY_IP_INET6 => {
            let port = memory
                .read_u16(ptr.offset(u64::from(WASIX_ADDR_PORT_UNION_OFFSET)))
                .await?;
            let octets = memory
                .read_array(ptr.offset(u64::from(WASIX_ADDR_PORT_IP6_ADDRESS_OFFSET)))
                .await?;
            Ok((
                Some(crate::NetworkIpAddress::Ipv6(
                    helios_netstack::Ipv6Address::new(octets),
                )),
                port,
            ))
        }
        WASIX_ADDRESS_FAMILY_UNIX => Err(P1Stop::Errno(p1::errno::NOTSUP)),
        _ => Err(P1Stop::Errno(p1::errno::INVAL)),
    }
}

pub(super) async fn wasix_read_addr_ip4(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
) -> Result<crate::Ipv4Address, P1Stop> {
    let tag = memory.read_u8(ptr).await?;
    match tag {
        WASIX_ADDRESS_FAMILY_IP_INET4 => {
            let octets = memory
                .read_array(ptr.offset(u64::from(WASIX_ADDR_IP_UNION_OFFSET)))
                .await?;
            Ok(crate::Ipv4Address::new(octets))
        }
        WASIX_ADDRESS_FAMILY_IP_INET6 | WASIX_ADDRESS_FAMILY_UNIX => {
            Err(P1Stop::Errno(p1::errno::NOTSUP))
        }
        WASIX_ADDRESS_FAMILY_UNSPEC => Err(P1Stop::Errno(p1::errno::INVAL)),
        _ => Err(P1Stop::Errno(p1::errno::INVAL)),
    }
}

pub(super) fn wasix_validate_addr_ip6<T>(
    caller: &mut Caller<'_, T>,
    memory: Preview1Memory,
    ptr: GuestAddress,
) -> Result<(), i32> {
    let tag = p1_try_read_u8(caller, memory, ptr).map_err(|_| p1::errno::FAULT)?;
    wasix_addr_ip6_family_status(tag)?;
    let mut octets = [0_u8; 16];
    p1_read_memory_into(
        caller,
        memory,
        ptr.offset(u64::from(WASIX_ADDR_IP_UNION_OFFSET)),
        &mut octets,
    )
    .map_err(|_| p1::errno::FAULT)
}

pub(super) fn wasix_addr_ip6_family_status(tag: u8) -> Result<(), i32> {
    match tag {
        WASIX_ADDRESS_FAMILY_IP_INET6 => Ok(()),
        WASIX_ADDRESS_FAMILY_UNIX => Err(p1::errno::NOTSUP),
        WASIX_ADDRESS_FAMILY_UNSPEC | WASIX_ADDRESS_FAMILY_IP_INET4 => Err(p1::errno::INVAL),
        _ => Err(p1::errno::INVAL),
    }
}

pub(super) async fn wasix_read_addr_cidr_ip4(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
) -> Result<crate::Ipv4Cidr, P1Stop> {
    let tag = memory.read_u8(ptr).await?;
    match tag {
        WASIX_ADDRESS_FAMILY_IP_INET4 => {
            let octets = memory
                .read_array(ptr.offset(u64::from(WASIX_ADDR_CIDR_IP4_ADDRESS_OFFSET)))
                .await?;
            let prefix = memory
                .read_u8(ptr.offset(u64::from(WASIX_ADDR_CIDR_IP4_PREFIX_OFFSET)))
                .await?;
            if prefix > 32 {
                return Err(P1Stop::Errno(p1::errno::INVAL));
            }
            Ok(crate::Ipv4Cidr::new(
                crate::Ipv4Address::new(octets),
                prefix,
            ))
        }
        WASIX_ADDRESS_FAMILY_IP_INET6 | WASIX_ADDRESS_FAMILY_UNIX => {
            Err(P1Stop::Errno(p1::errno::NOTSUP))
        }
        WASIX_ADDRESS_FAMILY_UNSPEC => Err(P1Stop::Errno(p1::errno::INVAL)),
        _ => Err(P1Stop::Errno(p1::errno::INVAL)),
    }
}

pub(super) async fn wasix_read_option_pid(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
) -> Result<Option<u32>, P1Stop> {
    let tag = memory.read_u8(ptr).await?;
    match tag {
        WASIX_OPTION_NONE => Ok(None),
        WASIX_OPTION_SOME => Ok(Some(
            memory
                .read_u32(ptr.offset(u64::from(WASIX_OPTION_UNION_U32_OFFSET)))
                .await?,
        )),
        _ => Err(P1Stop::Errno(p1::errno::INVAL)),
    }
}

pub(super) fn wasix_read_optional_timestamp<T>(
    caller: &mut Caller<'_, T>,
    memory: Preview1Memory,
    ptr: GuestAddress,
) -> Result<Option<u64>, i32> {
    if ptr == GuestAddress::wasm32(0) {
        return Ok(None);
    }
    let tag = p1_try_read_u8(caller, memory, ptr).map_err(|_| p1::errno::FAULT)?;
    match tag {
        0 => Ok(None),
        1 => p1_try_read_u64(caller, memory, ptr.offset(8))
            .map(Some)
            .map_err(|_| p1::errno::FAULT),
        _ => Err(p1::errno::INVAL),
    }
}

/// An optional-`u64` record as the guest's `__wasi_option_timestamp_t`
/// lays it out: the tag, then the value at its own offset.
pub(super) fn wasix_optional_timestamp_record(value: Option<u64>) -> [u8; 16] {
    let mut record = [0_u8; 16];
    record[0] = if value.is_some() {
        WASIX_OPTION_SOME
    } else {
        WASIX_OPTION_NONE
    };
    let offset = WASIX_OPTION_UNION_U64_OFFSET as usize;
    record[offset..offset + 8].copy_from_slice(&value.unwrap_or(0).to_le_bytes());
    record
}

pub(super) fn p1_write_wasix_optional_timestamp<T>(
    caller: &mut Caller<'_, T>,
    memory: Preview1Memory,
    ptr: GuestAddress,
    value: Option<u64>,
) -> i32 {
    p1_write_memory(caller, memory, ptr, &wasix_optional_timestamp_record(value))
}

/// [`wasix_read_optional_timestamp`] for a host call that awaits.
pub(super) async fn wasix_read_optional_timestamp_async(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
) -> Result<Option<u64>, P1Stop> {
    if ptr == GuestAddress::wasm32(0) {
        return Ok(None);
    }
    match memory.read_u8(ptr).await? {
        0 => Ok(None),
        1 => Ok(Some(memory.read_u64(ptr.offset(8)).await?)),
        _ => Err(P1Stop::Errno(p1::errno::INVAL)),
    }
}

/// The boolean option a WASIX `sock_option` number names.
fn wasix_socket_flag_option(option: i32) -> Result<SocketFlag, i32> {
    Ok(match option {
        WASIX_SOCK_OPTION_REUSE_PORT => SocketFlag::ReusePort,
        WASIX_SOCK_OPTION_REUSE_ADDR => SocketFlag::ReuseAddr,
        WASIX_SOCK_OPTION_NO_DELAY => SocketFlag::NoDelay,
        WASIX_SOCK_OPTION_DONT_ROUTE => SocketFlag::DontRoute,
        WASIX_SOCK_OPTION_ONLY_V6 => SocketFlag::OnlyV6,
        WASIX_SOCK_OPTION_BROADCAST => SocketFlag::Broadcast,
        WASIX_SOCK_OPTION_MULTICAST_LOOP_V4 => SocketFlag::MulticastLoopV4,
        WASIX_SOCK_OPTION_MULTICAST_LOOP_V6 => SocketFlag::MulticastLoopV6,
        WASIX_SOCK_OPTION_PROMISCUOUS => SocketFlag::Promiscuous,
        WASIX_SOCK_OPTION_LISTENING => SocketFlag::Listening,
        WASIX_SOCK_OPTION_KEEP_ALIVE => SocketFlag::KeepAlive,
        WASIX_SOCK_OPTION_OOB_INLINE => SocketFlag::OobInline,
        _ => return Err(p1::errno::INVAL),
    })
}

/// The sized option a WASIX `sock_option` number names. The socket's type
/// and protocol read back through `sock_get_opt_size` but are not options
/// a socket records.
fn wasix_socket_size_option(option: i32) -> Result<SocketSize, i32> {
    Ok(match option {
        WASIX_SOCK_OPTION_RECV_BUF_SIZE => SocketSize::ReceiveBuffer,
        WASIX_SOCK_OPTION_SEND_BUF_SIZE => SocketSize::SendBuffer,
        WASIX_SOCK_OPTION_RECV_LOWAT => SocketSize::ReceiveLowWater,
        WASIX_SOCK_OPTION_SEND_LOWAT => SocketSize::SendLowWater,
        WASIX_SOCK_OPTION_TTL => SocketSize::Ttl,
        WASIX_SOCK_OPTION_MULTICAST_TTL_V4 => SocketSize::MulticastTtlV4,
        _ => return Err(p1::errno::INVAL),
    })
}

/// The timeout option a WASIX `sock_option` number names.
fn wasix_socket_time_option(option: i32) -> Result<SocketTime, i32> {
    Ok(match option {
        WASIX_SOCK_OPTION_RECV_TIMEOUT => SocketTime::ReceiveTimeout,
        WASIX_SOCK_OPTION_SEND_TIMEOUT => SocketTime::SendTimeout,
        WASIX_SOCK_OPTION_CONNECT_TIMEOUT => SocketTime::ConnectTimeout,
        WASIX_SOCK_OPTION_ACCEPT_TIMEOUT => SocketTime::AcceptTimeout,
        WASIX_SOCK_OPTION_LINGER => SocketTime::Linger,
        _ => return Err(p1::errno::INVAL),
    })
}

const fn wasix_socket_option_errno(error: SocketOptionError) -> i32 {
    match error {
        SocketOptionError::Unsupported => p1::errno::NOTSUP,
        SocketOptionError::Invalid => p1::errno::INVAL,
    }
}

const fn wasix_socket_option_status(result: Result<(), SocketOptionError>) -> i32 {
    match result {
        Ok(()) => p1::errno::SUCCESS,
        Err(error) => wasix_socket_option_errno(error),
    }
}

/// `sock_set_opt_flag` on a socket, as its errno.
pub(super) fn wasix_socket_set_flag<Net: ComponentHostNetwork>(
    socket: &UnixSocket<Net>,
    option: i32,
    flag: bool,
) -> i32 {
    match wasix_socket_flag_option(option) {
        Ok(option) => wasix_socket_option_status(socket.set_flag(option, flag)),
        Err(errno) => errno,
    }
}

/// `sock_get_opt_flag` on a socket.
pub(super) fn wasix_socket_flag<Net: ComponentHostNetwork>(
    socket: &UnixSocket<Net>,
    option: i32,
) -> Result<bool, i32> {
    wasix_socket_flag_option(option).map(|option| socket.options().flag(option))
}

/// `sock_set_opt_size` on a socket's recorded options, as its errno.
pub(super) fn wasix_socket_set_size<Net: ComponentHostNetwork>(
    socket: &UnixSocket<Net>,
    option: i32,
    size: u64,
) -> i32 {
    match wasix_socket_size_option(option) {
        Ok(option) => wasix_socket_option_status(socket.set_size(option, size)),
        Err(errno) => errno,
    }
}

/// A sized option a socket records.
pub(super) fn wasix_socket_size<Net: ComponentHostNetwork>(
    socket: &UnixSocket<Net>,
    option: i32,
) -> Result<u64, i32> {
    wasix_socket_size_option(option).map(|option| socket.options().size(option))
}

/// `sock_set_opt_time` on a socket, as its errno.
pub(super) fn wasix_socket_set_time<Net: ComponentHostNetwork>(
    socket: &UnixSocket<Net>,
    option: i32,
    time: Option<u64>,
) -> i32 {
    match wasix_socket_time_option(option) {
        Ok(option) => {
            socket.set_time(option, time);
            p1::errno::SUCCESS
        }
        Err(errno) => errno,
    }
}

/// `sock_get_opt_time` on a socket.
pub(super) fn wasix_socket_time<Net: ComponentHostNetwork>(
    socket: &UnixSocket<Net>,
    option: i32,
) -> Result<Option<u64>, i32> {
    wasix_socket_time_option(option).map(|option| socket.options().time(option))
}

pub(super) fn p1_write_wasix_bool<T>(
    caller: &mut Caller<'_, T>,
    memory: Preview1Memory,
    ptr: GuestAddress,
    value: bool,
) -> i32 {
    p1_write_u8(caller, memory, ptr, u8::from(value))
}

pub(super) fn p1_read_wasix_bool<T>(
    caller: &mut Caller<'_, T>,
    memory: Preview1Memory,
    ptr: GuestAddress,
) -> Result<bool, i32> {
    match p1_try_read_u8(caller, memory, ptr).map_err(|_| p1::errno::FAULT)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(p1::errno::INVAL),
    }
}

/// Writes a `__wasi_addr_t` in the address's own family. The union is
/// 16 bytes wide, so an IPv6 address fills it exactly and an IPv4 one
/// occupies its first four bytes.
pub(super) async fn write_wasix_addr_ip(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
    address: crate::NetworkIpAddress,
) -> Result<(), GuestAccessError> {
    match address {
        crate::NetworkIpAddress::Ipv4(address) => write_wasix_addr_ip4(memory, ptr, address).await,
        crate::NetworkIpAddress::Ipv6(address) => {
            memory
                .write_bytes(ptr, &[WASIX_ADDRESS_FAMILY_IP_INET6])
                .await?;
            memory
                .write_bytes(
                    ptr.offset(u64::from(WASIX_ADDR_IP_UNION_OFFSET)),
                    &address.octets(),
                )
                .await
        }
    }
}

pub(super) async fn write_wasix_addr_ip4(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
    address: crate::Ipv4Address,
) -> Result<(), GuestAccessError> {
    memory
        .write_bytes(ptr, &[WASIX_ADDRESS_FAMILY_IP_INET4])
        .await?;
    memory
        .write_bytes(
            ptr.offset(u64::from(WASIX_ADDR_IP_UNION_OFFSET)),
            &address.octets(),
        )
        .await
}

pub(super) async fn write_wasix_addr_cidr_ip4(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
    cidr: crate::Ipv4Cidr,
) -> Result<(), GuestAccessError> {
    let mut bytes = [0_u8; WASIX_ADDR_CIDR_SIZE as usize];
    bytes[0] = WASIX_ADDRESS_FAMILY_IP_INET4;
    bytes[WASIX_ADDR_CIDR_IP4_ADDRESS_OFFSET as usize
        ..WASIX_ADDR_CIDR_IP4_ADDRESS_OFFSET as usize + 4]
        .copy_from_slice(&cidr.address().octets());
    bytes[WASIX_ADDR_CIDR_IP4_PREFIX_OFFSET as usize] = cidr.prefix_len();
    memory.write_bytes(ptr, &bytes).await
}

pub(super) async fn write_wasix_route_ip4(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
    route: crate::Ipv4Route,
) -> Result<(), GuestAccessError> {
    write_wasix_addr_cidr_ip4(
        memory,
        ptr.offset(u64::from(WASIX_ROUTE_CIDR_OFFSET)),
        route.destination(),
    )
    .await?;
    write_wasix_addr_ip4(
        memory,
        ptr.offset(u64::from(WASIX_ROUTE_ROUTER_OFFSET)),
        route.gateway(),
    )
    .await?;
    memory
        .write_bytes(
            ptr.offset(u64::from(WASIX_ROUTE_PREFERRED_UNTIL_OFFSET)),
            &wasix_optional_timestamp_record(route.preferred_until_nanos()),
        )
        .await?;
    memory
        .write_bytes(
            ptr.offset(u64::from(WASIX_ROUTE_EXPIRES_AT_OFFSET)),
            &wasix_optional_timestamp_record(route.expires_at_nanos()),
        )
        .await
}

/// Writes a `__wasi_addr_port_t` in the address's own family, so an
/// `AF_INET6` peer is reported as one rather than being flattened.
pub(super) fn write_wasix_addr_port<T>(
    caller: &mut Caller<'_, T>,
    memory: Preview1Memory,
    ptr: GuestAddress,
    address: crate::NetworkIpAddress,
    port: u16,
) -> i32 {
    let (record, len) = wasix_addr_port_record(Some(address), port);
    p1_write_memory(caller, memory, ptr, &record[..len])
}

pub(super) fn write_wasix_addr_port_unspec<T>(
    caller: &mut Caller<'_, T>,
    memory: Preview1Memory,
    ptr: GuestAddress,
) -> i32 {
    let (record, len) = wasix_addr_port_record(None, 0);
    p1_write_memory(caller, memory, ptr, &record[..len])
}

/// [`write_wasix_addr_port`] and [`write_wasix_addr_port_unspec`] for a
/// host call that awaits: `None` is `AF_UNSPEC`.
pub(super) async fn write_wasix_addr_port_async(
    memory: &Preview1AsyncMemory,
    ptr: GuestAddress,
    address: Option<crate::NetworkIpAddress>,
    port: u16,
) -> Result<(), GuestAccessError> {
    let (record, len) = wasix_addr_port_record(address, port);
    memory.write_bytes(ptr, &record[..len]).await
}

/// A `__wasi_addr_port_t` in the address's own family, and how many of its
/// bytes the family uses: an `AF_UNSPEC` or `AF_INET` record fills the tag,
/// the port and four address bytes, an `AF_INET6` one sixteen.
fn wasix_addr_port_record(
    address: Option<crate::NetworkIpAddress>,
    port: u16,
) -> ([u8; 20], usize) {
    let mut record = [0_u8; 20];
    let port_offset = WASIX_ADDR_PORT_UNION_OFFSET as usize;
    record[port_offset..port_offset + 2].copy_from_slice(&port.to_le_bytes());
    let address_offset = WASIX_ADDR_PORT_IP4_ADDRESS_OFFSET as usize;
    match address {
        None => {
            record[0] = WASIX_ADDRESS_FAMILY_UNSPEC;
            (record, address_offset + 4)
        }
        Some(crate::NetworkIpAddress::Ipv4(address)) => {
            record[0] = WASIX_ADDRESS_FAMILY_IP_INET4;
            record[address_offset..address_offset + 4].copy_from_slice(&address.octets());
            (record, address_offset + 4)
        }
        Some(crate::NetworkIpAddress::Ipv6(address)) => {
            record[0] = WASIX_ADDRESS_FAMILY_IP_INET6;
            let address_offset = WASIX_ADDR_PORT_IP6_ADDRESS_OFFSET as usize;
            record[address_offset..address_offset + 16].copy_from_slice(&address.octets());
            (record, address_offset + 16)
        }
    }
}

pub(super) fn wasix_effective_socket_timeout(option_timeout: Option<u64>, fdflags: u16) -> u64 {
    if p1_fdflags_nonblocking(fdflags) {
        0
    } else {
        option_timeout.unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_over(bytes: &mut [u8]) -> Preview1AsyncMemory {
        Preview1AsyncMemory::new(Preview1Memory {
            base: bytes.as_mut_ptr() as usize,
            len: bytes.len(),
        })
    }

    fn run<F: Future>(future: F) -> F::Output {
        futures_lite::future::block_on(future)
    }

    /// An optional pid decodes as the guest's record has it: a tag, then
    /// the value at its own offset; a tag that is neither is `EINVAL` and
    /// a record outside memory is `EFAULT`.
    #[test]
    fn an_optional_pid_decodes_its_tag_and_value() {
        let mut guest = vec![0_u8; 32];
        guest[8] = WASIX_OPTION_SOME;
        guest[8 + WASIX_OPTION_UNION_U32_OFFSET as usize..][..4]
            .copy_from_slice(&4242_u32.to_le_bytes());
        guest[16] = WASIX_OPTION_NONE;
        guest[24] = 9;
        guest[30] = WASIX_OPTION_SOME;
        let memory = memory_over(&mut guest);
        let read = |ptr| run(wasix_read_option_pid(&memory, GuestAddress::wasm32(ptr)));
        assert_eq!(read(8), Ok(Some(4242)));
        assert_eq!(read(16), Ok(None));
        assert_eq!(read(24), Err(P1Stop::Errno(p1::errno::INVAL)));
        assert_eq!(read(32), Err(P1Stop::Errno(p1::errno::FAULT)));
        assert_eq!(
            read(30),
            Err(P1Stop::Errno(p1::errno::FAULT)),
            "the value of a record that starts inside memory but ends outside it"
        );
    }

    /// An IPv4 address record that straddles a present page and one swap
    /// has taken, at the end of a two-page memory.
    fn ip4_record_over_an_evicted_page() -> (crate::memory::GuestSwap, GuestAddress) {
        let mut swap = crate::memory::GuestSwap::new(2);
        // The tag on page zero, the octets on page one.
        let at = TEST_PAGE - WASIX_ADDR_IP_UNION_OFFSET as usize;
        swap.bytes_mut()[at] = WASIX_ADDRESS_FAMILY_IP_INET4;
        swap.bytes_mut()[TEST_PAGE..TEST_PAGE + 4].copy_from_slice(&[198, 51, 100, 7]);
        swap.evict(1);
        (swap, GuestAddress::wasm32(at as u32))
    }

    /// Reading a socket address whose octets are on a page that is out
    /// waits for the page, asks for it, and once it is back decodes the
    /// address the guest wrote, not the page's absence.
    #[test]
    fn an_address_on_an_evicted_page_reads_once_the_page_is_back() {
        let (mut swap, record) = ip4_record_over_an_evicted_page();
        let memory = Preview1AsyncMemory::over_swap(&swap);
        let mut read = core::pin::pin!(wasix_read_addr_ip4(&memory, record));
        assert!(poll_once(read.as_mut()).is_none(), "the read waits");
        assert_eq!(swap.queued_faults(), 1, "the page was asked for");

        swap.serve();
        assert_eq!(
            poll_once(read.as_mut()),
            Some(Ok(crate::Ipv4Address::new([198, 51, 100, 7])))
        );
    }

    /// The address's page cannot come back, so the call traps the guest.
    #[test]
    fn an_address_on_a_lost_page_traps_the_guest() {
        let (mut swap, record) = ip4_record_over_an_evicted_page();
        swap.fail_reads(1);
        let memory = Preview1AsyncMemory::over_swap(&swap);
        let mut read = core::pin::pin!(wasix_read_addr_ip4(&memory, record));
        assert!(poll_once(read.as_mut()).is_none());
        swap.serve();
        assert_eq!(
            poll_once(read.as_mut()),
            Some(Err(P1Stop::Trap(crate::memory::SwapFaultError::Backend)))
        );
    }

    /// A receive's source address lands on a page that was out once the
    /// page is back, whole.
    #[test]
    fn a_peer_address_lands_on_an_evicted_page_once_it_is_back() {
        let mut swap = crate::memory::GuestSwap::new(2);
        swap.evict(1);
        let memory = Preview1AsyncMemory::over_swap(&swap);
        let at = GuestAddress::wasm32((TEST_PAGE - 4) as u32);
        let peer = crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([203, 0, 113, 9]));
        let mut write = core::pin::pin!(write_wasix_addr_port_async(&memory, at, Some(peer), 8080));
        assert!(poll_once(write.as_mut()).is_none());
        swap.serve();
        assert_eq!(poll_once(write.as_mut()), Some(Ok(())));

        let mut plain = vec![0_u8; 2 * TEST_PAGE];
        run(write_wasix_addr_port_async(
            &memory_over(&mut plain),
            at,
            Some(peer),
            8080,
        ))
        .expect("in bounds");
        assert!(
            swap.bytes()[TEST_PAGE - 4..TEST_PAGE + 16] == plain[TEST_PAGE - 4..TEST_PAGE + 16],
            "the record is the one a present page gets"
        );
    }

    type TestNetService = crate::network::NetworkService<
        crate::test_support::ManualClockCpu,
        crate::test_support::RecordingNetworkInterface,
    >;
    type TestProgramStore = Preview1ProgramStore<
        crate::test_support::ManualClockCpu,
        TestNetService,
        crate::test_support::UnsupportedStorage,
    >;

    const TEST_LOCAL_V4_A: helios_netstack::Ipv4Address =
        helios_netstack::Ipv4Address::new([192, 0, 2, 10]);
    const TEST_LOCAL_V4_B: helios_netstack::Ipv4Address =
        helios_netstack::Ipv4Address::new([192, 0, 2, 11]);
    const TEST_UNOWNED_V4: helios_netstack::Ipv4Address =
        helios_netstack::Ipv4Address::new([192, 0, 2, 99]);
    const TEST_PEER_V4: helios_netstack::Ipv4Address =
        helios_netstack::Ipv4Address::new([192, 0, 2, 20]);
    const TEST_LOCAL_V6_A: helios_netstack::Ipv6Address =
        helios_netstack::Ipv6Address::new([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const TEST_LOCAL_V6_B: helios_netstack::Ipv6Address =
        helios_netstack::Ipv6Address::new([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    const TEST_UNOWNED_V6: helios_netstack::Ipv6Address =
        helios_netstack::Ipv6Address::new([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]);
    const TEST_PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

    const fn ip_v4(addr: helios_netstack::Ipv4Address) -> crate::NetworkIpAddress {
        crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new(addr.octets()))
    }

    fn configured_test_net_service() -> (
        crate::test_support::ManualClockCpu,
        crate::test_support::RecordingNetworkInterface,
        TestNetService,
    ) {
        let clock = crate::test_support::ManualClockCpu::new();
        let device = crate::test_support::RecordingNetworkInterface::accepting_transmissions(1);
        let service = crate::network::NetworkService::new(
            clock.clone(),
            crate::test_support::single_node_pool(1),
            crate::test_support::test_profile_sink(),
            crate::test_support::test_uptime_clock(),
            crate::test_support::test_timer(clock.clone()),
            device.clone(),
            crate::test_support::test_root_entropy(),
        );
        service.configure_test_addresses(
            &[
                helios_netstack::Ipv4Cidr::new(TEST_LOCAL_V4_A, 24),
                helios_netstack::Ipv4Cidr::new(TEST_LOCAL_V4_B, 24),
            ],
            &[
                helios_netstack::Ipv6Cidr::new(TEST_LOCAL_V6_A, 64),
                helios_netstack::Ipv6Cidr::new(TEST_LOCAL_V6_B, 64),
            ],
            Some((
                helios_netstack::IpAddress::Ipv4(TEST_PEER_V4),
                TEST_PEER_MAC,
            )),
        );
        (clock, device, service)
    }

    fn run_with_wasix_caller<F>(
        authority: ProcessAuthority,
        service: TestNetService,
        clock: crate::test_support::ManualClockCpu,
        f: F,
    ) where
        F: for<'a> FnOnce(
                &'a mut Caller<'_, TestProgramStore>,
            ) -> core::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>
            + Send
            + Sync
            + 'static,
    {
        let engine = crate::wasmtime_adapter::engine::build_component_engine_for_platform(
            &crate::test_support::TestCpu::without_entropy(),
        )
        .expect("component engine builds on test platform");
        let memory = wasmtime::SharedMemory::new(
            &engine,
            wasmtime::MemoryType::shared(1, 1).expect("1..=1 is a valid shared memory type"),
        )
        .expect("shared guest test memory builds");
        let runtime_state: HostRuntimeState<
            crate::test_support::ManualClockCpu,
            TestNetService,
            crate::test_support::UnsupportedStorage,
        > = crate::RuntimeState::new(
            clock.timebase(),
            1,
            0,
            crate::BootPayload::for_tests(),
            GuestIsa::for_build_target(clock.native_feature_probe()),
        );
        runtime_state.install_root_entropy(crate::test_support::test_root_entropy());
        runtime_state.install_network_service(service);
        let executor = crate::Executor::new(
            crate::ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            helios_hal::cpu::ProcessorId::new(0),
        );
        let registry = crate::InstanceRegistry::new();
        let instance = registry.register("wasix-net-test", 0);
        let interrupts = Arc::new(crate::wasmtime_adapter::GuestInterrupts::new(
            1,
            clock.timebase(),
        ));
        fn read_nothing(_: &mut Vec<u8>, _: u32) {}
        let write_serial = crate::DebugSerialWriter::of::<super::test_store::DiscardPort>();
        let store_data = Preview1ProgramStore::new(
            clock.clone(),
            executor.timer(clock.clone()),
            executor
                .spawner(clock)
                .instance_spawner(crate::TaskFunding::Instance, &instance),
            runtime_state,
            interrupts,
            instance,
            None,
            Vec::new(),
            Vec::new(),
            authority,
            OutputMode::Serial,
            read_nothing,
            write_serial,
            Some(memory),
            None,
            None,
            WasixSignalState::new(),
            WasixSignalState::new(),
            Vec::new(),
            None,
            true,
            WasixProcessThreads::new(),
        );
        let mut store = wasmtime::Store::new(&engine, store_data);
        let f_cell = std::sync::Mutex::new(Some(f));
        let entry = wasmtime::Func::wrap_async(
            &mut store,
            move |mut caller: Caller<'_, TestProgramStore>, (): ()| {
                let callback = f_cell
                    .lock()
                    .expect("test callback mutex")
                    .take()
                    .expect("test callback runs once");
                Box::new(async move {
                    callback(&mut caller).await;
                    Ok(())
                })
            },
        );
        let typed = entry
            .typed::<(), ()>(&store)
            .expect("test func signature matches");
        run(typed.call_async(&mut store, ())).expect("test func run succeeds");
    }

    fn write_guest_addr_port(
        caller: &mut Caller<'_, TestProgramStore>,
        ptr: u32,
        address: crate::NetworkIpAddress,
        port: u16,
    ) {
        let (record, len) = wasix_addr_port_record(Some(address), port);
        let memory = p1_async_memory(caller).expect("guest memory");
        run(memory.write_bytes(GuestAddress::wasm32(ptr), &record[..len]))
            .expect("addr_port write fits in guest memory");
    }

    fn read_guest_addr_port(
        caller: &mut Caller<'_, TestProgramStore>,
        ptr: u32,
    ) -> (Option<crate::NetworkIpAddress>, u16) {
        let memory = p1_async_memory(caller).expect("guest memory");
        run(wasix_read_addr_port(&memory, GuestAddress::wasm32(ptr)))
            .expect("addr_port read succeeds")
    }

    fn write_guest_iov(
        caller: &mut Caller<'_, TestProgramStore>,
        iov_ptr: u32,
        buf_ptr: u32,
        buf_len: u32,
    ) {
        let memory = p1_async_memory(caller).expect("guest memory");
        run(memory.write_u32(GuestAddress::wasm32(iov_ptr), buf_ptr)).expect("iov buf");
        run(memory.write_u32(GuestAddress::wasm32(iov_ptr + 4), buf_len)).expect("iov len");
    }

    fn read_guest_u32(caller: &mut Caller<'_, TestProgramStore>, ptr: u32) -> u32 {
        let memory = p1_async_memory(caller).expect("guest memory");
        run(memory.read_u32(GuestAddress::wasm32(ptr))).expect("u32 read")
    }

    fn read_guest_u16(caller: &mut Caller<'_, TestProgramStore>, ptr: u32) -> u16 {
        let memory = p1_async_memory(caller).expect("guest memory");
        run(memory.read_u16(GuestAddress::wasm32(ptr))).expect("u16 read")
    }

    fn read_guest_bytes(
        caller: &mut Caller<'_, TestProgramStore>,
        ptr: u32,
        len: usize,
    ) -> Vec<u8> {
        let memory = p1_async_memory(caller).expect("guest memory");
        run(memory.read_bytes(GuestAddress::wasm32(ptr), len)).expect("bytes read")
    }

    fn network_authority(rights: NetworkAuthorityRights) -> ProcessAuthority {
        let mut authority = ProcessAuthority::empty();
        authority.grant_network_rights(rights);
        authority
    }

    fn build_ipv4_udp_frame(
        local_mac: [u8; 6],
        dst_ip: helios_netstack::Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use helios_netstack::{
            ETHERNET_FRAME_BYTES, EthernetFrame, EthernetProtocol, IpAddress, IpProtocol,
            Ipv4Packet, TransportChecksum, UdpPacket,
        };

        let mut frame = vec![0_u8; ETHERNET_FRAME_BYTES];
        let eth_len = EthernetFrame::encode_header(
            &mut frame,
            local_mac,
            TEST_PEER_MAC,
            EthernetProtocol::Ipv4,
        )
        .expect("ethernet header");
        let udp_start = eth_len + Ipv4Packet::MIN_HEADER_LEN;
        let udp_len = UdpPacket::encode(
            &mut frame[udp_start..],
            IpAddress::Ipv4(TEST_PEER_V4),
            IpAddress::Ipv4(dst_ip),
            src_port,
            dst_port,
            payload,
            TransportChecksum::Software,
        )
        .expect("udp packet");
        let ip_len = Ipv4Packet::encode_header(
            &mut frame[eth_len..],
            TEST_PEER_V4,
            dst_ip,
            IpProtocol::Udp,
            udp_len,
            1,
            64,
        )
        .expect("ipv4 header");
        frame.truncate(eth_len + ip_len + udp_len);
        frame
    }

    fn build_ipv4_tcp_frame(
        local_mac: [u8; 6],
        dst_ip: helios_netstack::Ipv4Address,
        header: helios_netstack::TcpHeader,
        payload: &[u8],
    ) -> Vec<u8> {
        use helios_netstack::{
            ETHERNET_FRAME_BYTES, EthernetFrame, EthernetProtocol, IpAddress, IpProtocol,
            Ipv4Packet, TcpPacket, TransportChecksum,
        };

        let mut frame = vec![0_u8; ETHERNET_FRAME_BYTES];
        let eth_len = EthernetFrame::encode_header(
            &mut frame,
            local_mac,
            TEST_PEER_MAC,
            EthernetProtocol::Ipv4,
        )
        .expect("ethernet header");
        let tcp_start = eth_len + Ipv4Packet::MIN_HEADER_LEN;
        let tcp_len = TcpPacket::encode(
            &mut frame[tcp_start..],
            IpAddress::Ipv4(TEST_PEER_V4),
            IpAddress::Ipv4(dst_ip),
            header,
            payload,
            TransportChecksum::Software,
        )
        .expect("tcp packet");
        let ip_len = Ipv4Packet::encode_header(
            &mut frame[eth_len..],
            TEST_PEER_V4,
            dst_ip,
            IpProtocol::Tcp,
            tcp_len,
            1,
            64,
        )
        .expect("ipv4 header");
        frame.truncate(eth_len + ip_len + tcp_len);
        frame
    }

    fn find_syn_ack_sequence(
        device: &crate::test_support::RecordingNetworkInterface,
        src_ip: helios_netstack::Ipv4Address,
        src_port: u16,
        dst_port: u16,
    ) -> u32 {
        use helios_netstack::{
            EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpFlags, TcpPacket,
        };

        for frame in device.transmitted_frames().into_iter().rev() {
            let Some(eth) = EthernetFrame::parse(&frame) else {
                continue;
            };
            if eth.protocol != EthernetProtocol::Ipv4 {
                continue;
            }
            let Some(ip) = Ipv4Packet::parse(eth.payload) else {
                continue;
            };
            if ip.source != src_ip || ip.protocol != IpProtocol::Tcp {
                continue;
            }
            let Some(tcp) = TcpPacket::parse(ip.payload) else {
                continue;
            };
            if tcp.source_port == src_port
                && tcp.destination_port == dst_port
                && tcp.flags.contains(TcpFlags::SYN)
                && tcp.flags.contains(TcpFlags::ACK)
            {
                return tcp.sequence;
            }
        }
        panic!("expected SYN-ACK from {src_ip:?}:{src_port} -> {dst_port}");
    }

    #[test]
    fn wasix_sock_bind_keeps_address_and_filters_udp_and_tcp_traffic() {
        let (clock, device, service) = configured_test_net_service();
        let local_mac = service.hardware_address();
        let authority =
            network_authority(NetworkAuthorityRights::TCP | NetworkAuthorityRights::UDP);
        run_with_wasix_caller(authority, service, clock, move |caller| {
            Box::pin(async move {
                // Unowned IPv4/IPv6 addresses fail with ADDRNOTAVAIL for both UDP and TCP.
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_DGRAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let udp_unowned = read_guest_u32(caller, 100) as i32;
                write_guest_addr_port(caller, 200, ip_v4(TEST_UNOWNED_V4), 5001);
                assert_eq!(
                    wasix_sock_bind(caller, udp_unowned, 200).await,
                    Ok(p1::errno::ADDRNOTAVAIL)
                );

                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET6_I32,
                        WASIX_SOCK_TYPE_DGRAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let udp6_unowned = read_guest_u32(caller, 100) as i32;
                write_guest_addr_port(
                    caller,
                    200,
                    crate::NetworkIpAddress::Ipv6(TEST_UNOWNED_V6),
                    5001,
                );
                assert_eq!(
                    wasix_sock_bind(caller, udp6_unowned, 200).await,
                    Ok(p1::errno::ADDRNOTAVAIL)
                );

                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let tcp_unowned = read_guest_u32(caller, 100) as i32;
                write_guest_addr_port(caller, 200, ip_v4(TEST_UNOWNED_V4), 8081);
                assert_eq!(
                    wasix_sock_bind(caller, tcp_unowned, 200).await,
                    Ok(p1::errno::ADDRNOTAVAIL)
                );

                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET6_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let tcp6_unowned = read_guest_u32(caller, 100) as i32;
                write_guest_addr_port(
                    caller,
                    200,
                    crate::NetworkIpAddress::Ipv6(TEST_UNOWNED_V6),
                    8081,
                );
                assert_eq!(
                    wasix_sock_bind(caller, tcp6_unowned, 200).await,
                    Ok(p1::errno::ADDRNOTAVAIL)
                );

                // IPv6 UDP bind keeps the specific owned address and reports it via sock_addr_local.
                write_guest_addr_port(
                    caller,
                    200,
                    crate::NetworkIpAddress::Ipv6(TEST_LOCAL_V6_A),
                    5002,
                );
                assert_eq!(
                    wasix_sock_bind(caller, udp6_unowned, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(
                    wasix_sock_addr_local(caller, udp6_unowned, 240),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    read_guest_addr_port(caller, 240),
                    (Some(crate::NetworkIpAddress::Ipv6(TEST_LOCAL_V6_A)), 5002)
                );

                // IPv4 UDP bind on TEST_LOCAL_V4_A:5000 only receives packets sent to TEST_LOCAL_V4_A.
                write_guest_addr_port(caller, 200, ip_v4(TEST_LOCAL_V4_A), 5000);
                assert_eq!(
                    wasix_sock_bind(caller, udp_unowned, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(
                    wasix_sock_addr_local(caller, udp_unowned, 240),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    read_guest_addr_port(caller, 240),
                    (Some(ip_v4(TEST_LOCAL_V4_A)), 5000)
                );

                device.deliver_on(
                    0,
                    &build_ipv4_udp_frame(local_mac, TEST_LOCAL_V4_B, 40000, 5000, b"wrong-ip"),
                );
                write_guest_iov(caller, 300, 400, 32);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        udp_unowned,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::AGAIN),
                    "UDP socket bound to A must not receive datagram sent to B"
                );

                device.deliver_on(
                    0,
                    &build_ipv4_udp_frame(local_mac, TEST_LOCAL_V4_A, 40001, 5000, b"right-ip"),
                );
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        udp_unowned,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                let len = read_guest_u32(caller, 500) as usize;
                assert_eq!(read_guest_bytes(caller, 400, len), b"right-ip");

                // TCP listeners on A:8080 and B:8080 coexist, report their bound address,
                // and A:8080 accepts only connections targeting A.
                write_guest_addr_port(caller, 200, ip_v4(TEST_LOCAL_V4_A), 8080);
                assert_eq!(
                    wasix_sock_bind(caller, tcp_unowned, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(
                    wasix_sock_addr_local(caller, tcp_unowned, 240),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    read_guest_addr_port(caller, 240),
                    (Some(ip_v4(TEST_LOCAL_V4_A)), 8080)
                );
                assert_eq!(
                    wasix_sock_listen(caller, tcp_unowned, 4).await,
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    wasix_sock_addr_local(caller, tcp_unowned, 240),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    read_guest_addr_port(caller, 240),
                    (Some(ip_v4(TEST_LOCAL_V4_A)), 8080)
                );

                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        104,
                    ),
                    p1::errno::SUCCESS
                );
                let tcp_b = read_guest_u32(caller, 104) as i32;
                write_guest_addr_port(caller, 200, ip_v4(TEST_LOCAL_V4_B), 8080);
                assert_eq!(
                    wasix_sock_bind(caller, tcp_b, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(
                    wasix_sock_listen(caller, tcp_b, 4).await,
                    p1::errno::SUCCESS
                );

                // SYN targeting B:8080 does not wake listener bound to A:8080.
                let listener_a = tcp_unowned;
                assert_eq!(
                    caller
                        .data_mut()
                        .descriptors
                        .set_fdflags(listener_a, P1_FDFLAG_NONBLOCK),
                    p1::errno::SUCCESS
                );
                device.deliver_on(
                    0,
                    &build_ipv4_tcp_frame(
                        local_mac,
                        TEST_LOCAL_V4_B,
                        helios_netstack::TcpHeader {
                            source_port: 41000,
                            destination_port: 8080,
                            sequence: 1000,
                            acknowledgement: 0,
                            flags: helios_netstack::TcpFlags::SYN,
                            window_size: u16::MAX,
                        },
                        &[],
                    ),
                );
                assert_eq!(
                    wasix_sock_accept_v2(caller, listener_a, 0, 600, 608).await,
                    Ok(p1::errno::AGAIN),
                    "listener bound to A must not accept SYN to B"
                );

                // SYN targeting A:8080 completes handshake on listener A.
                assert_eq!(
                    caller.data_mut().descriptors.set_fdflags(listener_a, 0),
                    p1::errno::SUCCESS
                );
                device.deliver_on(
                    0,
                    &build_ipv4_tcp_frame(
                        local_mac,
                        TEST_LOCAL_V4_A,
                        helios_netstack::TcpHeader {
                            source_port: 41001,
                            destination_port: 8080,
                            sequence: 2000,
                            acknowledgement: 0,
                            flags: helios_netstack::TcpFlags::SYN,
                            window_size: u16::MAX,
                        },
                        &[],
                    ),
                );
                {
                    let mut accept_fut =
                        core::pin::pin!(wasix_sock_accept_v2(caller, listener_a, 0, 600, 608));
                    assert!(
                        futures_lite::future::poll_once(accept_fut.as_mut())
                            .await
                            .is_none()
                    );
                    let seq = find_syn_ack_sequence(&device, TEST_LOCAL_V4_A, 8080, 41001);
                    device.deliver_on(
                        0,
                        &build_ipv4_tcp_frame(
                            local_mac,
                            TEST_LOCAL_V4_A,
                            helios_netstack::TcpHeader {
                                source_port: 41001,
                                destination_port: 8080,
                                sequence: 2001,
                                acknowledgement: seq.wrapping_add(1),
                                flags: helios_netstack::TcpFlags::ACK,
                                window_size: u16::MAX,
                            },
                            &[],
                        ),
                    );
                    assert_eq!(accept_fut.await, Ok(p1::errno::SUCCESS));
                }
            })
        });
    }

    #[test]
    fn wasix_sock_bind_enforces_shared_privilege_rule_and_exempts_port_zero() {
        let (clock, _device, service) = configured_test_net_service();
        let unprivileged =
            network_authority(NetworkAuthorityRights::TCP | NetworkAuthorityRights::UDP);
        run_with_wasix_caller(unprivileged, service, clock, move |caller| {
            Box::pin(async move {
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_DGRAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let udp = read_guest_u32(caller, 100) as i32;
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        104,
                    ),
                    p1::errno::SUCCESS
                );
                let tcp = read_guest_u32(caller, 104) as i32;

                // Low non-zero port 80 requires PRIVILEGED_BIND.
                write_guest_addr_port(
                    caller,
                    200,
                    crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([0, 0, 0, 0])),
                    80,
                );
                assert_eq!(
                    wasix_sock_bind(caller, udp, 200).await,
                    Ok(p1::errno::NOTCAPABLE)
                );
                assert_eq!(
                    wasix_sock_bind(caller, tcp, 200).await,
                    Ok(p1::errno::NOTCAPABLE)
                );

                // Ephemeral port 0 is exempt from PRIVILEGED_BIND.
                write_guest_addr_port(
                    caller,
                    200,
                    crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([0, 0, 0, 0])),
                    0,
                );
                assert_eq!(
                    wasix_sock_bind(caller, udp, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(wasix_sock_addr_local(caller, udp, 240), p1::errno::SUCCESS);
                let (_, assigned_port) = read_guest_addr_port(caller, 240);
                assert_ne!(assigned_port, 0);

                assert_eq!(
                    wasix_sock_bind(caller, tcp, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(wasix_sock_listen(caller, tcp, 4).await, p1::errno::SUCCESS);
                assert_eq!(wasix_sock_addr_local(caller, tcp, 240), p1::errno::SUCCESS);
                let (_, assigned_tcp_port) = read_guest_addr_port(caller, 240);
                assert_ne!(assigned_tcp_port, 0);

                // Unprivileged port 1024 does not require PRIVILEGED_BIND.
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_DGRAM,
                        0,
                        108,
                    ),
                    p1::errno::SUCCESS
                );
                let udp_high = read_guest_u32(caller, 108) as i32;
                write_guest_addr_port(
                    caller,
                    200,
                    crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([0, 0, 0, 0])),
                    1024,
                );
                assert_eq!(
                    wasix_sock_bind(caller, udp_high, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
            })
        });

        let (clock, _device, service) = configured_test_net_service();
        let privileged = network_authority(
            NetworkAuthorityRights::TCP
                | NetworkAuthorityRights::UDP
                | NetworkAuthorityRights::PRIVILEGED_BIND,
        );
        run_with_wasix_caller(privileged, service, clock, move |caller| {
            Box::pin(async move {
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_DGRAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let udp = read_guest_u32(caller, 100) as i32;
                write_guest_addr_port(
                    caller,
                    200,
                    crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([0, 0, 0, 0])),
                    80,
                );
                assert_eq!(
                    wasix_sock_bind(caller, udp, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
            })
        });
    }

    #[test]
    fn wasix_sock_accept_v2_validates_fdflags_and_sets_them_on_accepted_fd() {
        let (clock, device, service) = configured_test_net_service();
        let local_mac = service.hardware_address();
        let authority = network_authority(NetworkAuthorityRights::TCP);
        run_with_wasix_caller(authority, service, clock, move |caller| {
            Box::pin(async move {
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let listener = read_guest_u32(caller, 100) as i32;
                write_guest_addr_port(caller, 200, ip_v4(TEST_LOCAL_V4_A), 9000);
                assert_eq!(
                    wasix_sock_bind(caller, listener, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(
                    wasix_sock_listen(caller, listener, 4).await,
                    p1::errno::SUCCESS
                );

                for bad_flags in [i32::from(P1_FDFLAG_APPEND), 0x100, -1] {
                    assert_eq!(
                        wasix_sock_accept_v2(caller, listener, bad_flags, 600, 608).await,
                        Ok(p1::errno::INVAL)
                    );
                }

                device.deliver_on(
                    0,
                    &build_ipv4_tcp_frame(
                        local_mac,
                        TEST_LOCAL_V4_A,
                        helios_netstack::TcpHeader {
                            source_port: 42000,
                            destination_port: 9000,
                            sequence: 500,
                            acknowledgement: 0,
                            flags: helios_netstack::TcpFlags::SYN,
                            window_size: u16::MAX,
                        },
                        &[],
                    ),
                );
                {
                    let mut accept_fut = core::pin::pin!(wasix_sock_accept_v2(
                        caller,
                        listener,
                        i32::from(P1_FDFLAG_NONBLOCK),
                        600,
                        608,
                    ));
                    assert!(
                        futures_lite::future::poll_once(accept_fut.as_mut())
                            .await
                            .is_none()
                    );
                    let seq = find_syn_ack_sequence(&device, TEST_LOCAL_V4_A, 9000, 42000);
                    device.deliver_on(
                        0,
                        &build_ipv4_tcp_frame(
                            local_mac,
                            TEST_LOCAL_V4_A,
                            helios_netstack::TcpHeader {
                                source_port: 42000,
                                destination_port: 9000,
                                sequence: 501,
                                acknowledgement: seq.wrapping_add(1),
                                flags: helios_netstack::TcpFlags::ACK,
                                window_size: u16::MAX,
                            },
                            &[],
                        ),
                    );
                    assert_eq!(accept_fut.await, Ok(p1::errno::SUCCESS));
                }
                let accepted_fd = read_guest_u32(caller, 600) as i32;
                assert_eq!(
                    caller.data().descriptors.fdflags(accepted_fd),
                    Ok(P1_FDFLAG_NONBLOCK)
                );

                write_guest_iov(caller, 300, 400, 16);
                assert_eq!(
                    wasix_sock_recv_from(caller, accepted_fd, 300, 1, 0, 500, 504, 0).await,
                    Ok(p1::errno::AGAIN),
                    "accepted non-blocking socket must return AGAIN when empty"
                );
            })
        });
    }

    #[test]
    fn wasix_sock_recv_from_honours_flags_peek_dont_wait_and_data_truncated() {
        let (clock, device, service) = configured_test_net_service();
        let local_mac = service.hardware_address();
        let authority =
            network_authority(NetworkAuthorityRights::TCP | NetworkAuthorityRights::UDP);
        run_with_wasix_caller(authority, service, clock, move |caller| {
            Box::pin(async move {
                // Create UDP socket, TCP connected socket, and socketpair.
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_DGRAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let udp = read_guest_u32(caller, 100) as i32;
                write_guest_addr_port(caller, 200, ip_v4(TEST_LOCAL_V4_A), 5050);
                assert_eq!(
                    wasix_sock_bind(caller, udp, 200).await,
                    Ok(p1::errno::SUCCESS)
                );

                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        104,
                    ),
                    p1::errno::SUCCESS
                );
                let listener = read_guest_u32(caller, 104) as i32;
                write_guest_addr_port(caller, 200, ip_v4(TEST_LOCAL_V4_A), 9050);
                assert_eq!(
                    wasix_sock_bind(caller, listener, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(
                    wasix_sock_listen(caller, listener, 4).await,
                    p1::errno::SUCCESS
                );
                device.deliver_on(
                    0,
                    &build_ipv4_tcp_frame(
                        local_mac,
                        TEST_LOCAL_V4_A,
                        helios_netstack::TcpHeader {
                            source_port: 43000,
                            destination_port: 9050,
                            sequence: 100,
                            acknowledgement: 0,
                            flags: helios_netstack::TcpFlags::SYN,
                            window_size: u16::MAX,
                        },
                        &[],
                    ),
                );
                let seq = {
                    let mut accept_fut =
                        core::pin::pin!(wasix_sock_accept_v2(caller, listener, 0, 600, 608));
                    assert!(
                        futures_lite::future::poll_once(accept_fut.as_mut())
                            .await
                            .is_none()
                    );
                    let seq = find_syn_ack_sequence(&device, TEST_LOCAL_V4_A, 9050, 43000);
                    device.deliver_on(
                        0,
                        &build_ipv4_tcp_frame(
                            local_mac,
                            TEST_LOCAL_V4_A,
                            helios_netstack::TcpHeader {
                                source_port: 43000,
                                destination_port: 9050,
                                sequence: 101,
                                acknowledgement: seq.wrapping_add(1),
                                flags: helios_netstack::TcpFlags::ACK,
                                window_size: u16::MAX,
                            },
                            &[],
                        ),
                    );
                    assert_eq!(accept_fut.await, Ok(p1::errno::SUCCESS));
                    seq
                };
                let tcp = read_guest_u32(caller, 600) as i32;

                assert_eq!(
                    wasix_sock_pair(
                        caller,
                        WASIX_ADDRESS_FAMILY_UNIX_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        108,
                        112,
                    ),
                    p1::errno::SUCCESS
                );
                let pair_read = read_guest_u32(caller, 108) as i32;
                let pair_write = read_guest_u32(caller, 112) as i32;

                // Unknown receive flags return INVAL across UDP, TCP, and socketpair.
                write_guest_iov(caller, 300, 400, 16);
                for fd in [udp, tcp, pair_read] {
                    for bad_flag in [1 << 1, 1 << 2, 1 << 4, 0x1_0000, -1] {
                        assert_eq!(
                            wasix_sock_recv_from(caller, fd, 300, 1, bad_flag, 500, 504, 512).await,
                            Ok(p1::errno::INVAL)
                        );
                    }
                }

                // RECV_DONT_WAIT on empty blocking UDP, TCP, and socketpair returns AGAIN.
                for fd in [udp, tcp, pair_read] {
                    assert_eq!(
                        p1_reply(
                            wasix_sock_recv_from(
                                caller,
                                fd,
                                300,
                                1,
                                i32::from(WASIX_RIFLAGS_RECV_DONT_WAIT),
                                500,
                                504,
                                512,
                            )
                            .await
                        )
                        .expect("p1 reply"),
                        p1::errno::AGAIN
                    );
                }

                // UDP: RECV_PEEK + DATA_TRUNCATED + full receive.
                device.deliver_on(
                    0,
                    &build_ipv4_udp_frame(local_mac, TEST_LOCAL_V4_A, 44000, 5050, b"hello"),
                );
                write_guest_iov(caller, 300, 400, 3);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        udp,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_PEEK | WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 3);
                assert_eq!(read_guest_u16(caller, 504), WASIX_ROFLAGS_DATA_TRUNCATED);
                assert_eq!(read_guest_bytes(caller, 400, 3), b"hel");

                write_guest_iov(caller, 300, 400, 5);
                assert_eq!(
                    wasix_sock_recv_from(caller, udp, 300, 1, 0, 500, 504, 512).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 5);
                assert_eq!(read_guest_u16(caller, 504), 0);
                assert_eq!(read_guest_bytes(caller, 400, 5), b"hello");

                // Non-peek truncated datagram sets DATA_TRUNCATED, non-truncated larger buffer does not.
                device.deliver_on(
                    0,
                    &build_ipv4_udp_frame(local_mac, TEST_LOCAL_V4_A, 44000, 5050, b"hello"),
                );
                write_guest_iov(caller, 300, 400, 3);
                assert_eq!(
                    wasix_sock_recv_from(caller, udp, 300, 1, 0, 500, 504, 512).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 3);
                assert_eq!(read_guest_u16(caller, 504), WASIX_ROFLAGS_DATA_TRUNCATED);

                device.deliver_on(
                    0,
                    &build_ipv4_udp_frame(local_mac, TEST_LOCAL_V4_A, 44000, 5050, b"hello"),
                );
                write_guest_iov(caller, 300, 400, 8);
                assert_eq!(
                    wasix_sock_recv_from(caller, udp, 300, 1, 0, 500, 504, 512).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 5);
                assert_eq!(read_guest_u16(caller, 504), 0);

                // TCP: RECV_PEEK does not consume stream bytes.
                device.deliver_on(
                    0,
                    &build_ipv4_tcp_frame(
                        local_mac,
                        TEST_LOCAL_V4_A,
                        helios_netstack::TcpHeader {
                            source_port: 43000,
                            destination_port: 9050,
                            sequence: 101,
                            acknowledgement: seq.wrapping_add(1),
                            flags: helios_netstack::TcpFlags::ACK
                                .union(helios_netstack::TcpFlags::PSH),
                            window_size: u16::MAX,
                        },
                        b"hello",
                    ),
                );
                write_guest_iov(caller, 300, 400, 3);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        tcp,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_PEEK | WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        0,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 3);
                assert_eq!(read_guest_u16(caller, 504), 0);
                assert_eq!(read_guest_bytes(caller, 400, 3), b"hel");

                write_guest_iov(caller, 300, 400, 8);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        tcp,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_PEEK),
                        500,
                        504,
                        0,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 5);
                assert_eq!(read_guest_bytes(caller, 400, 5), b"hello");

                assert_eq!(
                    wasix_sock_recv_from(caller, tcp, 300, 1, 0, 500, 504, 0).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 5);
                assert_eq!(read_guest_bytes(caller, 400, 5), b"hello");

                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        tcp,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        0,
                    )
                    .await,
                    Ok(p1::errno::AGAIN)
                );

                // Socketpair: RECV_PEEK does not consume buffered bytes.
                let writer = match caller.data().descriptors.get_cloned(pair_write) {
                    Some(Preview1Descriptor::Socket(socket)) => {
                        socket.pair_writer().expect("expected socketpair writer")
                    }
                    _ => panic!("expected socketpair descriptor"),
                };
                writer
                    .write(Bytes::from_static(b"hello"))
                    .await
                    .expect("socketpair write succeeds");

                write_guest_iov(caller, 300, 400, 3);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        pair_read,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_PEEK | WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 3);
                assert_eq!(read_guest_u16(caller, 504), 0);
                assert_eq!(read_guest_bytes(caller, 400, 3), b"hel");

                write_guest_iov(caller, 300, 400, 8);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        pair_read,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_PEEK),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 5);
                assert_eq!(read_guest_bytes(caller, 400, 5), b"hello");

                assert_eq!(
                    wasix_sock_recv_from(caller, pair_read, 300, 1, 0, 500, 504, 512).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 5);
                assert_eq!(read_guest_bytes(caller, 400, 5), b"hello");

                assert_eq!(
                    p1_reply(
                        wasix_sock_recv_from(
                            caller,
                            pair_read,
                            300,
                            1,
                            i32::from(WASIX_RIFLAGS_RECV_DONT_WAIT),
                            500,
                            504,
                            512,
                        )
                        .await
                    )
                    .expect("p1 reply"),
                    p1::errno::AGAIN
                );
            })
        });
    }

    #[test]
    fn wasix_and_preview1_nonblocking_socketpair_empty_and_zero_length() {
        let (clock, _device, service) = configured_test_net_service();
        run_with_wasix_caller(ProcessAuthority::empty(), service, clock, move |caller| {
            Box::pin(async move {
                assert_eq!(
                    wasix_sock_pair(
                        caller,
                        WASIX_ADDRESS_FAMILY_UNIX_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        100,
                        104,
                    ),
                    p1::errno::SUCCESS
                );
                let pair_read = read_guest_u32(caller, 100) as i32;
                assert_eq!(
                    caller
                        .data_mut()
                        .descriptors
                        .set_fdflags(pair_read, P1_FDFLAG_NONBLOCK),
                    p1::errno::SUCCESS
                );

                // Empty nonblocking socketpair returns AGAIN with non-zero buffer.
                write_guest_iov(caller, 300, 400, 8);
                assert_eq!(
                    p1_reply(
                        wasix_sock_recv_from(caller, pair_read, 300, 1, 0, 500, 504, 512).await
                    )
                    .expect("p1 reply"),
                    p1::errno::AGAIN
                );
                assert_eq!(
                    p1_reply(p1_sock_recv_inner(caller, pair_read, 300, 1, 0, 500, 504).await)
                        .expect("p1 reply"),
                    p1::errno::AGAIN
                );

                // Zero-length receive on empty nonblocking socketpair returns SUCCESS immediately.
                write_guest_iov(caller, 300, 400, 0);
                assert_eq!(
                    wasix_sock_recv_from(caller, pair_read, 300, 1, 0, 500, 504, 512).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 0);
                assert_eq!(read_guest_u16(caller, 504), 0);
                assert_eq!(
                    p1_sock_recv_inner(caller, pair_read, 300, 1, 0, 500, 504).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 0);
            })
        });
    }

    #[test]
    fn wasix_duplicated_udp_socket_shares_bind_and_options() {
        let (clock, device, service) = configured_test_net_service();
        let local_mac = service.hardware_address();
        let authority = network_authority(NetworkAuthorityRights::UDP);
        run_with_wasix_caller(authority, service, clock, move |caller| {
            Box::pin(async move {
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_DGRAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let fd1 = read_guest_u32(caller, 100) as i32;
                let fd2 = caller.data_mut().descriptors.dup(fd1).expect("dup") as i32;
                let fd3 = caller
                    .data_mut()
                    .descriptors
                    .dup_to(fd1, 20, true)
                    .expect("dup_to") as i32;

                // Option changes through one duplicate are visible through all others.
                assert_eq!(
                    wasix_sock_set_opt_flag(caller, fd2, WASIX_SOCK_OPTION_REUSE_ADDR, 1),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    wasix_sock_set_opt_size(caller, fd2, WASIX_SOCK_OPTION_TTL, 42),
                    p1::errno::SUCCESS
                );
                let memory = p1_async_memory(caller).expect("guest memory");
                memory
                    .write_bytes(
                        GuestAddress::wasm32(200),
                        &wasix_optional_timestamp_record(Some(123_456)),
                    )
                    .await
                    .expect("write timeout");
                assert_eq!(
                    wasix_sock_set_opt_time(caller, fd2, WASIX_SOCK_OPTION_RECV_TIMEOUT, 200),
                    p1::errno::SUCCESS
                );

                for dup_fd in [fd1, fd3] {
                    assert_eq!(
                        wasix_sock_get_opt_flag(caller, dup_fd, WASIX_SOCK_OPTION_REUSE_ADDR, 220),
                        p1::errno::SUCCESS
                    );
                    assert_eq!(read_guest_bytes(caller, 220, 1), [1]);

                    assert_eq!(
                        wasix_sock_get_opt_size(caller, dup_fd, WASIX_SOCK_OPTION_TTL, 232),
                        p1::errno::SUCCESS
                    );
                    let ttl_bytes = read_guest_bytes(caller, 232, 8);
                    assert_eq!(u64::from_le_bytes(ttl_bytes.try_into().unwrap()), 42);

                    assert_eq!(
                        wasix_sock_get_opt_time(
                            caller,
                            dup_fd,
                            WASIX_SOCK_OPTION_RECV_TIMEOUT,
                            240
                        ),
                        p1::errno::SUCCESS
                    );
                    let time_bytes = read_guest_bytes(caller, 240, 16);
                    assert_eq!(time_bytes[0], WASIX_OPTION_SOME);
                    let off = WASIX_OPTION_UNION_U64_OFFSET as usize;
                    assert_eq!(
                        u64::from_le_bytes(time_bytes[off..off + 8].try_into().unwrap()),
                        123_456
                    );
                }

                // A bind through fd1 is observed via sock_addr_local and sock_recv_from on fd3.
                write_guest_addr_port(caller, 260, ip_v4(TEST_LOCAL_V4_A), 41000);
                assert_eq!(
                    wasix_sock_bind(caller, fd1, 260).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(wasix_sock_addr_local(caller, fd3, 280), p1::errno::SUCCESS);
                assert_eq!(
                    read_guest_addr_port(caller, 280),
                    (Some(ip_v4(TEST_LOCAL_V4_A)), 41000)
                );

                device.deliver_on(
                    0,
                    &build_ipv4_udp_frame(local_mac, TEST_LOCAL_V4_A, 49000, 41000, b"dup-udp"),
                );
                write_guest_iov(caller, 300, 400, 32);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        fd3,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                let len = read_guest_u32(caller, 500) as usize;
                assert_eq!(read_guest_bytes(caller, 400, len), b"dup-udp");
                assert_eq!(
                    read_guest_addr_port(caller, 512),
                    (Some(ip_v4(TEST_PEER_V4)), 49000)
                );
            })
        });
    }

    #[test]
    fn wasix_duplicated_tcp_socket_shares_bind_listen_connect_and_options() {
        use helios_netstack::{
            EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpFlags, TcpHeader, TcpPacket,
        };

        let (clock, device, service) = configured_test_net_service();
        let local_mac = service.hardware_address();
        let authority = network_authority(NetworkAuthorityRights::TCP);
        run_with_wasix_caller(authority, service, clock, move |caller| {
            Box::pin(async move {
                // Server socket: bind on fd1, listen on fd2, accept on fd1.
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        100,
                    ),
                    p1::errno::SUCCESS
                );
                let listener_1 = read_guest_u32(caller, 100) as i32;
                let listener_2 = caller.data_mut().descriptors.dup(listener_1).expect("dup") as i32;

                assert_eq!(
                    wasix_sock_set_opt_flag(caller, listener_1, WASIX_SOCK_OPTION_REUSE_ADDR, 1),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    wasix_sock_get_opt_flag(caller, listener_2, WASIX_SOCK_OPTION_REUSE_ADDR, 220),
                    p1::errno::SUCCESS
                );
                assert_eq!(read_guest_bytes(caller, 220, 1), [1]);

                write_guest_addr_port(caller, 200, ip_v4(TEST_LOCAL_V4_A), 42000);
                assert_eq!(
                    wasix_sock_bind(caller, listener_1, 200).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(
                    wasix_sock_addr_local(caller, listener_2, 240),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    read_guest_addr_port(caller, 240),
                    (Some(ip_v4(TEST_LOCAL_V4_A)), 42000)
                );

                assert_eq!(
                    wasix_sock_listen(caller, listener_2, 4).await,
                    p1::errno::SUCCESS
                );
                device.deliver_on(
                    0,
                    &build_ipv4_tcp_frame(
                        local_mac,
                        TEST_LOCAL_V4_A,
                        TcpHeader {
                            source_port: 43001,
                            destination_port: 42000,
                            sequence: 3000,
                            acknowledgement: 0,
                            flags: TcpFlags::SYN,
                            window_size: u16::MAX,
                        },
                        &[],
                    ),
                );
                {
                    let mut accept_fut =
                        core::pin::pin!(wasix_sock_accept_v2(caller, listener_1, 0, 600, 608));
                    assert!(
                        futures_lite::future::poll_once(accept_fut.as_mut())
                            .await
                            .is_none()
                    );
                    let seq = find_syn_ack_sequence(&device, TEST_LOCAL_V4_A, 42000, 43001);
                    device.deliver_on(
                        0,
                        &build_ipv4_tcp_frame(
                            local_mac,
                            TEST_LOCAL_V4_A,
                            TcpHeader {
                                source_port: 43001,
                                destination_port: 42000,
                                sequence: 3001,
                                acknowledgement: seq.wrapping_add(1),
                                flags: TcpFlags::ACK,
                                window_size: u16::MAX,
                            },
                            &[],
                        ),
                    );
                    assert_eq!(accept_fut.await, Ok(p1::errno::SUCCESS));
                }
                assert_eq!(
                    read_guest_addr_port(caller, 608),
                    (Some(ip_v4(TEST_PEER_V4)), 43001)
                );

                // Client socket: fork/dup shares connect state, peer address, and receive stream.
                assert_eq!(
                    wasix_sock_open(
                        caller,
                        WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        104,
                    ),
                    p1::errno::SUCCESS
                );
                let client_1 = read_guest_u32(caller, 104) as i32;
                let client_2 = caller.data_mut().descriptors.dup(client_1).expect("dup") as i32;
                let forked = caller.data().descriptors.clone_for_exec();

                write_guest_addr_port(caller, 200, ip_v4(TEST_PEER_V4), 44000);
                let (src_port, client_seq) = {
                    let mut connect_fut =
                        core::pin::pin!(wasix_sock_connect(caller, client_1, 200));
                    assert!(
                        futures_lite::future::poll_once(connect_fut.as_mut())
                            .await
                            .is_none()
                    );
                    let (src_port, client_seq) = device
                        .transmitted_frames()
                        .into_iter()
                        .rev()
                        .find_map(|frame| {
                            let eth = EthernetFrame::parse(&frame)?;
                            (eth.protocol == EthernetProtocol::Ipv4).then_some(())?;
                            let ip = Ipv4Packet::parse(eth.payload)?;
                            (ip.protocol == IpProtocol::Tcp && ip.destination == TEST_PEER_V4)
                                .then_some(())?;
                            let tcp = TcpPacket::parse(ip.payload)?;
                            (tcp.destination_port == 44000
                                && tcp.flags.contains(TcpFlags::SYN)
                                && !tcp.flags.contains(TcpFlags::ACK))
                            .then_some((tcp.source_port, tcp.sequence))
                        })
                        .expect("outgoing SYN to TEST_PEER_V4:44000");

                    device.deliver_on(
                        0,
                        &build_ipv4_tcp_frame(
                            local_mac,
                            TEST_LOCAL_V4_A,
                            TcpHeader {
                                source_port: 44000,
                                destination_port: src_port,
                                sequence: 9000,
                                acknowledgement: client_seq.wrapping_add(1),
                                flags: TcpFlags::SYN.union(TcpFlags::ACK),
                                window_size: u16::MAX,
                            },
                            &[],
                        ),
                    );
                    assert_eq!(connect_fut.await, Ok(p1::errno::SUCCESS));
                    (src_port, client_seq)
                };

                assert_eq!(
                    wasix_sock_addr_peer(caller, client_2, 240),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    read_guest_addr_port(caller, 240),
                    (Some(ip_v4(TEST_PEER_V4)), 44000)
                );

                // The descriptor entry cloned before connect also shares the connected state.
                let Some(Preview1Descriptor::Socket(forked_sock)) = forked.get(client_1) else {
                    panic!("forked descriptor missing client_1 socket");
                };
                assert!(matches!(
                    forked_sock.tcp_state(),
                    Some(UnixTcpSocket::Connected {
                        peer_port: 44000,
                        ..
                    })
                ));

                device.deliver_on(
                    0,
                    &build_ipv4_tcp_frame(
                        local_mac,
                        TEST_LOCAL_V4_A,
                        TcpHeader {
                            source_port: 44000,
                            destination_port: src_port,
                            sequence: 9001,
                            acknowledgement: client_seq.wrapping_add(1),
                            flags: TcpFlags::ACK.union(TcpFlags::PSH),
                            window_size: u16::MAX,
                        },
                        b"dup-tcp",
                    ),
                );
                write_guest_iov(caller, 300, 400, 32);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        client_2,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                let len = read_guest_u32(caller, 500) as usize;
                assert_eq!(read_guest_bytes(caller, 400, len), b"dup-tcp");
            })
        });
    }

    #[test]
    fn wasix_duplicated_socketpair_shares_carry_and_options() {
        let (clock, _device, service) = configured_test_net_service();
        run_with_wasix_caller(ProcessAuthority::empty(), service, clock, move |caller| {
            Box::pin(async move {
                assert_eq!(
                    wasix_sock_pair(
                        caller,
                        WASIX_ADDRESS_FAMILY_UNIX_I32,
                        WASIX_SOCK_TYPE_STREAM,
                        0,
                        100,
                        104,
                    ),
                    p1::errno::SUCCESS
                );
                let pair_read_1 = read_guest_u32(caller, 100) as i32;
                let pair_write = read_guest_u32(caller, 104) as i32;
                let pair_read_2 =
                    caller.data_mut().descriptors.dup(pair_read_1).expect("dup") as i32;
                let forked = caller.data().descriptors.clone_for_exec();

                assert_eq!(
                    wasix_sock_set_opt_size(
                        caller,
                        pair_read_1,
                        WASIX_SOCK_OPTION_RECV_BUF_SIZE,
                        2048
                    ),
                    p1::errno::SUCCESS
                );
                assert_eq!(
                    wasix_sock_get_opt_size(
                        caller,
                        pair_read_2,
                        WASIX_SOCK_OPTION_RECV_BUF_SIZE,
                        232
                    ),
                    p1::errno::SUCCESS
                );
                let buf_bytes = read_guest_bytes(caller, 232, 8);
                assert_eq!(u64::from_le_bytes(buf_bytes.try_into().unwrap()), 2048);

                let writer = match caller.data().descriptors.get_cloned(pair_write) {
                    Some(Preview1Descriptor::Socket(socket)) => {
                        socket.pair_writer().expect("socketpair writer")
                    }
                    _ => panic!("expected socketpair descriptor"),
                };
                writer
                    .write(Bytes::from_static(b"hello world"))
                    .await
                    .expect("pair write");

                // Consume "hello" via pair_read_1; " world" stays in the shared carry buffer.
                write_guest_iov(caller, 300, 400, 5);
                assert_eq!(
                    wasix_sock_recv_from(caller, pair_read_1, 300, 1, 0, 500, 504, 512).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 5);
                assert_eq!(read_guest_bytes(caller, 400, 5), b"hello");

                // The forked descriptor snapshot sees the same 6 carried bytes.
                let Some(Preview1Descriptor::Socket(forked_read)) = forked.get(pair_read_1) else {
                    panic!("forked descriptor missing pair_read_1");
                };
                assert_eq!(forked_read.pair_read_probe().expect("pair").1, 6);

                // RECV_PEEK via pair_read_2 reads from shared carry without consuming it.
                write_guest_iov(caller, 300, 420, 16);
                assert_eq!(
                    wasix_sock_recv_from(
                        caller,
                        pair_read_2,
                        300,
                        1,
                        i32::from(WASIX_RIFLAGS_RECV_PEEK | WASIX_RIFLAGS_RECV_DONT_WAIT),
                        500,
                        504,
                        512,
                    )
                    .await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 6);
                assert_eq!(read_guest_bytes(caller, 420, 6), b" world");

                // Next read through pair_read_2 drains the shared carry buffer.
                write_guest_iov(caller, 300, 440, 16);
                assert_eq!(
                    wasix_sock_recv_from(caller, pair_read_2, 300, 1, 0, 500, 504, 512).await,
                    Ok(p1::errno::SUCCESS)
                );
                assert_eq!(read_guest_u32(caller, 500), 6);
                assert_eq!(read_guest_bytes(caller, 440, 6), b" world");

                // Nonblocking read on pair_read_1 now sees an empty buffer.
                assert_eq!(
                    caller
                        .data_mut()
                        .descriptors
                        .set_fdflags(pair_read_1, P1_FDFLAG_NONBLOCK),
                    p1::errno::SUCCESS
                );
                write_guest_iov(caller, 300, 460, 8);
                assert_eq!(
                    p1_reply(p1_sock_recv_inner(caller, pair_read_1, 300, 1, 0, 500, 504).await)
                        .expect("p1 reply"),
                    p1::errno::AGAIN
                );
            })
        });
    }
}
