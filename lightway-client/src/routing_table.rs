use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result};
use net_route::{Handle, Route};
use netdev::Interface;
use thiserror::Error;
use tracing::warn;

#[derive(PartialEq)]
pub enum RoutingMode {
    Default,
    Lan,
    NoExec,
}

#[derive(Error, Debug)]
pub enum RoutingTableError {
    #[error("Routing table handle error {0}")]
    RoutingTableHandleError(std::io::Error),
    #[error("Tun interface not found")]
    TunInterfaceNotFound,
    #[error("Default gateway not found")]
    DefaultGatewayNotFound(String),
}

pub struct RoutingTable {
    routing_mode: RoutingMode,
    added_routes: Vec<Route>,
    handle: Handle,
}

impl RoutingTable {
    pub fn new(routing_mode: RoutingMode) -> Result<Self> {
        let handle = match Handle::new() {
            Ok(handle) => handle,
            Err(e) => return Err(RoutingTableError::RoutingTableHandleError(e).into()),
        };

        Ok(Self {
            routing_mode,
            added_routes: Vec::new(),
            handle,
        })
    }

    /// Delete all the routing rules created
    pub async fn clean_up_routes(&self) {
        for route in &self.added_routes {
            if let Err(e) = self.handle.delete(route).await {
                warn!("Failed to delete route: {route:?}, error: {e}")
            }
        }
    }

    /// Initialize the routing table
    pub async fn initialize_routing_table(
        &mut self,
        tun_peer_addr: Ipv4Addr,
        peer_addr: IpAddr,
        tun_name: &str,
    ) -> Result<()> {
        if self.routing_mode == RoutingMode::NoExec {
            return Ok(());
        }

        let default_interface = self.get_default_interface_info(peer_addr).await?;

        let default_gateway_ipv4_addr = match default_interface.gateway {
            Some(gateway) => {
                let gateway_ips = gateway.ipv4;

                if gateway_ips.is_empty() {
                    return Err(RoutingTableError::DefaultGatewayNotFound(
                        "No gateway IP address found for default interface".to_string(),
                    )
                    .into());
                }

                gateway_ips[0]
            }
            None => {
                return Err(RoutingTableError::DefaultGatewayNotFound(
                    "No device found for default interface".to_string(),
                )
                .into())
            }
        };

        let server_route = Route::new(peer_addr, 32)
            .with_ifindex(default_interface.index)
            .with_gateway(default_gateway_ipv4_addr.into());
        self.add_route(server_route)
            .await
            .context("Adding peer route")?;

        // LAN routing mode adds entries to LAN IPs.
        // If any of it fails, only a warning message is printed.
        if self.routing_mode == RoutingMode::Lan {
            // 192.168.0.0/16 (RFC 1918)
            self.add_lan_route_with_warning_only(
                Ipv4Addr::new(192, 168, 0, 0),
                16,
                default_interface.index,
                default_gateway_ipv4_addr,
            )
            .await;

            // 172.16.0.0/12
            self.add_lan_route_with_warning_only(
                Ipv4Addr::new(172, 16, 0, 0),
                12,
                default_interface.index,
                default_gateway_ipv4_addr,
            )
            .await;

            // 10.0.0.0/8
            self.add_lan_route_with_warning_only(
                Ipv4Addr::new(10, 0, 0, 0),
                8,
                default_interface.index,
                default_gateway_ipv4_addr,
            )
            .await;

            // 169.254.0.0/16 (RFC 3927)
            self.add_lan_route_with_warning_only(
                Ipv4Addr::new(169, 254, 0, 0),
                16,
                default_interface.index,
                default_gateway_ipv4_addr,
            )
            .await;

            // 224.0.0.0/24 (RFC 5771)
            self.add_lan_route_with_warning_only(
                Ipv4Addr::new(224, 0, 0, 0),
                24,
                default_interface.index,
                default_gateway_ipv4_addr,
            )
            .await;
        }

        let tun_interface = get_tun_interface_info(tun_name)?;
        println!("tun inteface found: {:?}", tun_interface);
        let default_route_first = Route::new(Ipv4Addr::new(0, 0, 0, 0).into(), 1)
            .with_ifindex(tun_interface.index)
            .with_gateway(tun_peer_addr.into());
        let default_route_second = Route::new(Ipv4Addr::new(128, 0, 0, 0).into(), 1)
            .with_ifindex(tun_interface.index)
            .with_gateway(tun_peer_addr.into());

        self.add_route(default_route_first)
            .await
            .context("Adding the first default route")?;
        self.add_route(default_route_second)
            .await
            .context("Adding the first default route")?;

        Ok(())
    }

    async fn add_lan_route_with_warning_only(
        &mut self,
        destination: Ipv4Addr,
        mask: u8,
        ifindex: u32,
        gateway_addr: Ipv4Addr,
    ) {
        let route = Route::new(destination.into(), mask)
            .with_ifindex(ifindex)
            .with_gateway(gateway_addr.into());

        let dest_addr = route.destination;
        if let Err(e) = self.add_route(route).await {
            warn!(
                "Failed to add a LAN entry {} in the routing table. Error message: {e:?}",
                dest_addr
            );
        }
    }

    async fn add_route(&mut self, route: Route) -> Result<(), RoutingTableError> {
        match self.handle.add(&route).await {
            Ok(()) => {
                self.added_routes.push(route); // The route is stored so that the routes can be cleaned up when the client shuts down.
                Ok(())
            }
            Err(e) => Err(RoutingTableError::RoutingTableHandleError(e)),
        }
    }

    async fn get_default_interface_info(
        &self,
        server_addr: IpAddr,
    ) -> Result<Interface, RoutingTableError> {
        let routes = match self.handle.list().await {
            Ok(routes) => routes,
            Err(e) => return Err(RoutingTableError::RoutingTableHandleError(e)),
        };

        let default_interface_index = find_ifindex_of_best_route_for_addr(routes, server_addr)?;

        match netdev::get_interfaces()
            .into_iter()
            .find(|interface| interface.index == default_interface_index)
        {
            Some(interface) => Ok(interface),
            None => Err(RoutingTableError::TunInterfaceNotFound),
        }
    }
}

fn find_ifindex_of_best_route_for_addr(
    routes: Vec<Route>,
    addr: IpAddr,
) -> Result<u32, RoutingTableError> {
    let default_route = match routes
        .into_iter()
        .find(|route| is_within_same_subnet(route.destination, addr, route.prefix as u32))
    {
        Some(route) => route,
        None => {
            return Err(RoutingTableError::DefaultGatewayNotFound(
                "Route not found".to_string(),
            ))
        }
    };

    match default_route.ifindex {
        Some(index) => Ok(index),
        None => Err(RoutingTableError::DefaultGatewayNotFound(
            "interface index not found".to_string(),
        )),
    }
}

fn is_within_same_subnet(addr1: IpAddr, addr2: IpAddr, prefix: u32) -> bool {
    // Should not compare interfaces between IPv4 and IPv6
    if addr1.is_ipv4() && addr2.is_ipv6() || addr1.is_ipv6() && addr2.is_ipv4() {
        return false;
    }

    let number_of_host_bits = if addr1.is_ipv4() { 32 } else { 128 } - prefix;

    let get_bits = |addr: IpAddr| match addr {
        IpAddr::V4(ip) => ip.to_bits() as u128,
        IpAddr::V6(ip) => ip.to_bits(),
    };

    let addr1_network = get_bits(addr1)
        .checked_shr(number_of_host_bits)
        .unwrap_or(0);
    let addr2_network = get_bits(addr2)
        .checked_shr(number_of_host_bits)
        .unwrap_or(0);

    addr1_network == addr2_network
}

fn get_tun_interface_info(tun_name: &str) -> Result<Interface, RoutingTableError> {
    match netdev::get_interfaces()
        .into_iter()
        .find(|interface| interface.name == tun_name)
    {
        Some(interface) => Ok(interface),
        None => Err(RoutingTableError::TunInterfaceNotFound),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_case::test_case;

    use std::net::Ipv6Addr;
    use IpAddr::{V4, V6};

    #[test_case(V4(Ipv4Addr::new(192, 168, 0, 1)), V4(Ipv4Addr::new(192, 168, 14, 1)), 16 => true; "IPv4 within same subnet")]
    #[test_case(V4(Ipv4Addr::new(192, 167, 0, 1)), V4(Ipv4Addr::new(192, 168, 14, 1)), 16 => false; "IPv4 not within same subnet")]
    #[test_case(V4(Ipv4Addr::new(0, 0, 0, 0)), V4(Ipv4Addr::new(3, 58, 72, 96)), 0 => true; "default route")]
    #[test_case(V4(Ipv4Addr::new(0, 0, 0, 0)), V6(Ipv6Addr::new(1, 2, 3, 0, 0, 0, 0, 0)), 10 => false; "Comparing IPv4 and IPv6")]
    #[test_case(V6(Ipv6Addr::new(1, 2, 3, 0, 0, 0, 2, 4)), V6(Ipv6Addr::new(1, 2, 3, 0, 0, 0, 0, 0)), 48 => true; "IPv6 within same subnet")]
    #[test_case(V6(Ipv6Addr::new(1, 2, 3, 0, 0, 0, 2, 4)), V6(Ipv6Addr::new(1, 2, 4, 0, 0, 0, 0, 0)), 48 => false; "IPv6 not within same subnet")]
    fn test_is_within_same_subet(addr1: IpAddr, addr2: IpAddr, mask: u32) -> bool {
        is_within_same_subnet(addr1, addr2, mask)
    }

    fn get_default_route() -> Route {
        let mut route = Route::new(V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        route.ifindex = Some(4);

        route
    }

    fn get_docker_route() -> Route {
        let mut route = Route::new(V4(Ipv4Addr::new(172, 17, 0, 0)), 16);
        route.ifindex = Some(5);

        route
    }

    #[test_case(Vec::new(), V4(Ipv4Addr::new(3, 58, 72, 96)), Err(RoutingTableError::DefaultGatewayNotFound("Route not found".to_string())); "Empty routes")]
    #[test_case(vec![get_docker_route(), get_default_route()], V4(Ipv4Addr::new(3, 58, 72, 96)), Ok(4); "has route")]
    #[test_case(vec![get_docker_route()], V4(Ipv4Addr::new(3, 58, 72, 96)), Err(RoutingTableError::DefaultGatewayNotFound("Route not found".to_string())); "no viable default route")]
    #[test_case(vec![get_docker_route()], V4(Ipv4Addr::new(172, 17, 5, 2)), Ok(5); "found docker as default route")]
    fn test_find_ifindex_of_best_route_for_addr(
        routes: Vec<Route>,
        addr: IpAddr,
        expected_result: Result<u32, RoutingTableError>,
    ) {
        match find_ifindex_of_best_route_for_addr(routes, addr) {
            Ok(result) if expected_result.is_ok() => {
                assert_eq!(result, expected_result.unwrap());
            }
            Err(e) if expected_result.is_err() => {
                let _expected_err = expected_result.unwrap_err();
                assert!(matches!(e, _expected_err));
            }
            _otherwise => {
                panic!("Result type does not match. actual: {_otherwise:?}, expected: {expected_result:?}");
            }
        }
    }
}
