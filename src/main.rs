mod trace;
mod geoip;
mod dns;
mod caps;

use std::net::IpAddr;
use std::sync::{Arc};
use trippy::tracing::SourceAddr;
use trippy::tracing::{
    MultipathStrategy, PortDirection, TracerAddrFamily, TracerChannelConfig, TracerConfig,
    TracerProtocol,
};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use anyhow::{anyhow, Result, Error};
use dns::{DnsResolver, DnsResolveMethod, DnsResolverConfig};
use serde::{Serialize, Serializer, Deserialize};
use clap::{Command, CommandFactory, Parser, ValueEnum};
use clap::builder::Str;
use geoip::GeoIpLookup;
use indexmap::IndexMap;
use crate::caps::{drop_caps, ensure_caps};
use crate::trace::Trace;
use parking_lot::RwLock;

fn main () -> anyhow::Result<()>{
    let json = Run()?;
    Ok(())
}

fn Run() -> anyhow::Result<(String)> {
    let host = String::from("1.1.1.1");

    let mut hosts = Vec::new();
    // If we run the program now, the compiler will give an error.
    // It doesn't know the type of vec.

    hosts.push(host); // Now it knows: it's Vec<String>

    let cfg = TrippyConfig{
        targets: hosts,
        protocol: TracerProtocol::Icmp,
        addr_family: TracerAddrFamily::Ipv4,
        first_ttl: 1,
        max_ttl: 64,
        min_round_duration: Duration::from_secs(1),
        max_round_duration: Duration::from_secs(1),
        grace_duration: Duration::from_millis(100),
        max_inflight: 24,
        initial_sequence: 33000,
        tos: 0,
        read_timeout: Duration::from_secs(10),
        packet_size: 84,
        payload_pattern: 0,
        source_addr: None,
        interface: None,
        multipath_strategy: MultipathStrategy::Classic,
        port_direction: PortDirection::None,
        dns_timeout: Duration::from_secs(5),
        dns_resolve_method: DnsResolveMethod::Cloudflare,
        dns_lookup_as_info: false,
        tui_max_samples: 0,
        tui_preserve_screen: false,
        tui_refresh_rate: Default::default(),
        tui_address_mode: AddressMode::Both,
        tui_as_mode: AsMode::Asn,
        tui_geoip_mode: GeoIpMode::Off,
        tui_max_addrs: None,
        report_cycles: 2,
        geoip_mmdb_file: None,
        max_rounds: None,
        verbose: false,
        log_filter: "".to_string(),
    };
    let pid = u16::try_from(std::process::id() % u32::from(u16::MAX))?;
    let resolver = start_dns_resolver(&cfg)?;
    let geoip_lookup = create_geoip_lookup(&cfg)?;
    ensure_caps()?;
    let traces: Vec<_> = cfg
        .targets
        .iter()
        .enumerate()
        .map(|(i, target_host)| start_tracer(&cfg, target_host, pid + i as u16, &resolver))
        .collect::<anyhow::Result<Vec<_>>>()?;
    drop_caps()?;
    let json_Data = run_frontend(&cfg, resolver, traces)?;

    println!("Hello, world!");
    Ok((json_Data))
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn fixed_width<S>(val: &f64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    serializer.serialize_str(&format!("{val:.2}"))
}

pub struct TrippyConfig {
    pub targets: Vec<String>,
    pub protocol: TracerProtocol,
    pub addr_family: TracerAddrFamily,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub grace_duration: Duration,
    pub max_inflight: u8,
    pub initial_sequence: u16,
    pub tos: u8,
    pub read_timeout: Duration,
    pub packet_size: u16,
    pub payload_pattern: u8,
    pub source_addr: Option<IpAddr>,
    pub interface: Option<String>,
    pub multipath_strategy: MultipathStrategy,
    pub port_direction: PortDirection,
    pub dns_timeout: Duration,
    pub dns_resolve_method: DnsResolveMethod,
    pub dns_lookup_as_info: bool,
    pub tui_max_samples: usize,
    pub tui_preserve_screen: bool,
    pub tui_refresh_rate: Duration,
    pub tui_address_mode: AddressMode,
    pub tui_as_mode: AsMode,
    pub tui_geoip_mode: GeoIpMode,
    pub tui_max_addrs: Option<u8>,
    pub report_cycles: usize,
    pub geoip_mmdb_file: Option<String>,
    pub max_rounds: Option<usize>,
    pub verbose: bool,
    pub log_filter: String,
}

/// How to render `GeoIp` information in the hop table.
///
/// Note that the hop details view is always shown using the `Long` representation.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeoIpMode {
    /// Do not display GeoIp data.
    Off,
    /// Show short format.
    ///
    /// The `city` name is shown, `subdivision` and `country` codes are shown, `continent` is not displayed.
    ///
    /// For example:
    ///
    /// `Los Angeles, CA, US`
    Short,
    /// Show long format.
    ///
    /// The `city`, `subdivision`, `country` and `continent` names are shown.
    ///
    /// `Los Angeles, California, United States, North America`
    Long,
    /// Show latitude and Longitude format.
    ///
    /// `lat=34.0544, long=-118.2441`
    Location,
}

/// How to render AS information.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AsMode {
    /// Show the ASN.
    Asn,
    /// Display the AS prefix.
    Prefix,
    /// Display the country code.
    CountryCode,
    /// Display the registry name.
    Registry,
    /// Display the allocated date.
    Allocated,
    /// Display the AS name.
    Name,
}

/// How to render the addresses.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressMode {
    /// Show IP address only.
    IP,
    /// Show reverse-lookup DNS hostname only.
    Host,
    /// Show both IP address and reverse-lookup DNS hostname.
    Both,
}

fn start_tracer(
    cfg: &TrippyConfig,
    target_host: &str,
    trace_identifier: u16,
    resolver: &DnsResolver,
) -> Result<TraceInfo, Error> {
    let target_addr: IpAddr = resolver
        .lookup(target_host)
        .map_err(|e| anyhow!("failed to resolve target: {} ({})", target_host, e))?
        .into_iter()
        .find(|addr| {
            matches!(
                (cfg.addr_family, addr),
                (TracerAddrFamily::Ipv4, IpAddr::V4(_)) | (TracerAddrFamily::Ipv6, IpAddr::V6(_))
            )
        })
        .ok_or_else(|| {
            anyhow!(
                "failed to find an {:?} address for target: {}",
                cfg.addr_family,
                target_host
            )
        })?;
    let source_addr = match cfg.source_addr {
        None => SourceAddr::discover(target_addr, cfg.port_direction, cfg.interface.as_deref())?,
        Some(addr) => SourceAddr::validate(addr)?,
    };
    let trace_data = Arc::new(RwLock::new(Trace::new(cfg.tui_max_samples)));
    let channel_config = make_channel_config(cfg, source_addr, target_addr);
    let tracer_config = make_tracer_config(cfg, target_addr, trace_identifier)?;
    {
        let trace_data = trace_data.clone();
        thread::Builder::new()
            .name(format!("tracer-{}", tracer_config.trace_identifier.0))
            .spawn(move || {
                trace::run_backend(&tracer_config, &channel_config, trace_data)
                    .expect("failed to run tracer backend");
            })?;
    }
    Ok(make_trace_info(
        cfg,
        trace_data,
        source_addr,
        target_host.to_string(),
        target_addr,
    ))
}

/// Make the tracer configuration.
fn make_tracer_config(
    args: &TrippyConfig,
    target_addr: IpAddr,
    trace_identifier: u16,
) -> anyhow::Result<TracerConfig> {
    Ok(TracerConfig::new(
        target_addr,
        args.protocol,
        args.max_rounds,
        trace_identifier,
        args.first_ttl,
        args.max_ttl,
        args.grace_duration,
        args.max_inflight,
        args.initial_sequence,
        args.multipath_strategy,
        args.port_direction,
        args.read_timeout,
        args.min_round_duration,
        args.max_round_duration,
        args.packet_size,
        args.payload_pattern,
    )?)
}

/// Make the tracer configuration.
fn make_channel_config(
    args: &TrippyConfig,
    source_addr: IpAddr,
    target_addr: IpAddr,
) -> TracerChannelConfig {
    TracerChannelConfig::new(
        args.protocol,
        args.addr_family,
        source_addr,
        target_addr,
        args.packet_size,
        args.payload_pattern,
        args.multipath_strategy,
        args.tos,
        args.read_timeout,
        args.min_round_duration,
    )
}

/// Make the per-trace information.
fn make_trace_info(
    args: &TrippyConfig,
    trace_data: Arc<RwLock<Trace>>,
    source_addr: IpAddr,
    target: String,
    target_addr: IpAddr,
) -> TraceInfo {
    TraceInfo::new(
        trace_data,
        source_addr,
        target,
        target_addr,
        args.multipath_strategy,
        args.port_direction,
        args.protocol,
        args.addr_family,
        args.first_ttl,
        args.max_ttl,
        args.grace_duration,
        args.min_round_duration,
        args.max_round_duration,
        args.max_inflight,
        args.initial_sequence,
        args.read_timeout,
        args.packet_size,
        args.payload_pattern,
        args.interface.clone(),
        args.geoip_mmdb_file.clone(),
    )
}


fn start_dns_resolver(cfg: &TrippyConfig) -> anyhow::Result<DnsResolver> {
    Ok(match cfg.addr_family {
        TracerAddrFamily::Ipv4 => DnsResolver::start(DnsResolverConfig::new_ipv4(
            cfg.dns_resolve_method,
            cfg.dns_timeout,
        ))?,
        TracerAddrFamily::Ipv6 => DnsResolver::start(DnsResolverConfig::new_ipv6(
            cfg.dns_resolve_method,
            cfg.dns_timeout,
        ))?,
    })
}

fn run_frontend(
    args: &TrippyConfig,
    resolver: DnsResolver,
    traces: Vec<TraceInfo>,
) -> Result<(String)> {
    let json = run_report_json(&traces[0], args.report_cycles, &resolver)?;
    /*match args.mode {
        Mode::Tui => frontend::run_frontend(traces, make_tui_config(args), resolver, geoip_lookup)?,
        Mode::Stream => report::run_report_stream(&traces[0])?,
        Mode::Csv => report::run_report_csv(&traces[0], args.report_cycles, &resolver)?,
        Mode::Json => report::run_report_json(&traces[0], args.report_cycles, &resolver)?,
        Mode::Pretty => report::run_report_table_pretty(&traces[0], args.report_cycles, &resolver)?,
        Mode::Markdown => report::run_report_table_md(&traces[0], args.report_cycles, &resolver)?,
        Mode::Silent => report::run_report_silent(&traces[0], args.report_cycles)?,
    }*/
    Ok((json))
}

/// Block until trace data for round `round` is available.
fn wait_for_round(trace_data: &Arc<RwLock<Trace>>, report_cycles: usize) -> anyhow::Result<Trace> {
    let mut trace = trace_data.read().clone();
    // log to console
    println!("Waiting for {} rounds", report_cycles);
    let s = Some(report_cycles - 1);

    while trace.round().is_none() || trace.round() < s {
        trace = trace_data.read().clone();
        if let Some(err) = trace.error() {
            return Err(anyhow!("error: {}", err));
        }
        sleep(Duration::from_millis(100));
    }
    Ok(trace)
}

pub fn run_report_json(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<(String)> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    let hops: Vec<ReportHop> = trace
        .hops()
        .iter()
        .map(|hop| {
            let hosts: Vec<_> = hop
                .addrs()
                .map(|ip| Host {
                    ip: ip.to_string(),
                    hostname: resolver.reverse_lookup(*ip).to_string(),
                })
                .collect();
            ReportHop {
                ttl: hop.ttl(),
                hosts,
                loss_pct: hop.loss_pct(),
                sent: hop.total_sent(),
                last: hop.last_ms().unwrap_or_default(),
                recv: hop.total_recv(),
                avg: hop.avg_ms(),
                best: hop.best_ms().unwrap_or_default(),
                worst: hop.worst_ms().unwrap_or_default(),
                stddev: hop.stddev_ms(),
            }
        })
        .collect();

    let report = Report {
        info: ReportInfo {
            target: Host {
                ip: info.target_addr.to_string(),
                hostname: info.target_hostname.to_string(),
            },
        },
        hops,
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok((serde_json::to_string_pretty(&report).unwrap()))
}

#[derive(Serialize)]
pub struct Report {
    pub info: ReportInfo,
    pub hops: Vec<ReportHop>,
}

#[derive(Serialize)]
pub struct ReportInfo {
    pub target: Host,
}

#[derive(Serialize)]
pub struct ReportHop {
    ttl: u8,
    hosts: Vec<Host>,
    #[serde(serialize_with = "fixed_width")]
    loss_pct: f64,
    sent: usize,
    #[serde(serialize_with = "fixed_width")]
    last: f64,
    recv: usize,
    #[serde(serialize_with = "fixed_width")]
    avg: f64,
    #[serde(serialize_with = "fixed_width")]
    best: f64,
    #[serde(serialize_with = "fixed_width")]
    worst: f64,
    #[serde(serialize_with = "fixed_width")]
    stddev: f64,
}

#[derive(Serialize)]
pub struct Host {
    pub ip: String,
    pub hostname: String,
}

fn create_geoip_lookup(cfg: &TrippyConfig) -> anyhow::Result<GeoIpLookup> {
    if let Some(path) = cfg.geoip_mmdb_file.as_ref() {
        GeoIpLookup::from_file(path)
    } else {
        Ok(GeoIpLookup::empty())
    }
}

/// Information about a `Trace` needed for the Tui, stream and reports.
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub data: Arc<RwLock<Trace>>,
    pub source_addr: IpAddr,
    pub target_hostname: String,
    pub target_addr: IpAddr,
    pub multipath_strategy: MultipathStrategy,
    pub port_direction: PortDirection,
    pub protocol: TracerProtocol,
    pub addr_family: TracerAddrFamily,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub grace_duration: Duration,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub max_inflight: u8,
    pub initial_sequence: u16,
    pub read_timeout: Duration,
    pub packet_size: u16,
    pub payload_pattern: u8,
    pub interface: Option<String>,
    pub geoip_mmdb_file: Option<String>,
}

impl TraceInfo {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        data: Arc<RwLock<Trace>>,
        source_addr: IpAddr,
        target_hostname: String,
        target_addr: IpAddr,
        multipath_strategy: MultipathStrategy,
        port_direction: PortDirection,
        protocol: TracerProtocol,
        addr_family: TracerAddrFamily,
        first_ttl: u8,
        max_ttl: u8,
        grace_duration: Duration,
        min_round_duration: Duration,
        max_round_duration: Duration,
        max_inflight: u8,
        initial_sequence: u16,
        read_timeout: Duration,
        packet_size: u16,
        payload_pattern: u8,
        interface: Option<String>,
        geoip_mmdb_file: Option<String>,
    ) -> Self {
        Self {
            data,
            source_addr,
            target_hostname,
            target_addr,
            multipath_strategy,
            port_direction,
            protocol,
            addr_family,
            first_ttl,
            max_ttl,
            grace_duration,
            min_round_duration,
            max_round_duration,
            max_inflight,
            initial_sequence,
            read_timeout,
            packet_size,
            payload_pattern,
            interface,
            geoip_mmdb_file,
        }
    }
}
