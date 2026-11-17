use std::{
    fmt::Write as _,
    io::{self, IsTerminal},
    time::Instant,
};

use anyhow::{Context, Result, anyhow};
use attestation_protocol::{
    modules::{CpuModule, GpuModule, Modules},
    report::manifest::PodManifest,
};
use clap::{Parser, ValueEnum};
use reticle::{ClientBuilder, ResponseHeaders, snp_attest::kds::Kds};
use serde::Deserialize;
use tdx_attest::pcs::Pcs;

const REPORT_WIDTH: usize = 68;

#[derive(Debug, Parser)]
#[command(
    name = "cvmcli",
    version,
    about = "Verify a confidential VM and display its attestation report",
    arg_required_else_help = true
)]
struct Args {
    /// Base URL of the Reticle attestation API
    #[arg(value_name = "API_URL")]
    api_url: String,

    /// Override the AMD certificate cache service
    #[arg(long, value_name = "URL")]
    kds_url: Option<String>,

    /// Override the Intel collateral service
    #[arg(long, value_name = "URL")]
    pcs_url: Option<String>,

    /// Override the signed Rego policy source
    #[arg(long, value_name = "URL")]
    policies_url: Option<String>,

    /// Override the signed reference measurements source
    #[arg(long, value_name = "URL")]
    measurements_url: Option<String>,

    /// Full Authorization header value (for example, "Bearer TOKEN")
    #[arg(
        long,
        env = "RETICLE_AUTHORIZATION",
        value_name = "VALUE",
        hide_env_values = true
    )]
    authorization: Option<String>,

    /// Output format; JSON includes the complete serialized attestation result
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Include response headers in the text report (always included in JSON)
    #[arg(long)]
    show_headers: bool,

    /// Control ANSI styling in the text report
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

// Read native report fields through the serialized API; pod_report() returns a JsValue.
#[derive(Deserialize)]
struct ReportView {
    attested_url: String,
    manifest: PodManifest,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy)]
struct Theme {
    enabled: bool,
}

impl Theme {
    fn new(mode: ColorMode) -> Self {
        let enabled = match mode {
            ColorMode::Auto => io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
            ColorMode::Always => true,
            ColorMode::Never => false,
        };
        Self { enabled }
    }

    fn paint(self, style: &str, text: impl AsRef<str>) -> String {
        if self.enabled {
            format!("\x1b[{style}m{}\x1b[0m", text.as_ref())
        } else {
            text.as_ref().to_owned()
        }
    }

    fn green(self, text: impl AsRef<str>) -> String {
        self.paint("1;32", text)
    }

    fn cyan(self, text: impl AsRef<str>) -> String {
        self.paint("1;36", text)
    }

    fn muted(self, text: impl AsRef<str>) -> String {
        self.paint("2", text)
    }

    fn label(self, text: impl AsRef<str>) -> String {
        self.paint("1;37", text)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let theme = Theme::new(args.color);
    let mut builder = ClientBuilder::new(&args.api_url);
    if let Some(url) = args.kds_url.as_deref() {
        builder =
            builder.with_kds(Kds::new(url).map_err(|error| anyhow!("invalid KDS URL: {error}"))?);
    }
    if let Some(url) = args.pcs_url.as_deref() {
        builder =
            builder.with_pcs(Pcs::new(url).map_err(|error| anyhow!("invalid PCS URL: {error}"))?);
    }
    if let Some(url) = args.policies_url.as_deref() {
        builder = builder
            .with_policies_url(url)
            .map_err(|error| anyhow!("invalid policies URL: {error}"))?;
    }
    if let Some(url) = args.measurements_url.as_deref() {
        builder = builder
            .with_measurements_url(url)
            .map_err(|error| anyhow!("invalid measurements URL: {error}"))?;
    }
    if let Some(authorization) = args.authorization.as_deref() {
        builder = builder
            .with_authorization(authorization)
            .map_err(|error| anyhow!("invalid authorization header: {error}"))?;
    }

    if matches!(args.output, OutputFormat::Text) {
        print_connecting(&args.api_url, theme);
    }
    let started_at = Instant::now();
    let client = builder
        .build()
        .await
        .map_err(|error| anyhow!("failed to initialize the attestation client: {error}"))?;

    let result = client
        .attest()
        .await
        .map_err(|error| anyhow!("confidential VM attestation failed: {error}"))?;
    let elapsed = started_at.elapsed();

    match args.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .context("failed to serialize the attestation result")?
        ),
        OutputFormat::Text => {
            let report: ReportView = serde_json::from_value(
                serde_json::to_value(&result)
                    .context("failed to serialize the attestation result")?,
            )
            .context("failed to read the attested manifest")?;
            println!(
                "{}",
                render_report(
                    &report.attested_url,
                    &report.manifest,
                    result.modules(),
                    result.headers(),
                    elapsed.as_millis(),
                    args.show_headers,
                    theme,
                )
            );
        }
    }
    Ok(())
}

fn print_connecting(api_url: &str, theme: Theme) {
    if io::stdout().is_terminal() {
        println!(
            "{} {}\n",
            theme.cyan("◌"),
            theme.muted(format!("Contacting {}…", compact(api_url, 52)))
        );
    }
}

fn render_report(
    api_url: &str,
    manifest: &PodManifest,
    modules: Modules,
    headers: ResponseHeaders,
    elapsed_ms: u128,
    show_headers: bool,
    theme: Theme,
) -> String {
    let cpu = cpu_name(modules.cpu());
    let gpu = modules.gpu().map(gpu_name);
    let mut output = String::new();

    top_border(&mut output, theme);
    row(
        &mut output,
        &format!("{}  CONFIDENTIAL VM ATTESTATION", theme.cyan("RETICLE //")),
    );
    divider(&mut output, theme);
    row(
        &mut output,
        &format!(
            "{}  Cryptographic evidence verified",
            theme.green("✓ VERIFIED")
        ),
    );
    row(&mut output, "");
    field(&mut output, "Target", &compact(api_url, 50), theme);
    field(&mut output, "Duration", &format_duration(elapsed_ms), theme);
    field(
        &mut output,
        "Evidence",
        "nonce-bound attestation report",
        theme,
    );
    divider(&mut output, theme);
    row(&mut output, &theme.label("TRUST CHAIN"));
    row(&mut output, "");
    chain_item(&mut output, "01", "CPU", cpu, true, theme);
    match gpu {
        Some(gpu) => chain_item(&mut output, "02", "GPU", gpu, true, theme),
        None => chain_item(&mut output, "02", "GPU", "Not presented", false, theme),
    }
    chain_item(&mut output, "03", "Policy", "Claims accepted", true, theme);

    divider(&mut output, theme);
    row(&mut output, &theme.label("ATTESTED MANIFEST"));
    row(&mut output, "");
    wrapped_field(
        &mut output,
        "PodVM",
        &sanitize(&manifest.podvm_version),
        theme,
    );
    wrapped_field(
        &mut output,
        "Workload",
        &sanitize(&manifest.workload_id),
        theme,
    );
    field(
        &mut output,
        "OHTTP key",
        if manifest.ohttp_key_config.is_some() {
            "Present (bound to attestation)"
        } else {
            "Not presented"
        },
        theme,
    );

    let mut header_names = headers.keys();
    header_names.sort_unstable();
    if show_headers {
        divider(&mut output, theme);
        row(&mut output, &theme.label("RESPONSE HEADERS"));
        row(&mut output, "");
        if header_names.is_empty() {
            row(&mut output, &theme.muted("No response headers returned"));
        } else {
            for name in header_names {
                let value = headers.get(&name).unwrap_or_default();
                field(
                    &mut output,
                    &compact(&name, 14),
                    &compact(&sanitize(&value), 45),
                    theme,
                );
            }
        }
    } else {
        row(&mut output, "");
        row(
            &mut output,
            &theme.muted(format!(
                "{} response headers · use --show-headers to inspect",
                header_names.len()
            )),
        );
    }

    bottom_border(&mut output, theme);
    output
}

fn cpu_name(cpu: CpuModule) -> &'static str {
    match cpu {
        CpuModule::Sev => "AMD SEV-SNP",
        CpuModule::Tdx => "Intel TDX",
        CpuModule::Azure => "Azure vTPM",
        _ => "Unknown confidential CPU",
    }
}

fn gpu_name(gpu: GpuModule) -> &'static str {
    match gpu {
        GpuModule::Nvidia => "NVIDIA Confidential GPU",
        _ => "Unknown confidential GPU",
    }
}

fn format_duration(elapsed_ms: u128) -> String {
    if elapsed_ms < 1_000 {
        format!("{elapsed_ms} ms")
    } else {
        format!("{:.2} s", elapsed_ms as f64 / 1_000.0)
    }
}

fn sanitize(value: &str) -> String {
    value.replace(['\r', '\n', '\t'], " ")
}

fn compact(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_owned();
    }

    let visible = max_chars.saturating_sub(1);
    let head = visible / 2;
    let tail = visible - head;
    let start: String = value.chars().take(head).collect();
    let end: String = value
        .chars()
        .rev()
        .take(tail)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}…{end}")
}

fn top_border(output: &mut String, theme: Theme) {
    let _ = writeln!(
        output,
        "{}",
        theme.cyan(format!("╭{}╮", "─".repeat(REPORT_WIDTH - 2)))
    );
}

fn bottom_border(output: &mut String, theme: Theme) {
    let _ = write!(
        output,
        "{}",
        theme.cyan(format!("╰{}╯", "─".repeat(REPORT_WIDTH - 2)))
    );
}

fn divider(output: &mut String, theme: Theme) {
    let _ = writeln!(
        output,
        "{}",
        theme.cyan(format!("├{}┤", "─".repeat(REPORT_WIDTH - 2)))
    );
}

fn row(output: &mut String, content: &str) {
    let visible_length = strip_ansi_len(content);
    let padding = REPORT_WIDTH.saturating_sub(visible_length + 4);
    let _ = writeln!(output, "│ {content}{} │", " ".repeat(padding));
}

fn field(output: &mut String, label: &str, value: &str, theme: Theme) {
    let label = format!("{:>10}", format!("{label}:"));
    row(output, &format!("{}  {value}", theme.muted(label)));
}

fn wrapped_field(output: &mut String, label: &str, value: &str, theme: Theme) {
    let chunks = char_chunks(value, 50);
    for (index, chunk) in chunks.iter().enumerate() {
        field(output, if index == 0 { label } else { "" }, chunk, theme);
    }
}

fn char_chunks(value: &str, chunk_size: usize) -> Vec<String> {
    if value.is_empty() {
        return vec![String::new()];
    }

    let characters: Vec<_> = value.chars().collect();
    characters
        .chunks(chunk_size)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

fn chain_item(
    output: &mut String,
    number: &str,
    label: &str,
    value: &str,
    verified: bool,
    theme: Theme,
) {
    let marker = if verified {
        theme.green("●")
    } else {
        theme.muted("○")
    };
    let status = if verified {
        theme.green("verified")
    } else {
        theme.muted("absent")
    };
    row(
        output,
        &format!(
            "{} {}  {:<8} {:<28} {}",
            theme.muted(number),
            marker,
            label,
            value,
            status
        ),
    );
}

fn strip_ansi_len(value: &str) -> usize {
    let mut in_escape = false;
    value
        .chars()
        .filter(|character| {
            if *character == '\x1b' {
                in_escape = true;
                return false;
            }
            if in_escape {
                if *character == 'm' {
                    in_escape = false;
                }
                return false;
            }
            true
        })
        .count()
}
