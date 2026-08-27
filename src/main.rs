mod checker;
mod input;
mod report;
mod spamhaus;

use anyhow::{Context, Result};
use clap::Parser;
use hickory_resolver::TokioResolver;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

use checker::check_domain;
use input::load_domains;
use report::write_xlsx_report;

#[derive(Parser, Debug)]
#[command(name = "db-guard")]
#[command(about = "Checks one-domain-per-line TXT files against Spamhaus DBL and exports XLSX")]
struct Cli {
    /// TXT file containing one domain per line.
    #[arg(short, long, default_value = "Domains.txt")]
    input: PathBuf,

    /// Output XLSX report.
    #[arg(short, long, default_value = "DB-Guard_Report.xlsx")]
    output: PathBuf,

    /// Spamhaus DQS key. If omitted, uses the public DBL zone.
    /// For production/automated use, DQS is strongly recommended.
    #[arg(long, env = "SPAMHAUS_DQS_KEY")]
    dqs_key: Option<String>,

    /// Maximum simultaneous DNS lookups.
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.concurrency == 0 {
        anyhow::bail!("--concurrency must be greater than zero");
    }

    let loaded = load_domains(&cli.input)
        .with_context(|| format!("failed to read {}", cli.input.display()))?;

    if loaded.domains.is_empty() {
        anyhow::bail!("input file contains no valid domains");
    }

    println!("Input lines:           {}", loaded.total_lines);
    println!("Valid entries:         {}", loaded.accepted_entries);
    println!("Duplicates removed:    {}", loaded.duplicates_removed);
    println!("Invalid entries:       {}", loaded.invalid_entries);
    println!("Unique domains:        {}", loaded.domains.len());
    println!("Spamhaus mode: {}", if cli.dqs_key.is_some() { "DQS" } else { "Public DBL" });

    let resolver = Arc::new(
        TokioResolver::builder_tokio()
            .context("failed to load system DNS configuration")?
            .build()
            .context("failed to initialize DNS resolver")?,
    );

    let semaphore = Arc::new(Semaphore::new(cli.concurrency));
    let mut tasks = Vec::with_capacity(loaded.domains.len());

    for domain in loaded.domains {
        let resolver = Arc::clone(&resolver);
        let semaphore = Arc::clone(&semaphore);
        let dqs_key = cli.dqs_key.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("semaphore closed");
            check_domain(&resolver, &domain, dqs_key.as_deref()).await
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.context("domain lookup task failed")?);
    }

    results.sort_by(|a, b| a.domain.cmp(&b.domain));

    write_xlsx_report(&cli.output, &results)
        .with_context(|| format!("failed to create {}", cli.output.display()))?;

    let listed = results.iter().filter(|r| r.is_listed()).count();
    let clean = results.iter().filter(|r| r.is_not_listed()).count();
    let errors = results.len() - listed - clean;

    println!();
    println!("Completed.");
    println!("  Checked:    {}", results.len());
    println!("  Listed:     {}", listed);
    println!("  Not listed: {}", clean);
    println!("  Errors:     {}", errors);
    println!("  Report:     {}", cli.output.display());

    Ok(())
}
