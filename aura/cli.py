import argparse
import json
import sys
import shutil
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich import box

from . import __version__
from .config import load_config, save_config, set_key, get
from .scraper import scrape_cyber_threats
from .cleaner import filter_and_clean, format_for_training
from .analyzer import digital_footprint, scan_ports
from .linux_knowledge import get_linux_training_data, get_categories, LINUX_COMMANDS_DATASET
from .modelscope_trainer import (
    prepare_dataset,
    generate_swift_config,
    save_swift_yaml,
    format_for_modelscope,
    merge_datasets,
    get_training_command,
    SUPPORTED_MODELS,
)

console = Console()


def cmd_scrape(args):
    console.print("[bold cyan]Scraping cyber threat intelligence...[/]")
    data = scrape_cyber_threats()
    if not data:
        console.print("[yellow]No data scraped.[/]")
        return
    table = Table(title=f"Threat Data ({len(data)} entries)", box=box.ROUNDED)
    table.add_column("Type", style="cyan")
    table.add_column("ID/IOC", style="yellow")
    table.add_column("Score", style="red")
    table.add_column("Source", style="green")

    for item in data[:20]:
        eid = item.get("id") or item.get("ioc") or item.get("url", "")[:40] or "-"
        score = str(item.get("cvss_score", "")) if item.get("cvss_score") else "-"
        table.add_row(item.get("type", "?"), str(eid)[:50], score, item.get("source", "?"))
    console.print(table)

    out = Path(args.output) if args.output else None
    if out:
        with open(out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Saved raw data to {out}[/]")
    console.print(f"[bold]Total:[/] {len(data)} threat entries")


def cmd_clean(args):
    console.print("[bold cyan]Cleaning and filtering threat data...[/]")
    if args.input:
        try:
            with open(args.input) as f:
                raw = json.load(f)
        except Exception as e:
            console.print(f"[red]Failed to load {args.input}: {e}[/]")
            return
    else:
        console.print("[yellow]No input file. Scraping fresh data...[/]")
        raw = scrape_cyber_threats()

    cleaned = filter_and_clean(raw)
    formatted = format_for_training(cleaned)

    table = Table(title=f"Cleaning Results", box=box.ROUNDED)
    table.add_column("Stage", style="cyan")
    table.add_column("Count", style="yellow")
    table.add_row("Raw entries", str(len(raw)))
    table.add_row("After cleaning", str(len(cleaned)))
    table.add_row("Training samples", str(len(formatted)))
    console.print(table)

    out = Path(args.output) if args.output else Path("aura_dataset_clean.json")
    with open(out, "w") as f:
        json.dump(formatted, f, indent=2)
    console.print(f"[green]Saved {len(formatted)} training samples to {out}[/]")


def cmd_analyze(args):
    target = args.target
    console.print(f"[bold cyan]Analyzing: {target}[/]")

    with console.status("[bold green]Gathering intelligence..."):
        result = digital_footprint(target)

    console.print(Panel(json.dumps(result, indent=2, default=str), title="Digital Footprint", border_style="cyan"))

    if args.scan_ports:
        console.print("[bold cyan]Scanning common ports...[/]")
        ip = target if target.replace(".", "").isdigit() else result.get("analysis", {}).get("domain", {}).get("dns", {}).get("ips", [None])[0]
        if ip:
            ports = scan_ports(ip)
            if ports:
                p_table = Table(title="Open Ports", box=box.ROUNDED)
                p_table.add_column("Port", style="cyan")
                p_table.add_column("State", style="green")
                for p in ports:
                    p_table.add_row(str(p["port"]), p["state"])
                console.print(p_table)
            else:
                console.print("[yellow]No open ports found[/]")
        else:
            console.print("[red]Could not resolve IP for port scan[/]")


def cmd_linux(args):
    categories = get_categories()

    if args.category:
        filtered = [c for c in categories if args.category.lower() in c.lower()]
        if not filtered:
            console.print(f"[red]No category matching '{args.category}'[/]")
            console.print(f"Categories: {', '.join(categories)}")
            return
        items = [i for i in LINUX_COMMANDS_DATASET if any(f in i["category"].lower() for f in [args.category.lower()])]
        console.print(f"[bold cyan]Linux Commands - {filtered[0]}[/]")
        for item in items:
            console.print(Panel(
                Syntax(item["response"], "bash", theme="monokai"),
                title=f"[bold]{item['instruction']}[/]",
                border_style="green",
            ))
    else:
        table = Table(title="Linux Commands for Cybersecurity", box=box.ROUNDED)
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="yellow")
        for cat in categories:
            count = sum(1 for i in LINUX_COMMANDS_DATASET if i["category"] == cat)
            table.add_row(cat, str(count))
        console.print(table)
        console.print("[dim]Use --category <name> to view commands[/]")


def cmd_train(args):
    console.print("[bold cyan]Preparing dataset for ModelScope cloud training...[/]")

    threat_data_file = args.data
    if threat_data_file:
        with open(threat_data_file) as f:
            threat_data = json.load(f)
        console.print(f"[green]Loaded {len(threat_data)} threat samples[/]")
    else:
        console.print("[yellow]No threat data provided. Using Linux commands only.[/]")
        threat_data = []

    linux_data = get_linux_training_data()
    console.print(f"[green]Loaded {len(linux_data)} Linux command samples[/]")

    all_formatted = []

    if threat_data:
        threat_formatted = format_for_modelscope(
            format_for_training(filter_and_clean(threat_data))
        )
        all_formatted.append(threat_formatted)
        console.print(f"[green]Threat training samples: {len(threat_formatted)}[/]")

    linux_formatted = format_for_modelscope(linux_data)
    all_formatted.append(linux_formatted)
    console.print(f"[green]Linux training samples: {len(linux_formatted)}[/]")

    merged = merge_datasets(all_formatted)
    console.print(f"[bold]Total training samples: {len(merged)}[/]")

    model = args.model or get("modelscope.model_name", "Qwen/Qwen2.5-7B-Instruct")
    dataset_path = prepare_dataset(merged, name=args.name or "aura_cyber_linux")

    hyperparams = {}
    if args.epochs:
        hyperparams["epochs"] = args.epochs
    if args.lr:
        hyperparams["learning_rate"] = args.lr
    if args.batch_size:
        hyperparams["batch_size"] = args.batch_size

    config = generate_swift_config(dataset_path, model_name=model, hyperparams=hyperparams or None)

    config_file = dataset_path / "swift_config.yaml"
    save_swift_yaml(config, config_file)

    console.print(Panel(
        f"[green]Dataset:[/] {dataset_path}\n"
        f"[green]Model:[/] {model}\n"
        f"[green]Config:[/] {config_file}\n"
        f"[green]Hub ID:[/] {config['output']['hub_model_id']}\n\n"
        f"[bold]Training runs on ModelScope Cloud — zero local GPU usage[/]",
        title="ModelScope Training Ready",
        border_style="green",
    ))

    console.print("\n[bold yellow]To start cloud training:[/]")
    console.print(Syntax(
        get_training_command(str(config_file), cloud=True),
        "bash",
        theme="monokai",
    ))

    if args.zip:
        import zipfile
        zip_path = dataset_path.parent / f"{dataset_path.name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in dataset_path.iterdir():
                zf.write(f, f.name)
        console.print(f"[green]Dataset zipped: {zip_path} (upload to ModelScope)[/]")


def cmd_config(args):
    cfg = load_config()
    if args.key and args.value:
        set_key(args.key, args.value)
        console.print(f"[green]Set {args.key} = {args.value}[/]")
    elif args.key:
        val = get(args.key)
        console.print(f"{args.key} = {val}")
    else:
        console.print(Panel(json.dumps(cfg, indent=2), title="AURA Configuration", border_style="cyan"))
        console.print("\n[dim]Use: aura config <key> <value>[/]")
        console.print("[dim]Keys: modelscope.api_key, modelscope.model_name, scraper.nvd_api_key, training.epochs, etc.[/]")


def cmd_list_models(args):
    table = Table(title="Supported ModelScope Models", box=box.ROUNDED)
    table.add_column("#", style="dim")
    table.add_column("Model ID", style="cyan")
    for i, m in enumerate(SUPPORTED_MODELS, 1):
        table.add_row(str(i), m)
    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        prog="aura",
        description="AURA - AI-driven Unified Response Agent for Cybersecurity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aura scrape                           Scrape cyber threat data
  aura clean -i data.json -o clean.json Clean and filter data
  aura analyze example.com              Digital footprint analysis
  aura analyze --scan-ports 8.8.8.8     Analyze IP with port scan
  aura linux                            List Linux command categories
  aura linux -c "Network"               Show network commands
  aura train -d data.json               Prepare dataset for ModelScope training
  aura config modelscope.api_key <key>  Set API key
  aura models                           List supported models
        """,
    )
    parser.add_argument("--version", action="version", version=f"AURA v{__version__}")
    sub = parser.add_subparsers(dest="command", help="Commands")

    p_scrape = sub.add_parser("scrape", help="Scrape cyber threat intelligence")
    p_scrape.add_argument("-o", "--output", help="Save raw data to file")

    p_clean = sub.add_parser("clean", help="Clean and filter scraped data")
    p_clean.add_argument("-i", "--input", help="Input raw data file")
    p_clean.add_argument("-o", "--output", help="Output cleaned data file")

    p_analyze = sub.add_parser("analyze", help="Analyze digital footprint of a target")
    p_analyze.add_argument("target", help="IP, domain, URL, or IOC")
    p_analyze.add_argument("--scan-ports", action="store_true", help="Also scan common ports")

    p_linux = sub.add_parser("linux", help="Linux cybersecurity command knowledge base")
    p_linux.add_argument("-c", "--category", help="Filter by category name")

    p_train = sub.add_parser("train", help="Prepare dataset for ModelScope cloud training")
    p_train.add_argument("-d", "--data", help="Threat data file (optional)")
    p_train.add_argument("-m", "--model", help=f"Model name (default: {SUPPORTED_MODELS[0]})")
    p_train.add_argument("-n", "--name", default="aura_cyber_linux", help="Dataset name")
    p_train.add_argument("--epochs", type=int, help="Training epochs")
    p_train.add_argument("--lr", type=float, help="Learning rate")
    p_train.add_argument("--batch-size", type=int, help="Batch size")
    p_train.add_argument("--zip", action="store_true", help="Zip dataset for upload")

    p_config = sub.add_parser("config", help="View or set configuration")
    p_config.add_argument("key", nargs="?", help="Config key")
    p_config.add_argument("value", nargs="?", help="Config value")

    sub.add_parser("models", help="List supported ModelScope models")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        console.print("\n[bold cyan]AURA[/] - Terminal Agent for Cyber Threat Intelligence & Model Training")
        console.print("  Scrape threats | Analyze footprints | Train AI on ModelScope cloud")
        return

    cmds = {
        "scrape": cmd_scrape,
        "clean": cmd_clean,
        "analyze": cmd_analyze,
        "linux": cmd_linux,
        "train": cmd_train,
        "config": cmd_config,
        "models": cmd_list_models,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
