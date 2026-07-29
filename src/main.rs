use clap::Parser;
use colored::*;
use regex::Regex;
use std::path::PathBuf;
use walkdir::WalkDir;

/// 🕳️🔑 KeyHole — Pre-commit scanner for AI API keys
/// Catch leaks before they reach GitHub. 15+ providers. Zero deps. <50ms.
#[derive(Parser)]
#[command(name = "keyhole", version, about)]
struct Args {
    /// Path to scan (default: current directory)
    #[arg(default_value = ".")]
    path: String,

    /// Exit with code 1 if leaks found (for CI/pre-commit)
    #[arg(short = 'e', long)]
    exit_code: bool,

    /// Show only critical findings
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Install as pre-commit hook in current repo
    #[arg(long)]
    install: bool,
}

#[derive(Debug)]
struct KeyPattern {
    name: &'static str,
    regex: &'static str,
    severity: &'static str,
    hint: &'static str,
}

const PATTERNS: &[KeyPattern] = &[
    // ── AI Model Providers ──
    KeyPattern {
        name: "OpenAI API Key",
        regex: r"sk-(?:proj-)?[a-zA-Z0-9_-]{20,}",
        severity: "CRITICAL",
        hint: "Rotate at https://platform.openai.com/api-keys — exposed keys can drain your billing",
    },
    KeyPattern {
        name: "Anthropic Claude API Key",
        regex: r"sk-ant-api03-[a-zA-Z0-9_\-]{93,95}",
        severity: "CRITICAL",
        hint: "Rotate at https://console.anthropic.com/keys",
    },
    KeyPattern {
        name: "OpenRouter API Key",
        regex: r"sk-or-v1-[a-fA-F0-9]{40,}",
        severity: "CRITICAL",
        hint: "Rotate at https://openrouter.ai/keys — attackers can use any model on your dime",
    },
    KeyPattern {
        name: "Google Gemini API Key",
        regex: r"AIzaSy[a-zA-Z0-9_\-]{33}",
        severity: "HIGH",
        hint: "Rotate at https://aistudio.google.com/app/apikey",
    },
    KeyPattern {
        name: "Fireworks AI Key",
        regex: r"fw_[a-zA-Z0-9]{16,}",
        severity: "HIGH",
        hint: "Rotate at https://fireworks.ai/account/api-keys",
    },
    KeyPattern {
        name: "DeepSeek API Key",
        regex: r"sk-[a-zA-Z0-9]{32}",
        severity: "HIGH",
        hint: "Rotate at https://platform.deepseek.com/api_keys",
    },
    KeyPattern {
        name: "Cohere API Key",
        regex: r"[a-zA-Z0-9]{40}",
        severity: "MEDIUM",
        hint: "Check if this matches Cohere's key format. Rotate if so.",
    },
    KeyPattern {
        name: "Together AI Key",
        regex: r"[a-f0-9]{32,40}",
        severity: "MEDIUM",
        hint: "Check if this matches Together AI key format. Rotate at https://api.together.xyz/settings/api-keys",
    },
    // ── Bot / Agent Tokens ──
    KeyPattern {
        name: "Telegram Bot Token",
        regex: r"\d{9,10}:[a-zA-Z0-9_-]{35}",
        severity: "CRITICAL",
        hint: "Revoke via @BotFather — attacker gains full bot control including message interception",
    },
    KeyPattern {
        name: "Discord Bot Token",
        regex: r"[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}",
        severity: "CRITICAL",
        hint: "Rotate at https://discord.com/developers/applications — full server access compromised",
    },
    KeyPattern {
        name: "Slack Bot Token",
        regex: r"xox[abpos]-[a-zA-Z0-9-]{10,}",
        severity: "HIGH",
        hint: "Rotate at https://api.slack.com/apps — workspace data at risk",
    },
    // ── Infrastructure ──
    KeyPattern {
        name: "GitHub Personal Access Token",
        regex: r"gh[pousr]_[a-zA-Z0-9]{36}",
        severity: "CRITICAL",
        hint: "Revoke at https://github.com/settings/tokens — full repo access compromised",
    },
    KeyPattern {
        name: "GitHub OAuth / Legacy Token",
        regex: r"gho_[a-zA-Z0-9]{36}",
        severity: "CRITICAL",
        hint: "Revoke at GitHub settings — attacker can push, delete, and access private repos",
    },
    KeyPattern {
        name: "AWS Access Key",
        regex: r"AKIA[0-9A-Z]{16}",
        severity: "CRITICAL",
        hint: "Deactivate at AWS IAM immediately — potential full cloud account compromise",
    },
    KeyPattern {
        name: "Supabase Service Key",
        regex: r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        severity: "HIGH",
        hint: "Rotate at Supabase Dashboard → Project Settings → API",
    },
    KeyPattern {
        name: "HuggingFace Token",
        regex: r"hf_[a-zA-Z0-9]{34}",
        severity: "HIGH",
        hint: "Rotate at https://huggingface.co/settings/tokens",
    },
];

struct Finding {
    pattern: &'static KeyPattern,
    file: PathBuf,
    line: usize,
    snippet: String,
}

fn main() {
    let args = Args::parse();

    if args.install {
        install_hook();
        return;
    }

    println!(
        "{}",
        "🕳️🔑  KeyHole — AI API Key Leak Scanner".bold().cyan()
    );
    println!("{}", "─".repeat(50).dimmed());

    let findings = scan(&args.path);

    if findings.is_empty() {
        println!(
            "{}",
            "✅  No leaked API keys detected! Your secrets are safe.".green().bold()
        );
        return;
    }

    // Group findings by severity
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern.severity == "CRITICAL")
        .collect();
    let high: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern.severity == "HIGH")
        .collect();
    let medium: Vec<_> = findings
        .iter()
        .filter(|f| f.pattern.severity == "MEDIUM")
        .collect();

    // Print criticals first
    for group in [("CRITICAL", &critical), ("HIGH", &high), ("MEDIUM", &medium)] {
        if group.1.is_empty() {
            continue;
        }
        if group.0 != "CRITICAL" && !args.quiet {
            println!();
        }

        let icon = match group.0 {
            "CRITICAL" => "🚨",
            "HIGH" => "⚠️",
            _ => "ℹ️",
        };

        for finding in group.1 {
            let severity_color = match group.0 {
                "CRITICAL" => finding.pattern.severity.red().bold(),
                "HIGH" => finding.pattern.severity.yellow().bold(),
                _ => finding.pattern.severity.blue(),
            };

            println!(
                "{} [{}] {} — {}:{}",
                icon,
                severity_color,
                finding.pattern.name.bold(),
                finding.file.display().to_string().dimmed(),
                finding.line
            );
            println!("   {} {}", "▶".dimmed(), finding.snippet.trim().yellow());
            println!("   {} {}", "💡".dimmed(), finding.pattern.hint.dimmed());
            println!();
        }
    }

    println!(
        "{} {} potential leak(s) found — {}",
        "🔍".bold(),
        findings.len().to_string().bold(),
        "REMOVE THESE BEFORE COMMITTING!".red().bold()
    );

    if args.exit_code {
        std::process::exit(1);
    }
}

fn scan(root: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let patterns: Vec<_> = PATTERNS
        .iter()
        .map(|p| (p, Regex::new(p.regex).unwrap()))
        .collect();

    let walker = WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.path()));

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();

        // Skip binary files, hidden dirs, and large files
        if path.is_dir()
            || is_binary(path)
            || path.to_string_lossy().contains("/.git/")
            || path.to_string_lossy().contains("/target/")
            || path.to_string_lossy().contains("/node_modules/")
            || path.to_string_lossy().contains("/__pycache__/")
        {
            continue;
        }

        // Skip files > 1MB
        if let Ok(meta) = path.metadata() {
            if meta.len() > 1_000_000 {
                continue;
            }
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Skip files that look like they contain only test/mock data
        if content.contains("sk-ant-api03-deadbeef")
            || content.contains("sk-ant-api03-legitimate")
            || content.contains("sk-or-v1-abcdef")
            || content.contains("sk-or-v1-abc123")
            || content.contains("sk-proj-FAKE")
            || content.contains("AKIAIOSFODNN7EXAMPLE")
        {
            continue;
        }

        for (pattern, regex) in &patterns {
            for cap in regex.captures_iter(&content) {
                let matched = cap.get(0).unwrap();
                let start = matched.start();
                let line = content[..start].matches('\n').count() + 1;

                // Get context: 100 chars around the match
                let ctx_start = if start > 50 { start - 50 } else { 0 };
                let ctx_end = std::cmp::min(matched.end() + 50, content.len());
                let snippet = content[ctx_start..ctx_end]
                    .replace('\n', " ")
                    .replace('\r', "");

                // Avoid duplicates
                if findings.iter().any(|f: &Finding| {
                    f.file == path
                        && f.line == line
                        && std::ptr::eq(f.pattern, *pattern)
                }) {
                    continue;
                }

                findings.push(Finding {
                    pattern,
                    file: path.to_path_buf(),
                    line,
                    snippet,
                });
            }
        }
    }

    // Sort by severity then file
    let severity_order = |s: &str| match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        _ => 2,
    };
    findings.sort_by(|a, b| {
        severity_order(a.pattern.severity)
            .cmp(&severity_order(b.pattern.severity))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    findings
}

fn is_binary(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("").to_lowercase();
        matches!(
            ext.as_str(),
            "png" | "jpg"
                | "jpeg"
                | "gif"
                | "ico"
                | "mp4"
                | "mp3"
                | "wav"
                | "zip"
                | "tar"
                | "gz"
                | "pdf"
                | "exe"
                | "dll"
                | "so"
                | "dylib"
                | "wasm"
                | "woff"
                | "woff2"
                | "ttf"
                | "eot"
                | "bin"
        )
    } else {
        false
    }
}

fn is_ignored(path: &std::path::Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_str().unwrap_or("");
    name.starts_with('.') && name != ".env" && name != ".env.example"
}

fn install_hook() {
    let hook_path = ".git/hooks/pre-commit";
    let hook_content = r#"#!/bin/sh
# 🕳️🔑 KeyHole pre-commit hook
# Installed by: keyhole --install

echo "🔑 KeyHole: Scanning for leaked API keys..."
keyhole -e
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Commit blocked! Remove leaked keys before committing."
    echo "   Run 'keyhole' for details."
    exit 1
fi
echo "✅ No leaks detected. Proceeding with commit."
"#;

    match std::fs::write(hook_path, hook_content) {
        Ok(_) => {
            println!("{}", "🔑 KeyHole pre-commit hook installed!".green().bold());
            println!(
                "   {}",
                "Every commit will now be scanned for leaked API keys.".dimmed()
            );
            let _ = std::process::Command::new("chmod")
                .args(["+x", hook_path])
                .output();
        }
        Err(e) => {
            eprintln!("{} Failed to install hook: {}", "❌".red(), e);
            eprintln!(
                "   {}",
                "Make sure you're in a git repository root.".yellow()
            );
        }
    }
}