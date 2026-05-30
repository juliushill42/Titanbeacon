#!/bin/bash
set -e

# 1. Enforcement Menu
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <directory_path> [llama_endpoint_url]"
    exit 1
fi

TARGET_DIR=$1
LLAMA_URL=${2:-"http://localhost:8080/v1/chat/completions"}
BINARY_PATH="./titan_beacon"

# 2. Check if native binary is already cached to ensure instant subsequent execution speeds
if [ ! -f "$BINARY_PATH" ]; then
    echo "[*] First run initialization: Compiling native Rust infrastructure..." >&2
    
    if ! command -v cargo &> /dev/null; then
        echo "Error: 'cargo' toolchain is required but not installed." >&2
        echo "Please install Rust first: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
        exit 1
    fi

    # Create safe hermetic build container
    BUILD_DIR=$(mktemp -d)
    mkdir -p "$BUILD_DIR/src"

    # Generate Cargo manifest inline
    cat << 'EOF' > "$BUILD_DIR/Cargo.toml"
[package]
name = "titan_beacon"
version = "1.0.0"
edition = "2021"

[dependencies]
regex = "1.10.4"
serde = { version = "1.0.203", features = ["derive"] }
serde_json = "1.0.117"
ureq = { version = "2.9.7", features = ["json"] }
EOF

    # Generate source file inline with zero placeholders
    cat << 'EOF' > "$BUILD_DIR/src/main.rs"
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use regex::Regex;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct Finding {
    line: usize,
    finding_type: String,
    severity: String,
    evidence: String,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct LlamaRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Deserialize)]
struct LlamaMessage {
    content: String,
}

#[derive(Deserialize)]
struct LlamaChoice {
    message: LlamaMessage,
}

#[derive(Deserialize)]
struct LlamaResponse {
    choices: Vec<LlamaChoice>,
}

fn query_local_llm(llama_url: &str, code_snippet: &str, context_type: &str) -> bool {
    let system_prompt = "You are a local application security scanner. Analyze the provided code line for true dependency risks or malicious payloads. If it looks dangerous or represents an anomalous, hallucinated package string, reply with the word 'VULNERABLE'. If it is a benign line of code or typical infrastructure configuration, reply with 'SAFE'. Do not provide explanations.";
    
    let payload = LlamaRequest {
        model: "local".to_string(),
        messages: vec![
            ChatMessage { role: "system".to_string(), content: system_prompt.to_string() },
            ChatMessage { role: "user".to_string(), content: format!("Context: {}\nCode: {}", context_type, code_snippet) }
        ],
        temperature: 0.1,
    };

    match ureq::post(llama_url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(5))
        .send_json(&payload) 
    {
        Ok(response) => {
            if let Ok(parsed) = response.into_json::<LlamaResponse>() {
                if let Some(choice) = parsed.choices.first() {
                    let text = choice.message.content.to_uppercase();
                    return text.contains("VULNERABLE");
                }
            }
            false
        }
        Err(_) => false,
    }
}

fn scan_file(file_path: &Path, secrets_regex: &Regex, import_regex: &Regex, llama_url: &str) -> Vec<Finding> {
    let mut file_findings = Vec::new();
    
    let file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(_) => return file_findings,
    };
    
    let reader = BufReader::new(file);
    
    for (line_num, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        
        let clean_line = line.trim();
        
        if clean_line.contains("TODO") {
            let has_critical_context = ["key", "secret", "password", "token"]
                .iter()
                .any(|k| clean_line.to_lowercase().contains(k));
            if !has_critical_context {
                continue;
            }
        }

        if secrets_regex.is_match(clean_line) {
            file_findings.push(Finding {
                line: line_num + 1,
                finding_type: "Hardcoded Secret/Token Leak".to_string(),
                severity: "CRITICAL".to_string(),
                evidence: clean_line.to_string(),
            });
            continue;
        }

        if import_regex.is_match(clean_line) {
            if query_local_llm(llama_url, clean_line, "Potential Malicious Import or AI Hallucination") {
                file_findings.push(Finding {
                    line: line_num + 1,
                    finding_type: "AI-Hallucinated / Suspicious Dependency".to_string(),
                    severity: "HIGH".to_string(),
                    evidence: clean_line.to_string(),
                });
            }
        }
    }
    
    file_findings
}

fn visit_dirs(
    dir: &Path, 
    secrets_regex: &Regex, 
    import_regex: &Regex, 
    llama_url: &str, 
    report: &mut serde_json::Map<String, serde_json::Value>
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(dir_name) = path.file_name() {
                let name_str = dir_name.to_string_lossy();
                if name_str == ".git" 
                    || name_str == "node_modules" 
                    || name_str == "target" 
                    || name_str == "venv" 
                    || name_str == "__pycache__" 
                {
                    continue;
                }
            }
            visit_dirs(&path, secrets_regex, import_regex, llama_url, report);
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy();
                if ["js", "ts", "py", "cpp", "h", "go"].iter().any(|&e| e == ext_str) {
                    let file_findings = scan_file(&path, secrets_regex, import_regex, llama_url);
                    if !file_findings.is_empty() {
                        let path_key = path.to_string_lossy().into_owned();
                        if let Ok(json_val) = serde_json::to_value(file_findings) {
                            report.insert(path_key, json_val);
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: titan_beacon <directory_path> [llama_endpoint_url]");
        std::process::exit(1);
    }

    let target_directory = &args[1];
    let default_url = "http://localhost:8080/v1/chat/completions".to_string();
    let llama_url = if args.len() > 2 { &args[2] } else { &default_url };

    let secrets_regex = Regex::new(r#"(?i)(?:key|secret|password|token|passwd|auth|api_key)\s*=\s*["\'][A-Za-z0-9%+\/=]{16,}["\']"#).unwrap();
    let import_regex = Regex::new(r#"(?x)
        ^import\s+[a-zA-Z0-9_]+ |
        ^from\s+[a-zA-Z0-9_]+\s+import |
        require\s*\(\s*["\'][a-zA-Z0-9_\-]+["\']\s*\) |
        import\s+.*from\s+["\'][a-zA-Z0-9_\-]+["\']
    "#).unwrap();

    let mut report = serde_json::Map::new();
    let path = Path::new(target_directory);

    if path.exists() {
        visit_dirs(path, &secrets_regex, &import_regex, llama_url, &mut report);
    } else {
        eprintln!("Error: Target path '{}' does not exist.", target_directory);
        std::process::exit(1);
    }

    let final_json = serde_json::Value::Object(report);
    println!("{}", serde_json::to_string_pretty(&final_json).unwrap());
}
EOF

    # Compile the native production build release silently
    (cd "$BUILD_DIR" && cargo build --release --quiet)
    
    # Store the output binary into execution workspace path and wipe build container traces
    cp "$BUILD_DIR/target/release/titan_beacon" "$BINARY_PATH"
    rm -rf "$BUILD_DIR"
    echo "[+] Done. System compiled successfully." >&2
fi

# 3. Direct Execution handoff passing shell parameters seamlessly
exec "$BINARY_PATH" "$TARGET_DIR" "$LLAMA_URL"

