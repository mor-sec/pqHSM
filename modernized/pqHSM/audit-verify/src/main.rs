fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = pqhsm_audit_verify::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
