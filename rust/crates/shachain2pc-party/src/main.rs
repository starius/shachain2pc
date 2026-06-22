use shachain2pc_party::{parse_args, run_party, PartyOutput};
use std::env;

// The derivation is a single sequential request/response task (Alice<->Bob round
// trips). A multi_thread runtime would spawn one worker per core that idle-park
// and bounce the task across run queues at every .await -- pure scheduler/mmap
// lock-contention overhead with no parallelism to gain. current_thread runs it on
// one thread, matching the C++ blocking-socket model.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    match parse_args(env::args().collect()) {
        Ok(args) => match run_party(args).await {
            Ok(PartyOutput::Single(out)) => {
                println!("RESULT {}", out.to_hex());
            }
            Ok(PartyOutput::Range(outputs)) => {
                for (index, out) in outputs {
                    println!("RESULT {} {}", index.to_hex12(), out.to_hex());
                }
            }
            Err(e) => {
                eprintln!("ABORT: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("ABORT: {e}");
            std::process::exit(1);
        }
    }
}
