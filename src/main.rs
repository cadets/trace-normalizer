use std::{
    env,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    process,
};

use serde_json::{self, Value};

fn main() {
    let args = env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        eprintln!("Usage: ./trace-normalizer INPUT OUTPUT");
        process::exit(1);
    }

    let fin: BufReader<Box<Read>> = BufReader::new(if args[1] == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(&args[1]).unwrap())
    });

    let mut fout: BufWriter<Box<Write>> = BufWriter::new(if args[2] == "-" {
        Box::new(io::stdout())
    } else {
        Box::new(File::create(&args[2]).unwrap())
    });

    for line in fin.lines() {
        let mut line = line.unwrap();
        if line == "" || line == "[" || line == "]" {
            continue;
        }
        if line.starts_with(", ") {
            line.drain(0..2);
        }

        let mut rec = match serde_json::from_str::<Value>(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e);
                continue;
            }
        };

        {
            tf_host_uuid(&mut rec);
            tf_mmap_share(&mut rec);
        }

        serde_json::to_writer(&mut fout, &rec).unwrap();
        writeln!(&mut fout).unwrap();
    }
}

fn tf_host_uuid(rec: &mut Value) {
    if rec.get("host").is_none() {
        rec.as_object_mut()
            .unwrap()
            .insert("host".into(), "44444444:4444:4444:4444:444444444444".into());
    }
}

fn tf_mmap_share(rec: &mut Value) {
    if rec["event"] == "audit:event:aue_mmap:"
        && rec.get("arg_sharing_flags").is_none()
        && rec.get("arg_mem_flags").is_some()
    {
        let mut flags = Vec::new();

        if rec["arg_mem_flags"]
            .as_array()
            .unwrap()
            .contains(&"PROT_WRITE".into())
        {
            let fdpath = rec["fdpath"].as_str().unwrap();
            if fdpath.starts_with("/lib/")
                || fdpath.starts_with("/usr/local/lib/")
                || fdpath.starts_with("/usr/lib/")
            {
                flags.push("MAP_SHARED");
            } else {
                flags.push("MAP_PRIVATE");
            }
        } else {
            flags.push("MAP_PRIVATE");
        }

        rec.as_object_mut()
            .unwrap()
            .insert("arg_sharing_flags".into(), flags.into());
    }
}
