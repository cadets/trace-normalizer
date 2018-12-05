//
// Copyright (c) 2018 Thomas Bytheway
// All rights reserved.
//
// This software was developed by BAE Systems, the University of Cambridge
// Computer Laboratory, and Memorial University under DARPA/AFRL contract
// FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
// (TC) research program.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//

use std::{
    env,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    thread,
    sync::mpsc,
    process,
};

use rayon::prelude::*;
use serde_json::{self, Value};

trait ValueExt {
    fn has<I>(&self, index: I) -> bool
    where
        I: serde_json::value::Index;
    fn set<K, T>(&mut self, key: K, value: T) where
        K: ToString,
        T: Into<Value>;
}

impl ValueExt for Value {
    fn has<I>(&self, index: I) -> bool
        where
            I: serde_json::value::Index
    {
        self.get(index).is_some()
    }

    fn set<K, T>(&mut self, key: K, value: T)
    where
        K: ToString,
        T: Into<Value>,
    {
        self.as_object_mut().unwrap().insert(key.to_string(), value.into());
    }
}

fn main() {
    let args = env::args().collect::<Vec<_>>();

    if args.len() != 3 {
        eprintln!("Usage: ./trace-normalizer INPUT OUTPUT");
        process::exit(1);
    }

    let fin: Box<Read + Send> = if args[1] == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(&args[1]).unwrap())
    };

    let fout: Box<Write + Send> = if args[2] == "-" {
        Box::new(io::stdout())
    } else {
        Box::new(File::create(&args[2]).unwrap())
    };

    process(fin, fout)
}

fn process<R, W>(input: R, output: W)
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
{
    let fin = BufReader::new(input);
    let mut fout = BufWriter::new(output);

    let (in_w, proc_r) = mpsc::sync_channel(1);

    let thr_input = thread::spawn(
        move || {
            let mut v = Some(Vec::new());
            for line in fin.lines() {
                let mut line = line.unwrap();
                if line == "" || line == "[" || line == "]" {
                    continue;
                }
                if line.starts_with(", ") {
                    line.drain(0..2);
                }

                v.as_mut().unwrap().push(line);
                if v.as_ref().unwrap().len() >= 1024 {
                    in_w.send(v.take().unwrap()).unwrap();
                    v = Some(Vec::new());
                }
            }
            in_w.send(v.take().unwrap()).unwrap();
        }
    );

    let (proc_w, out_r) = mpsc::sync_channel::<Vec<String>>(1);

    let thr_proc = thread::spawn(
        move || {
            for v in proc_r {
                let out = v.into_par_iter()
                    .filter_map(|val| {
                        match serde_json::from_str::<Value>(&val) {
                            Ok(v) => Some(v),
                            Err(e) => {
                                eprintln!("{}", e);
                                None
                            }
                        }
                    })
                    .update(|val| tf_host_uuid(val))
                    .update(|val| tf_mmap_share(val))
                    .filter_map(|val| {
                        match serde_json::to_string(&val) {
                            Ok(v) => Some(v),
                            Err(e) => {
                                eprintln!("{}", e);
                                None
                            }
                        }
                    })
                    .collect();
                proc_w.send(out).unwrap();
            }
        }
    );

    let thr_out = thread::spawn(
        move || {
            for v in out_r {
                for l in v {
                    writeln!(&mut fout, "{}", l).unwrap();
                }
            }
        }
    );

    thr_input.join().unwrap();
    thr_proc.join().unwrap();
    thr_out.join().unwrap();
}

fn tf_host_uuid(rec: &mut Value) {
    if !rec.has("host") {
        rec.set("host", "44444444-4444-4444-4444-444444444444");
    }
}

fn tf_mmap_share(rec: &mut Value) {
    if rec["event"] == "audit:event:aue_mmap:"
        && !rec.has("arg_sharing_flags")
        && rec.has("arg_mem_flags")
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

        rec.set("arg_sharing_flags", flags);
    }
}
