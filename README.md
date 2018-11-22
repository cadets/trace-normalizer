# trace-normalizer
A program for transforming CADETS JSON format traces, both normalizes formatting and attempts to add features missing from older traces in a heuristic fashion.

## Installation
```
git clone git@github.com:cadets/trace-normalizer.git
cd trace-normalizer
cargo build --release
```

## Use
```
./trace-normalizer INPUT OUTPUT
```
Transforms the file INPUT (can be - for stdin) and writes to the file OUTPUT (can be - for stdout)
