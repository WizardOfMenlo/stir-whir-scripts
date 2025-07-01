# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust library implementing scripts for STIR 🥣 and WHIR 🌪️ cryptographic protocols, developed using the arkworks ecosystem. It's an academic prototype for proof-of-concept estimation and analysis of these protocols.

**Important**: This is a WIP academic prototype that has NOT received careful code review and is NOT ready for production use.

## Development Commands

### Build and Test
- `cargo build` - Build the project
- `cargo build --verbose` - Build with verbose output
- `cargo test` - Run all tests
- `cargo test --verbose` - Run tests with verbose output
- `cargo run` - Run the main binary (demonstrates protocol configurations)

### Code Quality
- `cargo fmt` - Format code
- `cargo fmt --all -- --check` - Check formatting without modifying files
- `cargo clippy` - Run linter
- `cargo clippy -- -D warnings` - Run linter with warnings as errors

### Documentation
- `cargo doc` - Generate documentation
- `cargo doc --open` - Generate and open documentation

## Architecture

### Core Components

1. **Protocol Implementations** (`src/`)
   - `stir.rs` - STIR protocol implementation with configurable parameters
   - `whir.rs` - WHIR protocol implementation with configurable parameters  
   - `fri.rs` - FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol
   - `basefold.rs` - Basefold polynomial commitment scheme

2. **Protocol Framework** (`src/protocol/`)
   - `mod.rs` - Core `Protocol` struct with rounds, proof sizes, and soundness analysis
   - `builder.rs` - Protocol builder for constructing protocol configurations
   - `proof_size.rs` - Proof size estimation utilities (Merkle trees, field elements, queries)

3. **Supporting Modules**
   - `field.rs` - Field definitions (Goldilocks, BabyBear) with extension degrees
   - `errors.rs` - Security assumptions and error handling
   - `utils.rs` - Utility functions for calculations and formatting

4. **Executable** (`src/bin/main.rs`)
   - Demonstrates protocol configurations with concrete parameters
   - Shows proof size estimations for different protocol variants

### Key Types

- `LowDegreeParameters` - Core parameters for low-degree testing (field, degree, batch size)
- `StirParameters`/`WhirParameters` - Protocol-specific configuration (rates, folding factors, security)
- `Protocol` - Main struct containing protocol name, digest size, and round information
- `Field` - Field representation with size and extension degree

### Protocol Configuration Patterns

All protocols follow a similar instantiation pattern:
1. Create `LowDegreeParameters` for the test parameters
2. Create protocol-specific parameters (e.g., `StirParameters`)
3. Instantiate the protocol with both parameter sets
4. The protocol provides proof size estimates and security analysis

The main binary demonstrates typical configurations using the Goldilocks field with various security assumptions and folding strategies.