use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

// AES-GCM
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};

// Argon2 + parameters
use argon2::{Argon2, Params, Version};

// For reading passwords without echo
use rpassword::read_password;

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[clap(
    name = "filecrypt",
    author,
    version,
    about = "A CLI tool for file encryption and decryption"
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// The file to encrypt
        input: PathBuf,
        /// The encrypted output
        output: PathBuf,
    },
    /// Decrypt a file
    Decrypt {
        /// The file to decrypt
        input: PathBuf,
        /// The decrypted output
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => encrypt_file(&input, &output),
        Commands::Decrypt { input, output } => decrypt_file(&input, &output),
    }
}

/// Encrypts `input_file` using AES-256-GCM with a key derived via Argon2, and writes to `output_file`.
fn encrypt_file(input_file: &PathBuf, output_file: &PathBuf) -> Result<()> {
    // 1. Read plaintext
    let mut input_data = Vec::new();
    {
        let mut file = File::open(input_file)
            .map_err(|e| anyhow!("Failed to open input file {:?}: {e}", input_file))?;
        file.read_to_end(&mut input_data)
            .map_err(|e| anyhow!("Failed to read input file: {e}"))?;
    }

    // 2. Prompt for password
    eprintln!("Enter password to encrypt:");
    let password = read_password().map_err(|e| anyhow!("Failed to read password: {e}"))?;

    // 3. Generate a random salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // 4. Setup Argon2 and derive a 32-byte key directly
    let argon2_params = Params::new(15_000, 2, 1, Some(32))
        .map_err(|e| anyhow!("Failed to create Argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| anyhow!("Failed to derive key with Argon2: {e}"))?;

    // 5. Encrypt with AES-GCM
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, input_data.as_slice())
        .map_err(|e| anyhow!("AES-GCM encryption failed: {e}"))?;

    // 6. Write output file in format:
    // [magic 4 bytes] [salt_len 2 bytes] [salt] [nonce_len 2 bytes] [nonce] [ciphertext...]
    let mut out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_file)
        .map_err(|e| anyhow!("Failed to create output file {:?}: {e}", output_file))?;

    // Magic
    out_file.write_all(b"file")?;

    // Salt
    let salt_len = salt.len() as u16;
    out_file.write_all(&salt_len.to_be_bytes())?;
    out_file.write_all(&salt)?;

    // Nonce
    let nonce_len = nonce_bytes.len() as u16;
    out_file.write_all(&nonce_len.to_be_bytes())?;
    out_file.write_all(&nonce_bytes)?;

    // Ciphertext
    out_file.write_all(&ciphertext)?;
    out_file.sync_all()?;

    eprintln!("Encryption complete. Output saved to {:?}", output_file);

    // 7. Zeroize sensitive data
    zeroize_sensitive(&mut input_data, &mut key_bytes[..]);

    // Convert password string to bytes for zeroizing
    let mut password_bytes = password.into_bytes();
    password_bytes.zeroize();

    Ok(())
}

/// Decrypts `input_file` using AES-256-GCM with a key derived via Argon2, and writes to `output_file`.
fn decrypt_file(input_file: &PathBuf, output_file: &PathBuf) -> Result<()> {
    // 1. Read encrypted file
    let mut encrypted_data = Vec::new();
    {
        let mut file = File::open(input_file)
            .map_err(|e| anyhow!("Failed to open file {:?}: {e}", input_file))?;
        file.read_to_end(&mut encrypted_data)
            .map_err(|e| anyhow!("Failed to read file: {e}"))?;
    }

    // 2. Verify magic
    const MAGIC: &[u8] = b"file";
    if encrypted_data.len() < MAGIC.len() {
        return Err(anyhow!("File too short or corrupted (missing magic)"));
    }
    if &encrypted_data[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("Invalid file format (magic mismatch)"));
    }
    let mut offset = MAGIC.len();

    // 3. Parse salt
    if encrypted_data.len() < offset + 2 {
        return Err(anyhow!("File format error (no salt length)"));
    }
    let salt_len =
        u16::from_be_bytes([encrypted_data[offset], encrypted_data[offset + 1]]) as usize;
    offset += 2;
    if encrypted_data.len() < offset + salt_len {
        return Err(anyhow!("File format error (salt missing)"));
    }
    let salt_bytes = &encrypted_data[offset..offset + salt_len];
    offset += salt_len;

    // 4. Parse nonce
    if encrypted_data.len() < offset + 2 {
        return Err(anyhow!("File format error (no nonce length)"));
    }
    let nonce_len =
        u16::from_be_bytes([encrypted_data[offset], encrypted_data[offset + 1]]) as usize;
    offset += 2;
    if encrypted_data.len() < offset + nonce_len {
        return Err(anyhow!("File format error (nonce missing)"));
    }
    let nonce_bytes = &encrypted_data[offset..offset + nonce_len];
    offset += nonce_len;

    // 5. Ciphertext
    if encrypted_data.len() < offset {
        return Err(anyhow!("File format error (ciphertext missing)"));
    }
    let ciphertext = &encrypted_data[offset..];

    // 6. Prompt for password
    eprintln!("Enter password to decrypt:");
    let password = read_password().map_err(|e| anyhow!("Failed to read password: {e}"))?;

    // 7. Re-derive key using Argon2
    let argon2_params = Params::new(15_000, 2, 1, Some(32))
        .map_err(|e| anyhow!("Failed to create Argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key_bytes)
        .map_err(|e| anyhow!("Failed to derive key with Argon2: {e}"))?;

    // 8. Decrypt
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bytes));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES-GCM decryption failed: {e}"))?;

    // 9. Write plaintext
    let mut out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_file)
        .map_err(|e| anyhow!("Failed to create output file {:?}: {e}", output_file))?;

    out_file.write_all(&plaintext)?;
    out_file.sync_all()?;
    eprintln!("Decryption complete. Output saved to {:?}", output_file);

    // 10. Zeroize sensitive data
    zeroize_sensitive(&mut encrypted_data, &mut key_bytes[..]);

    // Convert password string to bytes for zeroizing
    let mut password_bytes = password.into_bytes();
    password_bytes.zeroize();

    Ok(())
}

/// Zeroize any sensitive buffers (plaintext, key, etc.).
fn zeroize_sensitive(buf1: &mut [u8], buf2: &mut [u8]) {
    buf1.zeroize();
    buf2.zeroize();
}



