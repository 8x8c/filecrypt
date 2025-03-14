# filecrypt 

filecrypt is a CLI (command-line interface) application written in Rust for encrypting and decrypting files using a password-based key derived with Argon2 and then performing authenticated encryption with AES-256-GCM. 


 Introduction

This repository provides a simple command-line tool (filecrypt) to encrypt and decrypt files using a password. It is designed to demonstrate near-production-grade file encryption using modern, secure primitives:

    Argon2 (Argon2id) for password-based key derivation.
    AES-256-GCM for authenticated encryption.
    Zeroization of memory buffers holding sensitive data.

By using Argon2, we have a memory-hard key derivation function resistant to brute-force attacks. By using AES-GCM, we get both confidentiality (encryption) and data integrity (authentication). 

