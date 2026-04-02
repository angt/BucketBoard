# BucketBoard

XET powered copypasta network

## The Setup

### Prerequisites

- [Zig](https://ziglang.org/) 0.16 or newer
- A [HuggingFace](https://huggingface.co/) account with a token

### Install

    $ zig build install --prefix ~/.local

Make sure `~/.local/bin` is in your `PATH`:

    $ export PATH="$HOME/.local/bin:$PATH"

### Configure

    $ export BKT_TOKEN=hf_xxxxxxxxxx
    $ export BKT=username/bucket

To enable end-to-end encryption, also set `BKT_SECRET` to a 16-byte key encoded as 32 hex characters:

    $ export BKT_SECRET=00112233445566778899aabbccddeeff

Generate one with OpenSSL if needed:

    $ openssl rand -hex 16

When `BKT_SECRET` is set, uploads are encrypted with AEGIS-128X2 using a random nonce prepended to the ciphertext, and downloads are decrypted automatically.

## Usage

### Send Your Stuff

    $ echo hello | bkt -

### Get Your Stuff Back

    $ bkt
    hello
