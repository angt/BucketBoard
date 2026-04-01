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

## Usage

### Send Your Stuff

    $ echo hello | bkt -

### Get Your Stuff Back

    $ bkt
    hello
