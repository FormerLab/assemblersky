mod ffi;
mod normalize;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ffi::*;
use normalize::{NormalizedEvent, NormalizedRecord};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    input: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let buf = fs::read(&args.input)
        .with_context(|| format!("failed to read {}", args.input.display()))?;

    unsafe {
        let mut env = std::mem::zeroed::<AsbEnvelope>();
        if asb_decode_envelope(buf.as_ptr(), buf.len(), &mut env as *mut _) != 0
            || env.is_commit == 0
        {
            return Err(anyhow!("envelope decode failed or frame is not #commit"));
        }

        let mut op = std::mem::zeroed::<AsbPostOp>();
        if asb_find_create_post_op(env.ops_ptr, env.ops_len, &mut op as *mut _) != 0
            || op.is_create_post == 0
        {
            return Err(anyhow!("no create app.bsky.feed.post op found"));
        }

        let target_cid_ptr = if !op.record_cid_ptr.is_null() && op.record_cid_len > 0 {
            op.record_cid_ptr
        } else {
            op.cid_ptr
        };
        let target_cid_len = if !op.record_cid_ptr.is_null() && op.record_cid_len > 0 {
            op.record_cid_len
        } else {
            op.cid_len
        };

        let mut block_ptr: *const u8 = std::ptr::null();
        let mut block_len: usize = 0;
        if asb_car_find_block(
            env.blocks_ptr,
            env.blocks_len,
            target_cid_ptr,
            target_cid_len,
            &mut block_ptr,
            &mut block_len,
        ) != 0
        {
            return Err(anyhow!("CAR block lookup failed"));
        }

        let mut rec = std::mem::zeroed::<AsbPostRecord>();
        if asb_extract_post_record(block_ptr, block_len, &mut rec as *mut _) == 0
            || rec.ok == 0
        {
            return Err(anyhow!("post record extraction failed"));
        }

        let event = NormalizedEvent {
            kind: "commit".to_string(),
            op: "create".to_string(),
            collection: slice_to_string(op.collection_ptr, op.collection_len),
            seq: env.seq,
            repo: slice_to_string(env.repo_ptr, env.repo_len),
            rev: slice_to_string(env.rev_ptr, env.rev_len),
            rkey: slice_to_string(op.rkey_ptr, op.rkey_len),
            record: NormalizedRecord {
                r#type: slice_to_string(rec.type_ptr, rec.type_len),
                text: slice_to_string(rec.text_ptr, rec.text_len),
                created_at: slice_to_string(rec.created_at_ptr, rec.created_at_len),
            },
        };

        println!("{}", serde_json::to_string_pretty(&event)?);
    }

    Ok(())
}
