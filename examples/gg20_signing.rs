use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt, TryStreamExt};
use structopt::StructOpt;

use curv::arithmetic::Converter;
use curv::BigInt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};
use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

mod gg20_sm_client;
use gg20_sm_client::join_computation;
use flexi_logger::{FileSpec, Logger, WriteMode};

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-signing")]
    room: String,
    #[structopt(short, long)]
    local_share: PathBuf,

    #[structopt(short, long, use_delimiter(true))]
    parties: Vec<u16>,
    #[structopt(short, long)]
    data_to_sign: String,
    #[structopt(short, long)]
    index:u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    run(args).await
}

async fn run(args:Cli) -> Result<()>{
    let _logger = Logger::try_with_str("info, my::critical::module=trace")?
    .log_to_file(FileSpec::default()
        .directory("logs")
        .basename("sign")
        .discriminant("dgg20"))
    .print_message()
    .write_mode(WriteMode::Direct)
    .format(flexi_logger::with_thread)
    .start()?;
    log::info!("####### Start a new signing ######");
    log::info!("index = {}; parties = {:#?}, data_to_sign = {}", args.index, args.parties, args.data_to_sign);

    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
    log::info!("read localkey:\n{}", local_share);
    let number_of_parties = args.parties.len();
    log::info!("number_of_parties={}", number_of_parties);

    let (i, incoming, outgoing) =
        join_computation(args.address.clone(), &format!("{}-offline", args.room))
            .await
            .context("join offline computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(i, args.parties, local_share)?;
    //let signing = OfflineStage::new(args.index, args.parties, local_share)?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let (_i, incoming, outgoing) = join_computation(args.address, &format!("{}-online", args.room))
        .await
        .context("join online computation")?;

    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let (signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(args.data_to_sign.as_bytes()),
        completed_offline_stage,
    )?;

    outgoing
        .send(Msg {
            sender: i,
            receiver: None,
            body: partial_signature,
        })
        .await?;

    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;
    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;
    let signature = serde_json::to_string(&signature).context("serialize signature")?;
    println!("{}", signature);
    outgoing.close().await?;

    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    
    #[actix_rt::test]
    async fn sign_1(){
        let args: Cli = Cli{
            address : surf::Url::parse("http://localhost:8000/").unwrap(),
            room : String::from("default-signing"),
            local_share: String::from("local-share1.json").into(),
            parties: Vec::<u16>::from([1u16, 2u16]),
            data_to_sign:String::from("hello"),
            index: 1u16
        };
        run(args).await.unwrap()
    }
}