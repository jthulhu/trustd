use std::{env::args, error::Error};

use libtrust::get_secret;
use zbus::Connection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let wkn = args().nth(1).unwrap();
    let connection = Connection::session().await?;
    connection.request_name(wkn).await?;
    let secret = get_secret(connection.clone()).await?;
    println!("Secret = {}", hex::encode(*secret));
    Ok(())
}
