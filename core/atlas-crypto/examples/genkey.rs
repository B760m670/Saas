fn main() {
    let pair = atlas_crypto::credentials::RealityKeypair::generate();
    println!("PrivateKey: {}", pair.secret_base64());
    println!("Password:   {}", pair.public_base64());
}
