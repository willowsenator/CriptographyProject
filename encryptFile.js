const {createECDH, createCipheriv} = require("crypto");
const { exit } = require("process");
const args = require("yargs").argv;
const {CURVE_NAME, ALGO_ENCRYPT} = require("./common_constants");
const fs = require("fs");

if(!args.private && !args.public && !args.data){
    console.error("Use: node encryptFile.js --private <custom_private_key> --public <custom_public_key> --data <file_to_encrypt>");
    exit(0);
} else {
    const ecdh = createECDH(CURVE_NAME);
    console.log("Reading public and private keys...");
    const privateKey = fs.readFileSync("./data/" + args.private + ".key").toString();
    const publicKey = fs.readFileSync("./data/" + args.public + ".pb").toString();
    ecdh.setPrivateKey(privateKey, "hex");

    // create secret to encrypt
    console.log("Creating secret to encrypt...");
    const secret = Uint8Array.from(ecdh.computeSecret(publicKey, "hex", "binary"));

    console.log("Encrypting file...");
    const cypher = createCipheriv(ALGO_ENCRYPT, secret.slice(0,32), secret.slice(0, 16));
    const text_to_encrypt = fs.readFileSync("./data/" + args.data + ".txt");
    let encrypted = cypher.update(text_to_encrypt, 'utf-8', 'binary');
    encrypted += cypher.final('binary');
    fs.writeFileSync("./data/" + args.public + "-" + args.data + ".enc", encrypted);

}
