const {createECDH, createDecipheriv} = require("crypto");
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
    console.log("Creating secret to decrypt...");
    const secret = Uint8Array.from(ecdh.computeSecret(publicKey, "hex", "binary"));

    console.log("Decrypting file...");
    const decypher = createDecipheriv(ALGO_ENCRYPT, secret.slice(0,32), secret.slice(0, 16));
    const input_File = "./data/" + args.private + "-" +args.data + ".enc";
    console.log(input_File);
    const text_to_decrypt = fs.readFileSync(input_File).toString();
    let decrypted = decypher.update(text_to_decrypt, 'binary', 'utf-8');
    decrypted += decypher.final('utf-8');

    console.log("Encrypted text: " + text_to_decrypt);
    console.log("Decrypted text: " + decrypted);
}
