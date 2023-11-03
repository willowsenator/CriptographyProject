const {createECDH} =  require("crypto");
const args = require("yargs").argv;
const fs = require("fs");
const {exit} = require("process");
const {CURVE_NAME} = require("./common_constants");

if (args.name){
    console.log("Creating ECDH object...");
    const ecdh = createECDH(CURVE_NAME);

    console.log("Creating public and private keys...");
    const publicKey = ecdh.generateKeys("hex");
    const privateKey = ecdh.getPrivateKey("hex");
    
    console.log("Writing to file the public and private keys...");
    fs.writeFileSync("./data/" + args.name + ".pb", publicKey);
    fs.writeFileSync("./data/" + args.name + ".key", privateKey);

} else {
    console.error("Use: node generateKeys.js --name <custom_name>");
    exit(0);
}