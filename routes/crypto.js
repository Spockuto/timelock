const bls = require("noble-bls12-381");
const { randomBytes, createHash } = require('crypto');
const utils = require("./utils");


const chainHash = "78c34edd50674313de43b112dd4e71ffcdfb547e91b66d41ba80470969888c70"
const urls = [
  'http://127.0.0.5:44511'
]

async function getClient(){
  const { default: Client, HTTP } = await import('drand-client')
  const disableBeaconVerification = true;
  const insecure = false;
  const options = { chainHash, disableBeaconVerification, insecure};
  const client = await Client.wrap(HTTP.forURLs(urls, chainHash), options);
  return client;
}

async function fetch_round(time){
  const client = await getClient();
  const round = client.roundAt(time);
  return round;

}

async function fetch_randomness(round) {
  const client = await getClient();
  const res = await client.get(round);
  return res
}
  
async function fetch_info(round){
  const client = await getClient();
  const res = await client.info(round);
  return res
}

async function fetch_current() {
  const client = await getClient();
  const res = await client.get();
  return res
}



async function encrypt(message, round){

  var distributedPublicKey;
  var info = await fetch_info(round);
  distributedPublicKey = info.public_key;
  const hexMessage = utils.bytesToHex(utils.str2Bytes(message));

  //rP
  const r = bls.utils.randomPrivateKey();
  const rP = bls.getPublicKey(r);

  // message for the H(m)
  let buf = Buffer.allocUnsafe(8);
  buf.writeBigInt64BE(BigInt(round));
  var roundHash = await bls.utils.sha256(buf);

  // H(m) = xP
  var Hround = await utils.hashToCurve(roundHash);

  if (Hround.isOnCurve()){
    //rxP
    var rHround = Hround.multiply(utils.bytesToNumberBE(r));
    //sP
    var Ppub = bls.PointG1.fromHex(distributedPublicKey);
    //e(rxP, sP)
    var pairing = bls.pairing(Ppub, rHround);
    
    const xof = utils.getXOF(pairing.toString(), message.length);
    var enc = utils.XORHex(hexMessage, xof);

    console.log("Round : " + round);
    console.log("Public Key : " + utils.bytesToHex(rP));
    console.log("Enc : " + enc);
    
  } 
  else {
    console.log("Point is not on curve");
    return;
  }

  var result;
  result =  round.toString() + "||" + utils.bytesToHex(rP) + "||" + enc;
  return Buffer.from(result).toString('base64');

}
  
async function decrypt(enc){
  const split = Buffer.from(enc, 'base64').toString('ascii').split("||");
  console.log(split);

  const round = parseInt(split[0], 10);
  const current = await fetch_current();
  if (round > current.round){
    return "Current round is " + current.round +". Please wait till " + round;
  }
  const rP = split[1];
  enc = split[2];

  var signature;
  var randomness = await fetch_randomness(round, false);
  signature = randomness.signaturev2;

  //rP
  var point1 = bls.PointG1.fromHex(rP);
  //xsP
  var point2 = bls.PointG2.fromSignature(signature);
  //e(rP, xsP)
  var pairing = bls.pairing(point1,point2);

  const xof = utils.getXOF(pairing.toString(), enc.length / 2);
  
  var message = utils.XORHex(enc, xof);
  console.log("Message : " + utils.hexToStr(message));

  return utils.hexToStr(message);
}

async function round_validate(round){
  const current = await fetch_current();
  if (current.round <= round)
    return true
  return false
}


module.exports = {round_validate, fetch_current, fetch_round, fetch_randomness, fetch_info, encrypt, decrypt}