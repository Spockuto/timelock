const bls = require("noble-bls12-381");
const { randomBytes, createHash } = require('crypto');
const utils = require("./utils");
const config = require('config');


const chainHash = config.get('chainHash');
const urls = config.get('urls');

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

async function round_validate(round){
  const current = await fetch_current();
  if (current.round <= round)
    return true
  return false
}


async function encrypt(message, round){

  var distributedPublicKey;
  var info = await fetch_info(round);
  distributedPublicKey = info.public_key;
  const hexMessage = utils.bytesToHex(utils.str2Bytes(message));

  const mSize = message.length;
  const sigma = utils.getRandom(mSize);
  
  // r = H3( sigma, M) -> zq* 
  var h3Hash = await bls.utils.sha256(Buffer.concat([sigma, utils.str2Bytes(message)]));  
  const r =  bls.utils.mod(utils.bytesToNumberBE(h3Hash), bls.CURVE.r);
  const rP = bls.getPublicKey(r);


  // message for the H(m)
  let buf = Buffer.allocUnsafe(8);
  buf.writeBigInt64BE(BigInt(round));
  var roundHash = await bls.utils.sha256(buf);

  // H(m) = xP
  var Hround = await utils.hashToCurve(roundHash);

  if (Hround.isOnCurve()){
    //rxP
    var rHround = Hround.multiply(r);
    //sP
    var Ppub = bls.PointG1.fromHex(distributedPublicKey);
    //e(rxP, sP)
    var pairing = bls.pairing(Ppub, rHround);
    
    const xof = utils.getXOF(pairing.toString(), mSize);
    var sig = utils.XORHex(utils.bytesToHex(sigma), xof);

    const xof2 = utils.getXOF(utils.bytesToHex(sigma), mSize);
    var enc = utils.XORHex(hexMessage, xof2);
  } 
  else {
    console.log("Point is not on curve");
    return;
  }

  var result;
  result =  round.toString() + "||" + utils.bytesToHex(rP) + "||" + sig + "||" + enc;
  return Buffer.from(result).toString('base64');

}
  
async function decrypt(enc){
  const split = Buffer.from(enc, 'base64').toString('ascii').split("||");

  const round = parseInt(split[0], 10);
  const current = await fetch_current();
  if (round > current.round){
    return "Current round is " + current.round +". Please wait till " + round;
  }

  if (split.length != 4) {
    return "Encrypted message is not formatted properly!"
  }
  const rP = split[1];
  const sigXOR = split[2];
  encXOR = split[3];

  var signature;
  var randomness = await fetch_randomness(round, false);
  signature = randomness.signaturev2;

  //rP
  var point1 = bls.PointG1.fromHex(rP);
  //xsP
  var point2 = bls.PointG2.fromSignature(signature);
  //e(rP, xsP)
  var pairing = bls.pairing(point1,point2);

  const xof = utils.getXOF(pairing.toString(), encXOR.length / 2);
  var sigma = utils.XORHex(sigXOR, xof);

  const xof2 = utils.getXOF(sigma, encXOR.length / 2);
  var message = utils.XORHex(encXOR, xof2);

  console.log("Message : " + utils.hexToStr(message));

  var h3Hash = await bls.utils.sha256(Buffer.concat([utils.hexToBytes(sigma), utils.str2Bytes(utils.hexToStr(message))]));  
  const r =  bls.utils.mod(utils.bytesToNumberBE(h3Hash), bls.CURVE.r);
  const rPdash = utils.bytesToHex(bls.getPublicKey(r));

  if(rP == rPdash){
    return utils.hexToStr(message);
  }
  
  return "Encrypted message is not formatted properly!";
}


module.exports = {round_validate, fetch_current, fetch_round, fetch_randomness, fetch_info, encrypt, decrypt}