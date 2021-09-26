const bls = require("noble-bls12-381");
const _crypto = require('crypto');
const buffer = require('buffer');
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
  var h3Hash = await bls.utils.sha256(Buffer.concat([sigma, utils.str2Bytes(message)]));  
  const r =  bls.utils.mod(utils.bytesToNumberBE(h3Hash), bls.CURVE.r);
  const rP = bls.getPublicKey(r);
  let buf = Buffer.allocUnsafe(8);
  buf.writeBigInt64BE(BigInt(round));
  var roundHash = await bls.utils.sha256(buf);
  var Hround = await utils.hashToCurve(roundHash);

  if (Hround.isOnCurve()){

    var rHround = Hround.multiply(r);
    var Ppub = bls.PointG1.fromHex(distributedPublicKey);
    var pairing = bls.pairing(Ppub, rHround);
    const xof = utils.getXOF(pairing.toString(), mSize);
    var sig = utils.XORHex(utils.bytesToHex(sigma), xof);
    const xof2 = utils.getXOF(utils.bytesToHex(sigma), 32);
    var auth = round.toString() + "||" + utils.bytesToHex(rP) + "||" + sig;
    var enc = aesEncrypt(message, xof2, auth);
  } 
  else {
    console.log("Point is not on curve");
    return;
  }
  var result;
  result =  auth + "||" + enc;
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
  encAES = split[3];

  var signature;
  var randomness = await fetch_randomness(round, false);
  signature = randomness.signaturev2;
  var point1 = bls.PointG1.fromHex(rP);
  var point2 = bls.PointG2.fromSignature(signature);
  var pairing = bls.pairing(point1,point2);
  const xof = utils.getXOF(pairing.toString(), sigXOR.length / 2);
  var sigma = utils.XORHex(sigXOR, xof);
  const xof2 = utils.getXOF(sigma, 32);
  var message = aesDecrypt(encAES, xof2, split[0] + "||" + split[1] + "||" + split[2])
  var h3Hash = await bls.utils.sha256(Buffer.concat([utils.hexToBytes(sigma), utils.str2Bytes(message)]));  
  const r =  bls.utils.mod(utils.bytesToNumberBE(h3Hash), bls.CURVE.r);
  const rPdash = utils.bytesToHex(bls.getPublicKey(r));

  if(rP == rPdash){
    return message;
  }
  
  return "Encrypted message is not formatted properly!";
}

function aesEncrypt(message, key, auth){
  const iv = utils.getRandom(12);
  const keyBuffer = utils.hexToBytes(key);
  const authBuffer = utils.str2Bytes(auth);

  const cipher = _crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  cipher.setAAD(authBuffer);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return  utils.bytesToHex(iv) + "~~" + utils.bytesToHex(cipher.getAuthTag()) + "~~" + encrypted;
}

function aesDecrypt(encrypt, key, auth){
  const split = encrypt.split("~~");
  const iv = utils.hexToBytes(split[0]);
  const tag = utils.hexToBytes(split[1]);
  const keyBuffer = utils.hexToBytes(key);
  const authBuffer = utils.str2Bytes(auth);
  const enc = split[2];

  const cipher = _crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
  cipher.setAAD(authBuffer);
  cipher.setAuthTag(tag);

  let decrypted = cipher.update(enc, 'hex', 'utf-8');
  decrypted += cipher.final('utf-8');
  return  decrypted;
}


module.exports = {round_validate, fetch_current, fetch_round, fetch_randomness, fetch_info, encrypt, decrypt}