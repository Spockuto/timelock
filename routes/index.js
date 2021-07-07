const express = require('express');
const https = require('https');
const { hrtime } = require('process');
var router = express.Router();
const bls = require("noble-bls12-381");
const { randomBytes, createHash } = await require('crypto');
const utils = require("./utils");


const chainHash = '8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce'
const urls = [
    'https://api.drand.sh',
    'https://api2.drand.sh/',
    'https://api3.drand.sh/',
    'https://drand.cloudflare.com'
]


const distributedPublicKey = '89d49d0cc8bbf6c50af1bdb6bb5176b93b5ac4ed9b66b93f4df42b886a422a54f814bd23fbb07cbde33214abaaa9a65d';
const round = 107;
const randomsig = '97f38c9824431f66742d5381ca31f927a6daafb536ca8fa0892ba829eaa3b71339fe4521c5ee1c453e7bf3f3959c356a08005bfe93d6cd6f95e304193de9b1717cebf69d8aa6ab170d6e9f93760e605c657837092cd3774216921d0fef042d96';




// Encryption 
// sigma -> random generation for message size
// r = H3( sigma, M) -> zq* 
// 1) rP
// 2) sigma xor H2(pairing)
// 3) M xor H4(sigma)

async function fetch_randomness() {
  const { default: Client, HTTP } = await import('drand-client')
  const options = { chainHash }
  const client = await Client.wrap(HTTP.forURLs(urls, chainHash), options)
  const res = await client.get()
  return res
}

async function encrypt(message, round, distributedPublicKey){

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
    console.log("Enc : " + enc);
    console.log("Public Key : " + utils.bytesToHex(rP));
  } 
  else {
    console.log("Point is not on curve");
  }
  
}

// Enc : 97333d60db66cd6be15e02
// Public Key : 99edf08c9abd1c97467fc18c875c1bec5272226fe548f325bf44611e5019126478b38b77d3bcf446b890fda7295d704b


async function decrypt(signature, enc, rP){
  //rP
  var point1 = bls.PointG1.fromHex(rP);
  //xsP
  var point2 = bls.PointG2.fromSignature(signature);
  //e(rP, xsP)
  var pairing = bls.pairing(point1,point2);

  const xof = utils.getXOF(pairing.toString(), enc.length / 2);
  
  var message = utils.XORHex(enc, xof);
  console.log("Message : " + utils.hexToStr(message));
}

encrypt("Golden rule", 107 , "89d49d0cc8bbf6c50af1bdb6bb5176b93b5ac4ed9b66b93f4df42b886a422a54f814bd23fbb07cbde33214abaaa9a65d");
decrypt("97f38c9824431f66742d5381ca31f927a6daafb536ca8fa0892ba829eaa3b71339fe4521c5ee1c453e7bf3f3959c356a08005bfe93d6cd6f95e304193de9b1717cebf69d8aa6ab170d6e9f93760e605c657837092cd3774216921d0fef042d96", "97333d60db66cd6be15e02", "99edf08c9abd1c97467fc18c875c1bec5272226fe548f325bf44611e5019126478b38b77d3bcf446b890fda7295d704b");

//ec72e76f5f0
//rP :87efc85ca9998615216c128069894089b090985eaf5bd0a9dc1a403588478c0c335d73db89c03ebe615ff8634b7f25e2

// Enc :8e8c618f865d49646fa4a9
// rP :93200fc18ea745b902054934b26efea8e989a314849e36aa6e373d93bdd71175088ee75ac686b7a9dcd01e6435933f55

// hex :476f6c64656e2072756c65
// Enc :e7dfd8c2594ff1f3b45b7d
// rP :aa064d29798f320d4e1e99587f6f8fcd996e570a9fcffad79f7ae06b018b2842282f0e76a44a20dd7d67ddd51439edd3

// xof :91f6bc74d47146ca93dbc7
// hex :476f6c64656e2072756c65
// enc :d699d010b11f66b8e6b7a2
// rP :84bd71851893ca6ef09cb2e19a560e872f2db4be678231494e4e2b51a5f8e37698d1057d2859113ab0dff8a45a8c1ce9

async function check_pairing(){
  
  // sigma
  const mSize = message.length;
  const sigma = getRandom(mSize);
  
  // r = H3( sigma, M) -> zq* 
  var h3Hash = await bls.utils.sha256(Buffer.concat([sigma, str2ab(message)]));
  
  
  const r =  bls.utils.mod(bytesToNumberBE(h3Hash), bls.CURVE.r);
  const rP = bls.getPublicKey(r);
}

/* GET home page. */
router.get('/', async (req, res) => {
  var randomness = await fetch_randomness();
  var stat = await check_pairing();
  console.log(randomness);
  res.render('index', {round : randomness.round});
});









module.exports = router;


//const distributedPublicKey = '868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31';
//const round = 985404;
//const previous_sig = "b0e992c1471c7cb74290ce5a4ddb750986229c6ab4c37472751a85edc20ef0a6d0127ce08d87df33670d238945358415102d04d5302e415062e0ef1dd1443cef64f699d883c910feb39a401dbe37401b399c3967fad74662fd461ace8749e55a";
//let sig_buf = hexToBytes(previous_sig);
//var roundHashPromise = bls.utils.sha256(Buffer.concat([sig_buf, buf]));
//var roundHashPromise = bls.utils.sha256(buf);
//var roundHash;
//roundHashPromise.then(data => roundHash = data);
// var HroundPromise = hashToCurve(roundHash);
// var Hround
// HroundPromise.then(data => Hround = data);
//const randomsig = 'a17df06705f638598099ae831b9feb99bb4cf580c0a126ce3cc439c67fc038d4eed2ac9bb572a5da96c98472db0e119917ac74503722fff771f8ca842ea5619c4ea65235eb7f6cd63f968b782a8536790180b88404b94b47a09cb5985928a32d';