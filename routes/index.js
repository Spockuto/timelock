const express = require('express');
const https = require('https');
const { hrtime } = require('process');
var router = express.Router();
const bls = require("noble-bls12-381");
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



async function fetch_randomness() {
  const { default: Client, HTTP } = await import('drand-client')
  const options = { chainHash }
  const client = await Client.wrap(HTTP.forURLs(urls, chainHash), options)
  const res = await client.get()
  return res
}

async function check_pairing(){
  //rP
  const r = bls.utils.randomPrivateKey();
  const rP = bls.getPublicKey(r);

  // message for the H(m)
  let buf = Buffer.allocUnsafe(8);
  buf.writeBigInt64BE(BigInt(round));
  var roundHash = await bls.utils.sha256(buf)
  
  // H(m) = xP
  var Hround = await hashToCurve(roundHash);

  if (Hround.isOnCurve()){
    //rxP
    var rHround = Hround.multiply(bytesToNumberBE(r));
    //sP
    var Ppub = bls.PointG1.fromHex(distributedPublicKey);
    //e(rxP, sP)
    var finalPairing = bls.pairing(Ppub, rHround);
    console.log(finalPairing.toString());
  }

  //rP
  point1 = bls.PointG1.fromHex(bytesToHex(rP));
  //xsP
  point2 = bls.PointG2.fromSignature(randomsig);
  //e(rP, xsP)
  var pairing2 = bls.pairing(point1,point2);
  
  console.log(pairing2.toString());

}

/* GET home page. */
router.get('/', async (req, res) => {
  var randomness = await fetch_randomness();
  var stat = await check_pairing();
  console.log(randomness);
  res.render('index', {round : randomness.round});
});

async function hashToCurve(message){
  var result = await bls.PointG2.hashToCurve(message);
  return result 
}

function bytesToNumberBE(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
      value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

function bytesToHex(uint8a) {
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
      hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex) {
  if (typeof hex !== 'string') {
      throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2)
      throw new Error('hexToBytes: received invalid unpadded hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
      const j = i * 2;
      array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}








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