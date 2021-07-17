const express = require('express');
const https = require('https');
const { hrtime } = require('process');
var router = express.Router();
const ecc_crypto = require("./crypto")

const round = 2118;


/* GET home page. */
router.get('/', async (req, res) => {
  const now = Date.now();
  var randomness = await ecc_crypto.fetch_randomness(now, true);

  // Testing
  var enc = await ecc_crypto.encrypt("This is a test message to check if the encryption works", round);
  console.log(enc);
  ecc_crypto.decrypt(enc);

  res.render('index', {round : randomness.round});
});





// async function check_pairing(){
  
//   // sigma
//   const mSize = message.length;
//   const sigma = getRandom(mSize);
  
//   // r = H3( sigma, M) -> zq* 
//   var h3Hash = await bls.utils.sha256(Buffer.concat([sigma, str2ab(message)]));
  
  
//   const r =  bls.utils.mod(bytesToNumberBE(h3Hash), bls.CURVE.r);
//   const rP = bls.getPublicKey(r);
// }

module.exports = router;
