const express = require('express');
const https = require('https');
const { hrtime } = require('process');
var router = express.Router();
const ecc_crypto = require("./crypto")

const round = 218;


/* GET home page. */
router.get('/', async (req, res) => {
  const now = Date.now();
  var randomness = await ecc_crypto.fetch_randomness(round);

  // Testing
  var enc = await ecc_crypto.encrypt("This is a test message to check if the encryption works", round);
  console.log(enc);
  ecc_crypto.decrypt(enc);

  res.render('index', {round : randomness.round});
});

router.post('/encrypt', async (req, res) => {
  var round = parseInt(req.body.round, 10);
  const message = req.body.message;
  const timeBool = (req.body.timeBool === 'true');
  console.log(round);
  console.log(message);
  console.log(timeBool);

  if (Boolean(timeBool)){
    round = await ecc_crypto.fetch_round(round);
  }

  const val = await ecc_crypto.round_validate(round);
  if (!val){
    return res.send({
      enc : 'Please provide a future round!'
   });
  }
  var enc = await ecc_crypto.encrypt(message, round);
  res.send({'enc' : enc});
});

router.post('/decrypt', async (req, res) => {
  var enc = req.body.enc;
  var message = await ecc_crypto.decrypt(enc);
  res.send({'message' : message});
});


router.get('/current', async (req, res) => {
  const current = await ecc_crypto.fetch_current();
  res.send({round : current.round});
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
