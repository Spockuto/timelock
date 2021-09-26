const express = require('express');
const https = require('https');
const _crypto = require('crypto');
const { hrtime } = require('process');
var router = express.Router();
const ecc_crypto = require("./crypto")

const round = 28;


/* GET home page. */
router.get('/', async (req, res) => {
  const now = Date.now();
  var randomness = await ecc_crypto.fetch_randomness(round);
  var enc_sum = 0;
  var dec_sum = 0;

  // Code for analysis 
  // for (i = 0; i < 1000; i++) {
  //   var rand = _crypto.randomBytes(1500).toString('hex');
  //   var start =  Date.now();
  //   var encryptdata = await ecc_crypto.encrypt(rand, 25);
  //   var enc_time = Date.now() - start;
  //   enc_sum += enc_time;
  //   var start =  Date.now();
  //   var decryptdata  = await ecc_crypto.decrypt(encryptdata);
  //   var dec_time = Date.now() - start;
  //   dec_sum += dec_time;
  //   console.log(enc_time.toString() + " " + dec_time.toString());
  // }
  // console.log(enc_sum.toString() + " " + dec_sum.toString())
  
  // x = [];
  // y = []; 

  // for (i = 1; i < 1501; i++) {
  //   var rand = _crypto.randomBytes(i).toString('hex');
  //   x.push(rand.length);
  //   var encryptdata = await ecc_crypto.encrypt(rand, 25);
  //   y.push(encryptdata.length);
  //   //console.log(rand.length.toString() + " " + encryptdata.length.toString());
  // }
  // console.log(x.toString());
  // console.log(y.toString());

  res.render('index', {round : randomness.round});
});

router.post('/encrypt', async (req, res) => {
  var round = parseInt(req.body.round, 10);
  const message = req.body.message;
  const timeBool = (req.body.timeBool === 'true');

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


module.exports = router;
