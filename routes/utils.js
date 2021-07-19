const bls = require("noble-bls12-381");
const _crypto = require('crypto');


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
  
function getRandom(bytesLength){
    return new Uint8Array(_crypto.randomBytes(bytesLength).buffer);
}
  
function str2Bytes(str) {
    var buf = new ArrayBuffer(str.length); // 1 bytes for each char
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen=str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return bufView;
}
  
function getXOF(pairing, length){
    return _crypto.createHash("shake256", { outputLength: length })
        .update(pairing)
        .digest("hex");
}
  
function XORHex(a, b) {
    var res = "",
        i = a.length,
        j = b.length;
    while (i-->0 && j-->0)
        res = (parseInt(a.charAt(i), 16) ^ parseInt(b.charAt(j), 16)).toString(16) + res;
    return res;
}
  
function hexToStr(str1) {
    var hex  = str1.toString();
    var str = '';
    for (var n = 0; n < hex.length; n += 2) {
        str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
    }
    return str;
}

module.exports = {hashToCurve, bytesToNumberBE, bytesToHex, hexToBytes, getRandom, str2Bytes, getXOF, XORHex, hexToStr};