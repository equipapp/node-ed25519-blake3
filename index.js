const ed = require("@noble/ed25519");
const blake3Wasm = require("blake3-wasm");
const blake3Native = require("blake3");

const blake3 = (data) =>
  data.length < 54 ? blake3Wasm.hash(data) : blake3Native.hash(data);

const sign = async (text, privateKey) => {
  const hash = blake3(text);
  return await ed.sign(hash, privateKey);
};

const verify = async (text, signature, publicKey) => {
  const hash = blake3(text);
  return await ed.verify(signature, hash, publicKey);
};

const generatePrivateKey = () => ed.utils.randomPrivateKey();
const generatePublicKey = async (privateKey) =>
  await ed.getPublicKey(privateKey);

module.exports.blake3 = blake3;
module.exports.sign = sign;
module.exports.verify = verify;
module.exports.generatePrivateKey = generatePrivateKey;
module.exports.generatePublicKey = generatePublicKey;
