import EthCrypto from "eth-crypto";

const encryptWithPublicKey = async (publicKey: any, value: any) => {
  const encryptedValue = await EthCrypto.encryptWithPublicKey(
    publicKey.replace("0x", ""), // publicKey
    value // message JSON.stringify(data)
  );
  return {
    iv: "0x" + encryptedValue.iv,
    ephemPublicKey: "0x" + encryptedValue.ephemPublicKey,
    ciphertext: "0x" + encryptedValue.ciphertext,
    mac: "0x" + encryptedValue.mac
  };
};

const decryptWithPrivateKey = async (privateKey: any, encryptedValue: any) => {
  const decryptedValue = await EthCrypto.decryptWithPrivateKey(
    privateKey.replace("0x", ""), // privateKey
    {
      iv: encryptedValue.iv.replace("0x", ""),
      ephemPublicKey: encryptedValue.ephemPublicKey.replace("0x", ""),
      ciphertext: encryptedValue.ciphertext.replace("0x", ""),
      mac: encryptedValue.mac.replace("0x", "")
    } // encrypted-data
  );
  return decryptedValue;
};

module.exports = {
  encryptWithPublicKey,
  decryptWithPrivateKey
};
