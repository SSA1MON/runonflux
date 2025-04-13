const zeltrezjs = require('zeltrezjs');
const btcmessage = require('bitcoinjs-message');

async function signMessage(message, privKey) {
    if (privKey.length !== 64) {
        privKey = zeltrezjs.address.WIFToPrivKey(privKey);
    }
    const pk = Buffer.from(privKey, 'hex');
    const mysignature = btcmessage.sign(message, pk, true);
    return mysignature.toString('base64');
}

const args = process.argv.slice(2);
const message = args[0];
const privKey = args[1];

signMessage(message, privKey).then(signature => {
    console.log(signature);
}).catch(err => {
    console.error("Error:", err);
});
