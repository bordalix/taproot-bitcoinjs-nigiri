# A Guide to creating TapRoot Scripts with bitcoinjs-lib

- [A Guide to creating TapRoot Scripts with bitcoinjs-lib](#a-guide-to-creating-taproot-scripts-with-bitcoinjs-lib)
  - [Introduction](#introduction)
  - [Development environment](#development-environment)
    - [Nigiri](#nigiri)
    - [Docker](#docker)
  - [Code](#code)
    - [Taproot Key-spend transaction](#taproot-key-spend-transaction)
    - [Taproot Script-spend transaction](#taproot-script-spend-transaction)
  - [Conclusion](#conclusion)

## Introduction

Taproot and Schnorr are upgrades to the Bitcoin protocol designed to enhance the privacy, efficiency and flexibility of Bitcoin transactions.

Taproot introduces Taptrees, a feature that reduces the size of transaction data and ensures only necessary information is revealed on the blockchain, thereby preserving privacy. With Taproot, multisig transactions are also more private as unused spending conditions are hidden.

Schnorr signatures are 64 bytes long instead of the 72 bytes used by current ECDSA signature scheme. Taproot also use only x-values of public keys for signature creation which saves 1 byte.

With the adoption of Taproot and Schnorr, Bitcoin transactions can be more efficient, flexible, and private.

We'll go over two examples. In our first example, we will create a pay-to-taproot(p2tr) address that will lock funds to a key and create a spend transaction for it. In our second example, we will jump straight into taproot script-spend transactions, we will create a Taptree consisting of two script-spend paths, a pay-to-pubkey script spend path and a hash-lock script spend path. We will create transactions that spend from both paths. Finally, we will create a fourth transaction that spends the hash-lock script without using the script tree.

We'll be using Regtest provided by [Nigiri](https://github.com/vulpemventures/nigiri).

## Development environment

### Nigiri

Download and install Nigiri command line interface:

```
$ curl https://getnigiri.vulpem.com | bash
```

This will also install several configurable files, such as `bitcoin.conf` and `elements.conf`, that can be edited. These can be found browsing the following directory:

> POSIX (Linux/BSD): ~/.nigiri
>
> macOS: $HOME/Library/Application\ Support/Nigiri
>
> Windows: %LOCALAPPDATA%\Nigiri
>
> Plan 9: $home/nigiri

### Docker

If you don't have it, [install Docker](https://docs.docker.com/desktop/).

Lauch Docker daemon (Mac OSX)

```
$ open -a Docker
```

You may want to [Manage Docker as a non-root user](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user)

Close and reopen your terminal, then start Bitcoin

```
$ nigiri start
```

**Note for users of macOS Monterey an onward**

<details>
  <summary>Show more...</summary>
   When trying to start Nigiri, you might get an error similar to the following:

```bash
Error response from daemon: Ports are not available: listen tcp 0.0.0.0:5000: bind: address already in use
exit status 1
```

This is due to AirPlay Receiver using port 5000, conflicting with Esplora trying to run using the very same port.

There are two ways to deal with this issue:

1. Uncheck AirPlay Receiver in `System Preferences → Sharing → AirPlay Receiver`
2. Change Esplora’s port to something other than 5000. This can be done by changing it in [docker-compose.yml](https://github.com/vulpemventures/nigiri/blob/master/cmd/nigiri/resources/docker-compose.yml#L110) found in your data directory. If you previously tried starting Nigiri getting an error – you might have to run `nigiri stop --delete` before restarting it.
</details>
<br />

**That's it.**

You now have a command line interface that manages a selection of `docker-compose` batteries included to have ready-to-use bitcoin `regtest` development environment, with a bitcoin node, electrum explorer both backend and frontend user interface.

Nigiri also offers a JSON HTTP proxy passtrough that adds to the explorer handy endpoints like `/faucet` and automatic block generation when calling the `/tx` pushing a transaction.

## Code

### Taproot Key-spend transaction

For illustration purposes, we'll use a random keypair:

```
const keypair = ECPair.makeRandom({ network });
```

We tweak this keypair with our pubkey:

```
const tweakedSigner = tweakSigner(keypair, { network });
```

bitcoinjs-lib provides a p2tr function to generate p2tr outputs:

```
const p2pktr = payments.p2tr({
  pubkey: toXOnly(tweakedSigner.publicKey),
  network
});

const p2pktr_addr = p2pktr.address ?? "";

console.log(p2pktr_addr);
```

The `toXOnly` function extracts the x-value of our public key.

We will use Nigiri to automate the faucet.

Creating a spend-transaction for this address with bitcoinjs-lib is straightforward:

```
const psbt = new Psbt({ network });

psbt.addInput({
  hash: utxos[0].txid,
  index: utxos[0].vout,
  witnessUtxo: { value: utxos[0].value, script: p2pktr.output! },
  tapInternalKey: toXOnly(keypair.publicKey)
});

psbt.addOutput({
   address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
   value: utxos[0].value - 150
});

psbt.signInput(0, tweakedSigner);

psbt.finalizeAllInputs();
```

Extract the transaction and broadcast the transaction hex:

```
const tx = psbt.extractTransaction();

console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);

const txid = await broadcast(tx.toHex());

console.log(`Success! Txid is ${txid}`);
```

### Taproot Script-spend transaction

We'll create a Tap tree with two spend paths, a hash-lock spend path and a pay-to-pubkey spend path.

The hash-lock script-spend path will require the spender to include a preimage that will produce the hash specified in the script.

Let's make another random keypair for our hash-lock script:

```
const hash_lock_keypair = ECPair.makeRandom({ network });
```

Now, we will construct our hash-lock script:

```
const secret_bytes = Buffer.from('SECRET');

const hash = crypto.hash160(secret_bytes);

// Construct script to pay to hash_lock_keypair if the correct preimage/secret is provided
const hash_script_asm = `OP_HASH160 ${hash.toString('hex')} OP_EQUALVERIFY ${toXOnly(hash_lock_keypair.publicKey).toString('hex')} OP_CHECKSIG`;

const hash_lock_script = script.fromASM(hash_script_asm);
```

Notice that script still requires a signature to unlock funds.

The pay-to-pubkey spend path is much simpler:

```
const p2pk_script_asm = `${toXOnly(keypair.publicKey).toString('hex')} OP_CHECKSIG`;
const p2pk_script = script.fromASM(p2pk_script_asm);
```

We can now create our Taptree and p2tr address:

```
const scriptTree: Taptree = [
  { output: hash_lock_script },
  { output: p2pk_script },
];

const script_p2tr = payments.p2tr({
  internalPubkey: toXOnly(keypair.publicKey),
  scriptTree,
  network
});

const script_addr = script_p2tr.address ?? '';

console.log(script_addr);
```

Nigiri deposits some test btc into the address using the regtest faucet.

To spend on any of the leaf scripts, you must present the leafVersion, script and controlBlock for that leaf script. The control block is data required to prove that the leaf script exists in the script tree (merkle proof).

bitcoinjs-lib will generate the control block for us:

```
const hash_lock_redeem = {
  output: hash_lock_script,
  redeemVersion: 192,
};

const p2pk_redeem = {
  output: p2pk_script,
  redeemVersion: 192
}

const p2pk_p2tr = payments.p2tr({
  internalPubkey: toXOnly(keypair.publicKey),
  scriptTree,
  redeem: p2pk_redeem,
  network
});

const hash_lock_p2tr = payments.p2tr({
  internalPubkey: toXOnly(keypair.publicKey),
  scriptTree,
  redeem: hash_lock_redeem,
  network
});

console.log(`Waiting till UTXO is detected at this Address: ${script_addr}`);

let utxos = await waitUntilUTXO(script_addr)

console.log(`Trying the P2PK path with UTXO ${utxos[0].txid}:${utxos[0].vout}`);

const p2pk_psbt = new Psbt({ network });

p2pk_psbt.addInput({
  hash: utxos[0].txid,
  index: utxos[0].vout,
  witnessUtxo: { value: utxos[0].value, script: p2pk_p2tr.output! },
  tapLeafScript: [
    {
      leafVersion: p2pk_redeem.redeemVersion,
      script: p2pk_redeem.output,
      controlBlock: p2pk_p2tr.witness![p2pk_p2tr.witness!.length -  1] // extract control block from witness data
    }
  ]
});

p2pk_psbt.addOutput({
  address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
  value: utxos[0].value - 150
});

p2pk_psbt.signInput(0, keypair);
p2pk_psbt.finalizeAllInputs();

let tx = p2pk_psbt.extractTransaction();

console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);

let txid = await broadcast(tx.toHex());

console.log(`Success! Txid is ${txid}`);
```

To spend using the hash-lock leaf script, we have to create a custom finalizer function. In our custom finalizer, we will create our witness stack of signature, preimage, original hash-lock script and our control block:

```
const tapLeafScript = {
  leafVersion: hash_lock_redeem.redeemVersion,
  script: hash_lock_redeem.output,
  controlBlock: hash_lock_p2tr.witness![hash_lock_p2tr.witness!.length - 1]
};

const psbt = new Psbt({ network });
psbt.addInput({
  hash: utxos[0].txid,
  index: utxos[0].vout,
  witnessUtxo: { value: utxos[0].value, script: hash_lock_p2tr.output! },
  tapLeafScript: [
    tapLeafScript
  ]
});

psbt.addOutput({
  address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
  value: utxos[0].value - 150
});

psbt.signInput(0, hash_lock_keypair);

// We have to construct our witness script in a custom finalizer

const customFinalizer = (_inputIndex: number, input: any) => {
  const scriptSolution = [
    input.tapScriptSig[0].signature,
    secret_bytes
  ];
  const witness = scriptSolution
    .concat(tapLeafScript.script)
    .concat(tapLeafScript.controlBlock);
  return {
    finalScriptWitness: witnessStackToScriptWitness(witness)
  }
}

psbt.finalizeInput(0, customFinalizer);

tx = psbt.extractTransaction();

console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);

txid = await broadcast(tx.toHex());

console.log(`Success! Txid is ${txid}`);
```

## Conclusion

You should now have a better understanding of how to use bitcoinjs-lib to create and spend P2TR (Pay to Taproot) payments. With this knowledge, you are one step closer to leveraging the benefits of Taproot in your Bitcoin transactions, such as improved privacy, scalability, and the ability to create more complex smart contracts.
