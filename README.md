# A Guide to creating TapRoot Scripts with bitcoinjs-lib

- [A Guide to creating TapRoot Scripts with bitcoinjs-lib](#a-guide-to-creating-taproot-scripts-with-bitcoinjs-lib)
  - [Introduction](#introduction)
  - [Development environment](#development-environment)
    - [Docker](#docker)
    - [Nigiri](#nigiri)
    - [Run](#run)
  - [Code](#code)
    - [Taproot Key-spend transaction](#taproot-key-spend-transaction)
    - [Taproot Script-spend transaction](#taproot-script-spend-transaction)
  - [Conclusion](#conclusion)
  - [Acknowledgements](#acknowledgements)

## Introduction

Taproot and Schnorr are upgrades to the Bitcoin protocol designed to enhance the privacy, efficiency and flexibility of Bitcoin transactions.

Taproot introduces Taptrees, a feature that reduces the size of transaction data and ensures only necessary information is revealed on the blockchain, thereby preserving privacy. With Taproot, multisig transactions are also more private as unused spending conditions are hidden.

Schnorr signatures are 64 bytes long instead of the 72 bytes used by current ECDSA signature scheme. Taproot also use only x-values of public keys for signature creation which saves 1 byte.

With the adoption of Taproot and Schnorr, Bitcoin transactions can be more efficient, flexible, and private.

We'll go over two examples. In our first example, we will create a pay-to-taproot(p2tr) address that will lock funds to a key and create a spend transaction for it. In our second example, we will jump straight into taproot script-spend transactions, we will create a Taptree consisting of two script-spend paths, a pay-to-pubkey script spend path and a hash-lock script spend path. We will create transactions that spend from both paths. Finally, we will create a fourth transaction that spends the hash-lock script without using the script tree.

We'll be using Regtest provided by [Nigiri](https://github.com/vulpemventures/nigiri).

Nigiri is a local regtest development box for Bitcoin and Liquid:

- Run Bitcoin and Liquid in regtest mode
- Electrs and Esplora for easy development
- Faucet, mint and broadcast with a command

## Development environment

### Docker

If you don't have it, [install Docker](https://docs.docker.com/desktop/).

Lauch Docker daemon (Mac OSX)

```
$ open -a Docker
```

### Nigiri

If you don't have it, [install Nigiri](https://github.com/vulpemventures/nigiri)

Start Nigiri

```
$ nigiri start
```

### Run

Install dependencies (only first time)

```
$ yarn
```

and then

```
$ yarn start
```

## Code

### Taproot Key-spend transaction

For illustration purposes, we'll use a random keypair:

```
const keypair = ECPair.makeRandom({ network })
```

We tweak this keypair with our pubkey:

```
const tweakedSigner = tweakSigner(keypair, { network })
```

bitcoinjs-lib provides a p2tr function to generate p2tr outputs:

```
const p2pktr = payments.p2tr({
  pubkey: toXOnly(tweakedSigner.publicKey),
  network
});

const p2pktr_addr = p2pktr.address ?? ""

console.log(`Address generated: ${p2pktr_addr}\n`)
```

The `toXOnly` function extracts the x-value of our public key.

We will use Nigiri to automate the faucet:

```
// instruct Nigiri to send coins to address
const utxos = await faucetAndWait(p2pktr_addr)
```

Creating a spend-transaction for this address with bitcoinjs-lib is straightforward:

```
// create psbt
 const psbt = new Psbt({ network })

 psbt.addInput({
   hash: utxos[0].txid,
   index: utxos[0].vout,
   witnessUtxo: { value: utxos[0].value, script: p2pktr.output! },
   tapInternalKey: toXOnly(keypair.publicKey),
 })

 psbt.addOutput({
   address: return_address,
   value: utxos[0].value - 150,
 })

 psbt.signInput(0, tweakedSigner)

 psbt.finalizeAllInputs()

 // extract transaction from psbt and broadcast
 await extractAndBroadcast(psbt)
```

Extract the transaction and broadcast the transaction hex:

```
async function extractAndBroadcast(psbt: Psbt) {
  const tx = psbt.extractTransaction()
  console.log(`- Broadcasting Transaction Hex: ${tx.toHex()}`)
  const txid = await broadcast(tx.toHex())
  console.log(`- Success! Txid is ${txid}`)
}
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
const secret_bytes = Buffer.from('SECRET')

const hash = crypto.hash160(secret_bytes)

// Construct script to pay to hash_lock_keypair if the correct preimagesecret is provided
const hash_script_asm = [
  'OP_HASH160',
  hash.toString('hex'),
  'OP_EQUALVERIFY',
  toXOnly(hash_lock_keypair.publicKey).toString('hex'),
  'OP_CHECKSIG',
].join(' ')

const hash_lock_script = script.fromASM(hash_script_asm)
```

Notice that script still requires a signature to unlock funds.

The pay-to-pubkey spend path is much simpler:

```
// Construct script to pay to pubkey
const p2pk_script_asm = [
  toXOnly(keypair.publicKey).toString('hex'),
  'OP_CHECKSIG',
].join(' ')

const p2pk_script = script.fromASM(p2pk_script_asm)
```

We can now create our Taptree and p2tr address:

```
const scriptTree: Taptree = [
  { output: hash_lock_script },
  { output: p2pk_script },
]

const script_p2tr = payments.p2tr({
  internalPubkey: toXOnly(keypair.publicKey),
  scriptTree,
  network,
})

const script_addr = script_p2tr.address ?? ''

console.log(`Address generated: ${script_addr}\n`)
```

Nigiri deposits some test btc into the address using the regtest faucet:

```
let utxos = await faucetAndWait(script_addr)
```

To spend on any of the leaf scripts, you must present the leafVersion, script and controlBlock for that leaf script. The control block is data required to prove that the leaf script exists in the script tree (merkle proof).

bitcoinjs-lib will generate the control block for us:

```
const hash_lock_redeem = {
  output: hash_lock_script,
  redeemVersion: 192,
}

const p2pk_redeem = {
  output: p2pk_script,
  redeemVersion: 192,
}

const p2pk_p2tr = payments.p2tr({
  internalPubkey: toXOnly(keypair.publicKey),
  scriptTree,
  redeem: p2pk_redeem,
  network,
})

const hash_lock_p2tr = payments.p2tr({
  internalPubkey: toXOnly(keypair.publicKey),
  scriptTree,
  redeem: hash_lock_redeem,
  network,
})

// create PSBT
const p2pk_psbt = new Psbt({ network })

p2pk_psbt.addInput({
  hash: utxos[0].txid,
  index: utxos[0].vout,
  witnessUtxo: { value: utxos[0].value, script: p2pk_p2tr.output! },
  tapLeafScript: [
    {
      leafVersion: p2pk_redeem.redeemVersion,
      script: p2pk_redeem.output,
      controlBlock: p2pk_p2tr.witness![p2pk_p2tr.witness!.length - 1],
    },
  ],
})

p2pk_psbt.addOutput({
  address: return_address,
  value: utxos[0].value - 150,
})

// sign and finalize
p2pk_psbt.signInput(0, keypair)
p2pk_psbt.finalizeAllInputs()

// extract transaction from psbt and broadcast
await extractAndBroadcast(p2pk_psbt)
```

To spend using the hash-lock leaf script, we have to create a custom finalizer function. In our custom finalizer, we will create our witness stack of signature, preimage, original hash-lock script and our control block:

```
const tapLeafScript = {
  leafVersion: hash_lock_redeem.redeemVersion,
  script: hash_lock_redeem.output,
  controlBlock: hash_lock_p2tr.witness![hash_lock_p2tr.witness!.length - 1],
}

// create psbt
const psbt = new Psbt({ network })

psbt.addInput({
  hash: utxos[0].txid,
  index: utxos[0].vout,
  witnessUtxo: { value: utxos[0].value, script: hash_lock_p2tr.output! },
  tapLeafScript: [tapLeafScript],
})

psbt.addOutput({
  address: return_address,
  value: utxos[0].value - 150,
})

// sign input
psbt.signInput(0, hash_lock_keypair)

// We have to construct our witness script in a custom finalizer
const customFinalizer = (_inputIndex: number, input: any) => {
  const scriptSolution = [input.tapScriptSig[0].signature, secret_bytes]
  const witness = scriptSolution
    .concat(tapLeafScript.script)
    .concat(tapLeafScript.controlBlock)

  return {
    finalScriptWitness: witnessStackToScriptWitness(witness),
  }
}

// finalize input
psbt.finalizeInput(0, customFinalizer)

// extract transaction from psbt and broadcast
await extractAndBroadcast(psbt)
```

Finally, we'll use the hash lock spend path without using the script tree. The main advantage is the transaction will be much smaller in size (150 vs 281 bytes and 396 vs 527 weight):

```
const key_spend_psbt = new Psbt({ network })

key_spend_psbt.addInput({
  hash: utxos[0].txid,
  index: utxos[0].vout,
  witnessUtxo: { value: utxos[0].value, script: script_p2tr.output! },
  tapInternalKey: toXOnly(keypair.publicKey),
  tapMerkleRoot: script_p2tr.hash,
})

key_spend_psbt.addOutput({
  address: return_address,
  value: utxos[0].value - 150,
})

// We need to create a signer tweaked by script tree's merkle root
const tweakedSigner = tweakSigner(keypair, { tweakHash: script_p2tr.hash })
key_spend_psbt.signInput(0, tweakedSigner)
key_spend_psbt.finalizeAllInputs()

await extractAndBroadcast(key_spend_psbt)
```

## Conclusion

You should now have a better understanding of how to use bitcoinjs-lib to create and spend P2TR (Pay to Taproot) payments. With this knowledge, you are one step closer to leveraging the benefits of Taproot in your Bitcoin transactions, such as improved privacy, scalability, and the ability to create more complex smart contracts.

## Acknowledgements

Oghenovo Usiwoma for [his article](https://dev.to/eunovo/a-guide-to-creating-taproot-scripts-with-bitcoinjs-lib-4oph) and [original repo](https://github.com/Eunovo/taproot-with-bitcoinjs)

[Vulpem Ventures](https://vulpem.com/) for [Nigiri](https://vulpem.com/nigiri.html)
