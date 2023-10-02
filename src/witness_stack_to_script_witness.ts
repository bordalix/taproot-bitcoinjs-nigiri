import varuint from 'varuint-bitcoin'

/**
 * Helper function that produces a serialized witness script
 * https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/integration/csv.spec.ts#L477
 */
export const witnessStackToScriptWitness = (witness: Buffer[]) => {
  let buffer = Buffer.allocUnsafe(0)

  const writeSlice = (slice: Buffer) => {
    buffer = Buffer.concat([buffer, Buffer.from(slice)])
  }

  const writeVarInt = (i: number) => {
    const currentLen = buffer.length
    const varintLen = varuint.encodingLength(i)

    buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)])
    varuint.encode(i, buffer, currentLen)
  }

  const writeVarSlice = (slice: Buffer) => {
    writeVarInt(slice.length)
    writeSlice(slice)
  }

  const writeVector = (vector: Buffer[]) => {
    writeVarInt(vector.length)
    vector.forEach(writeVarSlice)
  }

  writeVector(witness)

  return buffer
}
