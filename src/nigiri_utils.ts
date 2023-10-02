import axios, { AxiosResponse } from 'axios'

export interface IUTXO {
  txid: string
  vout: number
  status: {
    confirmed: boolean
    block_height: number
    block_hash: string
    block_time: number
  }
  value: number
}

const nigiri = new axios.Axios({
  baseURL: `http://localhost:3000`,
})

export const waitUntilUTXO = async (address: string) => {
  return new Promise<IUTXO[]>((resolve, reject) => {
    let intervalId: any
    const checkForUtxo = async () => {
      try {
        const response: AxiosResponse<string> = await nigiri.get(
          `/address/${address}/utxo`
        )
        const data: IUTXO[] = response.data
          ? JSON.parse(response.data)
          : undefined
        if (data.length > 0) {
          resolve(data)
          clearInterval(intervalId)
        }
      } catch (error) {
        reject(error)
        clearInterval(intervalId)
      }
    }
    intervalId = setInterval(checkForUtxo, 10000)
  })
}

export const broadcast = async (txHex: string) => {
  const response: AxiosResponse<string> = await nigiri.post('/tx', txHex)
  return response.data
}
