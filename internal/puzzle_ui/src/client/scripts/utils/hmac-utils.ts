import {HmacSHA256, enc} from 'crypto-js'


/**
 * generateHmacWithFallback allows for hashing using either the crypto.subtle api for modern browsers or the bundled crypto-js if crypto.subtle not found
 * @param key hmac key
 * @param message payload
 * @returns hmac
 */
export async function generateHmacWithFallback(key: string, message: string): Promise<string> {
    if (window.crypto && window.crypto.subtle) {
        const encKey = new TextEncoder().encode(key)
        const encMessage = new TextEncoder().encode(message)
        const cryptoKey = await crypto.subtle.importKey('raw', encKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
        const signature = await crypto.subtle.sign('HMAC', cryptoKey, encMessage)
        return Array.from(new Uint8Array(signature)).map((b) => b.toString(16).padStart(2, '0')).join('')
    } else {
        return HmacSHA256(message, key).toString(enc.Hex)
    }
}
