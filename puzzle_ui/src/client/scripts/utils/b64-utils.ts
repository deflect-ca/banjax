import {encode as base64Encode} from "js-base64"

/**
 * Encodes a string to Base64, using `btoa` when available,
 * and `js-base64` as a fallback.
 */
export function stringToBase64WithFallback(str: string): string {
    try {
        return typeof btoa === "function" ? btoa(str) : base64Encode(str)
    } catch (err) {
        console.error("Base64 encoding failed, using fallback:", err)
        return base64Encode(str)
    }
}

/**
 * Converts a click chain array to a Base64 string.
 */
export function clickChainToBase64WithFallback(clickChain: iClickChainEntry[]): string {
    try {
        const jsonString = JSON.stringify(clickChain)
        return stringToBase64WithFallback(jsonString)
    } catch (err) {
        console.error("Failed to encode click chain:", err)
        return ""
    }
}