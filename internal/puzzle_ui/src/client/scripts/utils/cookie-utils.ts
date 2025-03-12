import cookie from "cookie"

export function getCookieValue(targetCookieName: string): string | Error {

    const cookieHeadersString = document.cookie

    if (!cookieHeadersString) {
        return new Error(`ErrHeadersMissingCookieString: expected parsable cookie string, got: ${cookieHeadersString}`)
    }

    const cookieMap: Record<string, string> = cookie.parse(cookieHeadersString)
    const targetCookieValue = cookieMap[targetCookieName]

    if (targetCookieValue === undefined) {
        return new Error(`ErrMissingTargetCookie: cookie with name: ${targetCookieName} not found`)
    }

    if (!targetCookieValue) {
        return new Error(`ErrInvalidTargetCookie: cookie with name: ${targetCookieName} returned empty value`)
    }

    return targetCookieValue
}

export function attachCookie(
    
    name:string, 
    value:string, 
    args?:{
        expirySecondsFromNow?:number, 
        path?:string, 
        sameSite?:"Strict" | "Lax" | "None"
    }

) : void {

    let expiryValue = args?.expirySecondsFromNow ?? 30
    let sameSiteValue = args?.sameSite ?? "Lax"
    let pathValue = args?.path ?? "/"

    const expiryDate = new Date()
    expiryDate.setSeconds(expiryDate.getSeconds() + expiryValue)

    const isHTTPSConnection = window.location.protocol === "https"

    let cookieToAttach = `${name}=${value}; path=${pathValue}; SameSite=${sameSiteValue}; Max-Age=${expiryValue}; expires=${expiryDate.toUTCString()};`
    
    //if its https or samesite is 'none', we need to add 'secure' since some 
    //browsers (like safari) require it and make testing a pain when working over http
    if (isHTTPSConnection || sameSiteValue === "None") {
        cookieToAttach += " Secure;"
    }

    document.cookie = cookieToAttach
}