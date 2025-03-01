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
