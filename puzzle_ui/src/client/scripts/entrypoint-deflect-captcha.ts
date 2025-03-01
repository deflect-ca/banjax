/*
    for future reference:

        - since we need to support legacy browsers and they dont have JS features we are using like Promise/Array.prototype.find, URLSearchParams etc
        - we need to import these so that rollup can bundle the requirements for core-js polyfilling

        - always import polyfills you need explicitly at the very top of this entrypoint file (as we are using "entry" in the rollup)
        - entry mode provides better predictability when dealing with complex setups involving Rollup, Babel, CSS injection, and legacy browser support.

    order matters:
        - Polyfills first
        - CSS second
        - App logic last
*/
import 'core-js/es/string/starts-with' //for String.prototype.startsWith
import 'core-js/web/url-search-params' //for URLSearchParams
import 'regenerator-runtime/runtime' //for async/await support
import 'core-js/es/string/pad-start' // String.prototype.padStart for hex formatting
import 'core-js/es/array/find' // for Array.prototype.find
import 'fast-text-encoding' // Polyfill for TextEncoder/TextDecoder
import 'core-js/es/promise' //for promises
import 'core-js/stable'





//import css such that rolllup will bundle all of the css as its imported in the entrypoint 
//this allows us to replace multiple requests of assets with 1 request for the bundle
import '../styles/puzzle-messages-to-user.css'
import '../styles/puzzle-instructions.css'
import '../styles/puzzle-submission.css'
import '../styles/puzzle-container.css'
import '../styles/puzzle-thumbnail.css'
import '../styles/puzzle-refresh.css'
import '../styles/puzzle-grid.css'
import '../styles/main.css'


import attachFooterHeaderHostname from "./attach-footer-and-header-info"
import attachInfoOverlay from "./puzzle-instructions-info-button"
import attachThumbnailOverlay from "./inspect-target-image-modal"
import ClientCaptchaSolver from "./client-captcha-solver"
import RefreshPuzzle from "./request-different-puzzle"







/*
    entrypoint to the captcha

    phones home to get the CAPTCHA
    if any critical failure occurs, retry until exhaust attempts or server response indicates to stop trying
        -NOTE: A critical failure is an inability to setup the challenge or run the puzzle in any way. 
            - Some issues like failure to setup thumbail inspection or additional info listeners are non critical, so the captcha will proceed (but it will report them)
    if server indicates to stop trying, run hardcoded fallback challenge
*/

let clientSideAttempt = 0

const ENABLE_DEBUG = false
const MAX_CLIENT_SIDE_RETRIES = 3
const CLIENT_SIDE_RATE_LIMIT_WINDOW = {
    maxNumberOfNewPuzzles: 3, 
    unitTimeInMs: 60000
}

const CAPTCHA_COOKIE_NAME = "deflect_challenge4"

const HOSTNAME_FOOTER_HEADER_ERROR_ENDPOINT = "/api/hostname-footer-header-error"
const REQUEST_NEW_PUZZLE_ERROR_ENDPOINT = "/api/request-different-puzzle-error"
const DETAILED_INSTRUCTION_ERROR_ENDPOINT = "/api/detail-instruction-error"
const INSPECT_THUMBNAIL_ERROR_ENDPOINT = "/api/inspect-thumbnail-error"
const CAPTCHA_INIT_ERROR_ENDPOINT = "/api/captcha-init-error"
const GENERIC_ERROR_ENDPOINT = "/api/generic-error"


const VERIFY_SOLUTION_ENDPOINT = "/validate_puzzle_solution"
const NEW_PUZZLE_ENDPOINT = "/new_puzzle_challenge"




//init CAPTCHA after dom has fully loaded
document.addEventListener('DOMContentLoaded', async function() {
    window.addEventListener("captchaError", captchaErrorListener)
    await runCaptcha(clientSideAttempt)
})




/*
    Some error cannot be dealt with inside of the functions themselves, for example if a puzzle 
    is missing a cookie, we cannot fix that problem internally, so instead we bubble the error
    all the way back out and exploit the existing retry+fallback mechanisms that exist
*/
const captchaErrorListener = async (event: CustomEvent) => {
    console.error(`ErrGlobalCaptcha: ${event.detail}`)
    await runCaptcha(clientSideAttempt, event.detail)
}





/*
    NOTE for future:

        we can use this space here (ie at the level of the runCaptcha() prior to phoning home) to run checks to see if their browser supports
        things like webworkers, wasm etc and send that info when phoning home so that we can respond back with the right captcha that is most secure
        or best performing for their system etc.. up to you!
*/
async function runCaptcha(clientSideAttempt:number=0, error?: any):Promise<void> {
    
    clientSideAttempt++

    try {

        if (error) {
            throw new Error(`ErrCaughtUnhandledGlobalError: ${error}`)
        }
        
        await phoneHomeForCaptcha()

    } catch(error) {

        let errEndpoint = GENERIC_ERROR_ENDPOINT

        if (error instanceof Error && error.message.includes("ErrFailedClientCaptchaInit")) {
            errEndpoint = CAPTCHA_INIT_ERROR_ENDPOINT
        }

        const requestToRetry = await reportError(new Error(`ErrCaughtException: ${error}`), errEndpoint)

        if (requestToRetry.allowedToRetry && clientSideAttempt < MAX_CLIENT_SIDE_RETRIES) {    
            await runCaptcha(clientSideAttempt)
            return
        } else {
            await runFallbackCaptcha()
            return
        }
    }
}


async function phoneHomeForCaptcha() {

    //this request will already admit the challenge cookie, so we can acceess that from headers
    const requestForPuzzle = await fetch(NEW_PUZZLE_ENDPOINT, {
        method:"GET",
        credentials:"include"
    })

    if (!requestForPuzzle.ok) {
        throw new Error("ErrNoResponse: Failed to get response")
    }
    
    //at this point we know we got a response back (response.ok)

    if (requestForPuzzle.status !== 200) {
        throw new Error(`ErrUnexpectedStatus: Expected status 200, got: ${requestForPuzzle.status}}`)
    }

    //at this point we know we received the result as desired (status 200)
        
    //parse challenge we received
    const puzzleChallenge:PuzzleChallenge = await requestForPuzzle.json()
    
    //the constructor sets up the entire puzzle - ie just initializing is enough
    //NOTE: Since this is a critical error, we will immediately check for retry by throwing and catching in the runChallenge.
    // This is unlike the remaining scripts which are nice to have for user experience, but not critical to functionality
    const clientSideSolver = new ClientCaptchaSolver(puzzleChallenge, VERIFY_SOLUTION_ENDPOINT, CAPTCHA_COOKIE_NAME, ENABLE_DEBUG)
    const successfullyInitializedCaptcha = clientSideSolver.initCaptcha()
    if (!successfullyInitializedCaptcha.success) {
        throw new Error(`ErrFailedClientCaptchaInit: ${successfullyInitializedCaptcha.error}`)
    }

    //attaches client side rate limited request new puzzle button. NOTE: We also rate limit server side
    const {maxNumberOfNewPuzzles, unitTimeInMs} = CLIENT_SIDE_RATE_LIMIT_WINDOW
    const rateLimitedPuzzleRefresher = new RefreshPuzzle(maxNumberOfNewPuzzles, unitTimeInMs, clientSideSolver, NEW_PUZZLE_ENDPOINT, ENABLE_DEBUG)
    const successfullyAttachedRefresh = rateLimitedPuzzleRefresher.initPuzzleRefresh()
    if (!successfullyAttachedRefresh.success) {
        if (successfullyAttachedRefresh.error instanceof Error) {
            await reportError(successfullyAttachedRefresh.error, REQUEST_NEW_PUZZLE_ERROR_ENDPOINT)
        }                
    }

    //attaches capability to inspect the thumbnail, reports error if fails
    const successfullAttachedThumbnailInspection = attachThumbnailOverlay()
    if (!successfullAttachedThumbnailInspection.success) {
        if (successfullAttachedThumbnailInspection.error instanceof Error) {
            await reportError(successfullAttachedThumbnailInspection.error, INSPECT_THUMBNAIL_ERROR_ENDPOINT)
        }                
    }

    //attaches capability to open detailed instructions overlay on click info button, reports error if fails
    const successfullyAttachedInstructions = attachInfoOverlay()
    if (!successfullyAttachedInstructions.success) {
        if (successfullyAttachedInstructions.error instanceof Error) {
            await reportError(successfullyAttachedInstructions.error, DETAILED_INSTRUCTION_ERROR_ENDPOINT)
        }                
    }
    
    const successfullyAttachedHostname = attachFooterHeaderHostname(puzzleChallenge.users_intended_endpoint)
    if (!successfullyAttachedHostname.success) {
        if (successfullyAttachedHostname.error instanceof Error) {
            await reportError(successfullyAttachedHostname.error, HOSTNAME_FOOTER_HEADER_ERROR_ENDPOINT)
        }
    }
}


async function reportError(error:Error, endpoint:string=GENERIC_ERROR_ENDPOINT):Promise<{allowedToRetry:boolean}> {

    try {
        //we will add additional info later
        const somethingWentWrong_requestPermissionToRetry = await fetch(endpoint, {
            method:"POST",
            headers: {"Content-Type": "application/json"},
            credentials:"include",
            body:JSON.stringify({error:`${error}`})
        })

        if (somethingWentWrong_requestPermissionToRetry.ok) {
            if (somethingWentWrong_requestPermissionToRetry.status === 202) {
                //we got permission to retry, otherwise we would be blocked
                return {allowedToRetry:true}
            }
        }

        //no answer or not correct status code, fallback
        return {allowedToRetry:false}
    
    } catch(error) {
        return {allowedToRetry:false}
    }

}

async function runFallbackCaptcha() {

    console.log("RUNNING FALLBACK!")
    /*
        classic POW challenge - either hardcoded or fetch for the existing deflect challenge? That way the user always has something...

        NOTE: 
            the fallback would need to remove the entire gameboard and then run its own challenge
    
    */
}