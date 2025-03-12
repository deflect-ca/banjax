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

//extra polyfills for IE11/Older Browsers as needed depending on legacy browsers we need to support
// import 'core-js/es/object/entries' //Object.entries()
// import 'core-js/es/object/values' //Object.values()
// import 'core-js/es/array/includes' //Array.prototype.includes()
// import 'core-js/es/number/is-nan' //Number.isNaN()


/*
    NOTE: SINCE WE DECIDED TO INCLUDE THE CSS DIRECTLY INTO THE INDEX.HTML
    WE NEED NOT IMPORT THE FILES HERE FOR THE BUNDLER TO FIND THEM. IF YOU WANT TO
    START RE-BUNDLING THE CSS ALONG WITH THE JS, YOU NEED ONLY UNCOMMENT THESE LINES
    AND SUBSEQUENTLY MAKE SURE THAT THE PostCSS() hook in rollup IS ALSO UNCOMMENTED.

    also, you will need to delete the style tags and the css from the index.html
*/
//import css such that rolllup will bundle all of the css as its imported in the entrypoint 
//this allows us to replace multiple requests of assets with 1 request for the bundle
// import '../styles/puzzle-messages-to-user.css'
// import '../styles/puzzle-instructions.css'
// import '../styles/puzzle-submission.css'
// import '../styles/puzzle-container.css'
// import '../styles/puzzle-thumbnail.css'
// import '../styles/puzzle-refresh.css'
// import '../styles/puzzle-grid.css'
// import '../styles/main.css'


import attachFooterHeaderHostname from "./attach-footer-and-header-info"
import attachInfoOverlay from "./puzzle-instructions-info-button"
import attachThumbnailOverlay from "./inspect-target-image-modal"
import {stringToBase64WithFallback} from './utils/b64-utils'
import ClientCaptchaSolver from "./client-captcha-solver"
import checkForInitialState from './check-initial-state'
import RefreshPuzzle from "./request-different-puzzle"
import {attachCookie} from './utils/cookie-utils'








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

const HOSTNAME_FOOTER_HEADER_ERROR_ENDPOINT = "/__banjax/error/hostname-footer-header-error"
const REQUEST_NEW_PUZZLE_ERROR_ENDPOINT = "/__banjax/error/request-different-puzzle-error"
const DETAILED_INSTRUCTION_ERROR_ENDPOINT = "/__banjax/error/detail-instruction-error"
const INSPECT_THUMBNAIL_ERROR_ENDPOINT = "/__banjax/error/inspect-thumbnail-error"
const ENTRYPOINT_INIT_ERROR_ENDPOINT = "/__banjax/error/entrypoint-init-error"
const CAPTCHA_INIT_ERROR_ENDPOINT = "/__banjax/error/captcha-init-error"


const REFRESH_PUZZLE_STATE_ENDPOINT = "/__banjax/refresh/puzzle-state"

// const VERIFY_SOLUTION_ENDPOINT = "/__banjax/validate_puzzle_solution"


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
    if (ENABLE_DEBUG) {
        console.error(`ErrGlobalCaptcha: ${event.detail}`)
    }
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

        let errEndpoint = ENTRYPOINT_INIT_ERROR_ENDPOINT

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

    let skipRequestForPuzzle = false

    const initialInjectedState:{success:boolean, error:Error | null, initialState:PuzzleChallenge | null}  = checkForInitialState()

    //the null check is a bit redundant given that the checkForInitialState only returns success if it has access but its important since 
    //its up to the dev to make sure that this is the case and we could mess it up. Plus typescript gets all mad and stuff
    if (initialInjectedState.success && initialInjectedState !== null) {
        skipRequestForPuzzle = true
    }

    let puzzleChallenge:PuzzleChallenge


    if (skipRequestForPuzzle) {
        
        puzzleChallenge = initialInjectedState.initialState

    } else {

        //this request will already admit the challenge cookie, so we can acceess that from headers
        //NOTE this uses the refresh endpoint
        const requestForPuzzle = await fetch(REFRESH_PUZZLE_STATE_ENDPOINT, {
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
        puzzleChallenge = await requestForPuzzle.json()
    }


    
    //the constructor sets up the entire puzzle - ie just initializing is enough
    //NOTE: Since this is a critical error, we will immediately check for retry by throwing and catching in the runChallenge.
    // This is unlike the remaining scripts which are nice to have for user experience, but not critical to functionality
    const clientSideSolver = new ClientCaptchaSolver(puzzleChallenge, CAPTCHA_COOKIE_NAME, ENABLE_DEBUG)
    const successfullyInitializedCaptcha = clientSideSolver.initCaptcha()
    if (!successfullyInitializedCaptcha.success) {
        throw new Error(`ErrFailedClientCaptchaInit: ${successfullyInitializedCaptcha.error}`)
    }

    //attaches client side rate limited request new puzzle button. (NOTE: We also rate limit server side)
    //we also provide a reference to the clientSideSolver defined above such that we can just update state 
    //on receiving new puzzle without needing to reattach all listeners
    const {maxNumberOfNewPuzzles, unitTimeInMs} = CLIENT_SIDE_RATE_LIMIT_WINDOW
    const rateLimitedPuzzleRefresher = new RefreshPuzzle(maxNumberOfNewPuzzles, unitTimeInMs, clientSideSolver, REFRESH_PUZZLE_STATE_ENDPOINT, ENABLE_DEBUG)
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
    
    const successfullyAttachedHostname = attachFooterHeaderHostname()
    if (!successfullyAttachedHostname.success) {
        if (successfullyAttachedHostname.error instanceof Error) {
            await reportError(successfullyAttachedHostname.error, HOSTNAME_FOOTER_HEADER_ERROR_ENDPOINT)
        }
    }
}

/**
reportError is limited for the time being to reporting the `errorType` that occured (inferred from the endpoint) and 
we rely on the user agent in order to recreate the issue. We send additional information about the stack trace through a cookie
 */
async function reportError(error:Error, endpoint:string):Promise<{allowedToRetry:boolean}> {

    try {
        
        const metadata = stringToBase64WithFallback(error.stack ?? error.message).slice(0, 4000) //to guarentee fitting into a cookie

        attachCookie("__banjax_error", metadata, {expirySecondsFromNow:10})

        //we will add additional info later
        const somethingWentWrong_requestPermissionToRetry = await fetch(endpoint, {
            method:"GET",
            headers: {"Content-Type": "application/json"},
            credentials:"include",
        })

        if (somethingWentWrong_requestPermissionToRetry.ok) {
            if (somethingWentWrong_requestPermissionToRetry.status === 204) {
                //we got permission to retry, otherwise we would be blocked server side
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

    if (ENABLE_DEBUG) {
        console.debug("RUNNING FALLBACK!")
    }
    
    /*
        classic POW challenge - either hardcoded or fetch for the existing deflect challenge? That way the user always has something...

        NOTE: 
            the fallback would need to remove the entire gameboard and then run its own challenge
    
    */
}

