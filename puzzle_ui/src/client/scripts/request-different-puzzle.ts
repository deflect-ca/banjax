import ClientCaptchaSolver from "./client-captcha-solver"

/**
    RefreshPuzzle allows the user to request a new puzzle. 
    This will be rate limited so they cannot keep looking for a new puzzle arbitrarily
    rate limiting will be applied to both client side and server side

    example: if you want to allow 3 puzzle requests per minute: new RefreshPuzzle(3, 60000)
*/
export default class RefreshPuzzle {
    
    private puzzleCount: number = 0
    private maxNumberOfNewPuzzles: number
    private unitTime: number
    private resetTimeout: ReturnType<typeof setTimeout> | null = null
    
    private cooldownMessageElement: Element | null = null
    private requestPuzzleButton:HTMLElement | null = null
    
    clientSideSolver: ClientCaptchaSolver

    NEW_PUZZLE_ENDPOINT:string
    
    private debug:boolean

    constructor(maxNumberOfNewPuzzles: number, unitTimeInMs: number, clientSideSolver: ClientCaptchaSolver, NEW_PUZZLE_ENDPOINT:string, debug?:boolean) {
        this.maxNumberOfNewPuzzles = maxNumberOfNewPuzzles
        this.unitTime = unitTimeInMs
        this.clientSideSolver = clientSideSolver
        this.NEW_PUZZLE_ENDPOINT = NEW_PUZZLE_ENDPOINT
        this.debug = debug ?? false
    }

    initPuzzleRefresh():{success:boolean, error:Error | null} {

        this.logIfDebug("Refreshing puzzle", "info")

        try {
            const cooldownMessageElement = document.querySelector(".display-message-to-user")
            const requestPuzzleButton = document.getElementById("request-different-puzzle-icon")
            
            if (!cooldownMessageElement) {
                //not having access to cooldown is non critical to functionality as it just means we can't display
                //the message that they are being rate limited but the underlying request functionality will continue to work
                //as long as requestPuzzleButton is found
                this.logIfDebug(`cooldown message element not found: ${cooldownMessageElement}`, "warn")
            }

            if (!requestPuzzleButton) {
                const err = {cool_down_status: cooldownMessageElement, new_puzzle_button_status: requestPuzzleButton}
                return {success:false, error:new Error(`ErrMissingPuzzleRefresh: ${JSON.stringify(err)}`)}
            }

            if (cooldownMessageElement) {
                this.cooldownMessageElement = cooldownMessageElement
            }
            
            if (requestPuzzleButton !== null) {
                // requestPuzzleButton.addEventListener("click", this.debounce(this.requestNewPuzzle.bind(this), 150))
                requestPuzzleButton.removeEventListener("click", this.requestNewPuzzle)
                requestPuzzleButton.addEventListener("click", this.debounce(this.requestNewPuzzle.bind(this), 150))
                //if we have access to everything we need we can have the cursor be a pointer so users know the can click it
                requestPuzzleButton.classList.add("enabled")
                requestPuzzleButton.style.opacity = "1"
                this.requestPuzzleButton = requestPuzzleButton
            }

            return {success:true, error:null}

        } catch(error) {
            return {success:false, error:new Error(`ErrCaughtException: while initPuzzleRefresh: ${error}`)}
        }
    }

    private async requestNewPuzzle() {
        
        const messageToUser_type:'success' | 'warning' | 'error' = "warning"
        if (this.puzzleCount >= this.maxNumberOfNewPuzzles) {
            this.showCooldownMessage(`Please wait ${this.unitTime / 1000} seconds before requesting a new puzzle.`, messageToUser_type, 60_000) //60 seconds
            if (this.requestPuzzleButton) {
                this.requestPuzzleButton.classList.add("not-currently-clickable")
                this.requestPuzzleButton.classList.remove("enabled")
                this.requestPuzzleButton.style.opacity = "0.3"
            }
            return
        }

        this.puzzleCount++
        this.logIfDebug(`New puzzle requested. Count: ${this.puzzleCount}/${this.maxNumberOfNewPuzzles}`)

        
        const newPuzzleResult = await this.fetchNewPuzzle()
        if (!newPuzzleResult.success) {
            //if the fetchNewPuzzle fails, throw, this will be caught by the entrypoint script which will be able to relay the error back to the server
            //to ask what to do (try again from the beginning or use hardcoded fallback puzzle)
            throw new Error(`ErrFailedRequestNewPuzzle: ${newPuzzleResult.error}`)
        }

        //at this point we successfully got the puzzle and reset it, so we can proceed with removing the cooldown message

        //reset the counter after the unitTime window
        if (!this.resetTimeout) {
            this.resetTimeout = setTimeout(() => {
                this.puzzleCount = 0
                this.hideCooldownMessage(messageToUser_type)
                this.resetTimeout = null
            }, this.unitTime)
        }
    }

    private async fetchNewPuzzle():Promise<{success:boolean, error:Error | null}> {
        try {
            
            this.logIfDebug("Fetching new puzzle from server", "info")

            if (this.requestPuzzleButton) {
                this.requestPuzzleButton.classList.add("rotating-while-waiting-on-new-puzzle-request-response")
            }

            const thumbnailWrapper = document.getElementById("thumbnail-wrapper") as HTMLElement | null
            if (thumbnailWrapper !== null) {
                //attach the scroll wheel class overlay while loading
                this.addLoadingOverlay(thumbnailWrapper)
            }
            const puzzleContainerElement = document.getElementById('deflect-puzzle') as HTMLElement | null
            if (puzzleContainerElement) {
                //attack the scroll wheel class overlay while loading
                this.addLoadingOverlay(puzzleContainerElement)
            }

            const requestForPuzzle = await fetch(this.NEW_PUZZLE_ENDPOINT, {
                method:"GET",
                credentials:"include"
            })

            if (!requestForPuzzle.ok) {
                return {success:false, error: new Error("ErrNoResponse: Failed to get response")}
            }

            if (requestForPuzzle.status !== 200) {
                return {success:false, error: new Error(`ErrUnexpectedStatus: Expected status 200, got: ${requestForPuzzle.status}}`)}
            }

            //at this point we received the new challenge payload, so invoking clientSideSOlver.resetPuzzle will re-use the same event listeners
            //but reset all of the puzzle requirements like the board etc
            
            const newPuzzleChallenge:PuzzleChallenge = await requestForPuzzle.json()
            const resultOfReset = this.clientSideSolver.resetPuzzle(newPuzzleChallenge)
            this.logIfDebug("New puzzle loaded successfully!", "info")

            if (thumbnailWrapper !== null) {
                //remove the scroll wheel class overlay while loading
                this.removeLoadingOverlay(thumbnailWrapper)
            }

            if (puzzleContainerElement) {
                //remove the scroll wheel class overlay while loading
                this.removeLoadingOverlay(puzzleContainerElement)
            }


            return resultOfReset

        } catch(error) {

            this.logIfDebug(`caught exception while attempting to get new puzzle due to error: ${error}`, "error")
            return {success:false, error:new Error(`ErrCaughtException: while RefreshPuzzle.fetchNewPuzzle: ${error} `)}

        } finally {
            if (this.requestPuzzleButton) {
                this.requestPuzzleButton.classList.remove("rotating-while-waiting-on-new-puzzle-request-response")
            }
        }
    }

    

    private debounce<T extends (...args: any[]) => void>(func: T, delay: number): (...args: Parameters<T>) => void {
        let timeoutId: ReturnType<typeof setTimeout>
        return (...args: Parameters<T>) => {
            if (timeoutId) {
                clearTimeout(timeoutId)
            }
            timeoutId = setTimeout(() => func(...args), delay)
        }
    }




    //NOTE: all messages are display UNDER the grid
    private showCooldownMessage(message: string, type: 'success' | 'warning' | 'error' = 'error', duration = 5000) {
        
        if (this.cooldownMessageElement) {
            // this.cooldownMessageElement.className = 'display-message-to-user'
            //just add either ".success", ".warning" or ".error" depending on what you're trying to say to the user
            this.cooldownMessageElement.classList.add('show', type)
            this.cooldownMessageElement.textContent = message
    
            //hide the message after the specified duration
            setTimeout(() => {
                this.hideCooldownMessage(type)
            }, duration)
        }
    }

    private hideCooldownMessage(type: 'success' | 'warning' | 'error' = 'error') {
        if (this.cooldownMessageElement) {
            this.cooldownMessageElement.classList.remove('show')
            this.cooldownMessageElement.classList.remove(type)
        }

        if (this.requestPuzzleButton) {
            this.requestPuzzleButton.classList.remove("not-currently-clickable")
            // this.requestPuzzleButton.style.cursor = "pointer"
            this.requestPuzzleButton.classList.add("enabled")
            this.requestPuzzleButton.style.opacity = "1"
        }
    }


    private addLoadingOverlay(element: HTMLElement) {
        element.classList.add("position-relative")
        const overlay = document.createElement("div")
        overlay.classList.add("loading-overlay")
        overlay.innerHTML = `<div class="loading-spinner"></div>`
        overlay.id = `${element.id}-loading-overlay`
        element.appendChild(overlay)
    }
    

    private removeLoadingOverlay(element: HTMLElement) {
        const overlay = document.getElementById(`${element.id}-loading-overlay`)
        if (overlay) {
            overlay.remove()
        }
    }


    private logIfDebug(msg:string, type:"debug"| "info" | "warn"|"error" = "debug") {
        if (this.debug) {
            switch(type) {
                case "debug":
                    console.log(msg)
                    break
                case "info":
                    console.info(msg)
                    break
                case "warn":
                    console.warn(msg)
                    break
                case "error":
                    console.error(msg)
                    break
                default:
                    console.log(msg)
            }
        }
    }
}