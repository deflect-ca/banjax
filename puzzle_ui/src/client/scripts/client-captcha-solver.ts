import {generateHmacWithFallback} from "./utils/hmac-utils"
import {getCookieValue} from "./utils/cookie-utils"



export default class ClientCaptchaSolver {

    private puzzleChallenge: PuzzleChallenge

    private gameBoard:(TileImagePartitionValue | null)[][]
    
    private maxNumberOfMovesAllowed:number
    private clickCountTracker:number
    private clickChain:iClickChainEntry[]
    
    private timerId: number | null = null
    private startTime: number = 0
    private totalTimeAllowed: number = 0
    private challengeIssuedAtTime:string

    private puzzleContainerElement:HTMLElement
    private thumbnailElement: HTMLImageElement
    private submitSolutionButton: HTMLButtonElement
    private isSubmittingSolution:boolean

    private challengeDifficulty:difficulty

    private tileElements: HTMLElement[][] = []

    private gameplayDataCollectionEnabled:boolean

    private desiredEndpoint:string

    private VERIFY_SOLUTION_ENDPOINT:string
    private CAPTCHA_COOKIE_NAME: string

    private debug:boolean


    constructor(puzzleChallenge: PuzzleChallenge, VERIFY_SOLUTION_ENDPOINT:string, CAPTCHA_COOKIE_NAME:string, debug?:boolean) {
        
        this.debug = debug ?? false

        this.isSubmittingSolution = false

        this.VERIFY_SOLUTION_ENDPOINT = VERIFY_SOLUTION_ENDPOINT
        this.CAPTCHA_COOKIE_NAME = CAPTCHA_COOKIE_NAME

        this.gameBoard = puzzleChallenge.gameBoard

        this.maxNumberOfMovesAllowed = puzzleChallenge.maxNumberOfMovesAllowed
        this.clickCountTracker = 0
        
        this.totalTimeAllowed = puzzleChallenge.timeToSolve_ms

        this.puzzleChallenge = puzzleChallenge

        this.gameplayDataCollectionEnabled = puzzleChallenge.collect_data

        this.desiredEndpoint = puzzleChallenge.users_intended_endpoint

        this.challengeIssuedAtTime = puzzleChallenge.challenge_issued_date

        this.clickChain = puzzleChallenge.click_chain

        this.challengeDifficulty = puzzleChallenge.challenge_difficulty

        const thumbnailElement = document.getElementById("deflect-puzzle-thumbnail") as HTMLImageElement | null
        if (!thumbnailElement) {
            throw new Error(`ErrMissingRequirement: thumnailElement`)
        }
        this.thumbnailElement = thumbnailElement

        const puzzleContainerElement = document.getElementById('deflect-puzzle') as HTMLElement | null
        if (!puzzleContainerElement) {
            throw new Error(`ErrMissingRequirement: puzzleContainerElement`)
        }
        this.puzzleContainerElement = puzzleContainerElement

        const submitSolutionButton = document.getElementById("submit-deflect-captcha-solution") as HTMLButtonElement | null
        if (!submitSolutionButton) {
            throw new Error(`ErrMissingRequirement: submitSolutionButton`)
        }
        this.submitSolutionButton = submitSolutionButton


        //60ms debounce to prevent accidental clicks & double clicks etc
        this.moveTile = this.debounce(this.moveTile.bind(this), 60) 
        // this.puzzleContainerElement.addEventListener("mousedown", this.moveTile)
        //we attach it in such a way that if something is thrown we can bubble it back to the entry point to exploit the retry/fallback 
        this.puzzleContainerElement.addEventListener("mousedown", async (event) => {
            try {
                await this.moveTile(event)
            } catch (error) {
                console.error(`Error bubbled to top level: ${error}`);
                // throw new Error(`ErrCaughtException: moveTile event listener: ${error}`)
                window.dispatchEvent(new CustomEvent("captchaError", {detail: error}))
            }
        })



        //no debounce on submit since we have a function guard. When submission starts we immediately set it to true
        //and only set it back to false (allowing another submission) when the previous submission completes
        this.submitSolution = this.submitSolution.bind(this)
        this.submitSolutionButton.addEventListener("click", this.submitSolution)
    }


    initCaptcha():{success:boolean, error:Error | null} {

        try {
            
            //check for missing requirements
            if (this.thumbnailElement === null || !this.thumbnailElement) {
                return {success:false, error: new Error(`ErrMissingThumbnail: expected HTMLImageElement, got: type: ${typeof this.thumbnailElement} - ${this.thumbnailElement}`)}
            }

            if (this.puzzleContainerElement === null || !this.puzzleContainerElement) {
                return {success:false, error: new Error(`ErrMissingPuzzleContainer: expected HTMLElement, got: type: ${typeof this.puzzleContainerElement} - ${this.puzzleContainerElement}`)}
            }

            //at this point we know we have access to all elements needed to run challenge

            //figure out the dimensions of the puzzle user is meant to solve and apply the css grid styling required
            const rows = this.puzzleChallenge.gameBoard.length
            const columns = this.puzzleChallenge.gameBoard[0].length

            //set the thumbnail image
            //we cannot apply the grid directly to the <img> tags, so we wrap it to apply the grid to the wrapper instead
            this.thumbnailElement.src = `data:image/png;base64,${this.puzzleChallenge.thumbnail_base64}`
            const wrapper = document.getElementById("thumbnail-wrapper") as HTMLElement
            wrapper.style.gridTemplateColumns = `repeat(${columns}, 1fr)`
            wrapper.style.gridTemplateRows = `repeat(${rows}, 1fr)`
            
            //set up the puzzle grid, event listener and assign tiles their locations according to dimensions
            this.puzzleContainerElement.style.display = 'grid'
            this.puzzleContainerElement.style.gridTemplateColumns = `repeat(${columns}, 1fr)`
            this.puzzleContainerElement.style.gridTemplateRows = `repeat(${rows}, 1fr)`

            /*
                NOTE: 

                We add a row-col id to each tile we put in the DOM tree. These are FIXED. The tiles themselves NEVER move. It is the CONTENTS of
                the tile (ie the gameboard we superimpose onto the grid) which changes the contents within the 2D array. The TILES THEMSELVES DO NOT CHANGE.

                For example, suppose you have a 2x2 grid:

                    [[0,1],
                    [2,3]]

                then the gameboard will also be a 2x2 but comprised of objects

                    [[obj0,obj1],
                    [obj2,obj3]]

                when the user makes a move, the OBJECTS in the GAMEBOARD will move, BUT the TILEs of the GRID do NOT. 
                
                Ie, if we swap obj0 and obj1, we end up with an UNCHANGED 2x2 grid:

                    [[0,1],
                    [2,3]]

                but with a gameboard that has changed:

                    [[obj1,obj0],
                    [obj2,obj3]]

                This is really important to understand as it not only ensures that positional information is not encoded into the gameboard making it 
                resistant to cheating/tampering BUT it also means that if the user decides to request a different grid (by clicking the refresh puzzle button)
                we need only change the gameboard and not the grid. HOWEVER, it does mean we are RE-USING the SAME grid. Therefore, we MUST ALWAYS check to see 
                if the DOM tree already admits that TILE (by id: `${row}-${col}`) in the GRID before we draw the contents of the gameboard onto the grid.
                IF it exists, we must remove it:
                
                if the resetPuzzle() is called to get a new puzzle, we need to remove EXISTING tiles otherwise they stack up and 
                we end up with visual glitches. So we have to check to see if there exists a tile there BEFORE and pruining the DOM tree as we go
                about adding the tildDivs to the tree (drawing)

                This is why we always check to see if there exists a tile by that ID:
                                    
                    const tileAlreadyExists = document.getElementById(tileID)
                    if (tileAlreadyExists) {
                        tileAlreadyExists.remove()
                    }
                
                BEFORE adding the tile to the DOM tree. 

                WARNING:
                    If at any point you add something else to the tree, you MUST remember to check for its existence and remove it such that on puzzle
                    refresh, we do not end up with any surprises.
            */

            this.gameBoard.forEach((row, rowIndex) => {
                //track the tile row/cols - note these are fixed, we only move the content on top of the tiles, but the tiles themselves never move.
                this.tileElements[rowIndex] = []
                row.forEach((tile, colIndex) => {
                    const tileDiv = document.createElement('div')
                    const tileID = `${rowIndex}-${colIndex}`
                    const tileAlreadyExists = document.getElementById(tileID)
                    if (tileAlreadyExists) {
                        tileAlreadyExists.remove()
                    }
                    tileDiv.id = tileID
                    tileDiv.className = tile ? 'tile' : 'tile empty-tile'
                    tileDiv.style.backgroundImage = tile ? `url(data:image/png;base64,${tile.base64_image})` : 'none'
                    this.puzzleContainerElement.appendChild(tileDiv)
                    this.tileElements[rowIndex][colIndex] = tileDiv
                })
            })

            //set timer and start
            this.startTime = Date.now()
            this.startTimer(this.puzzleChallenge.timeToSolve_ms)

            this.logIfDebug("CAPTCHA successfully initialized!", "info")
            return {success:true, error:null}

        } catch (error) {
            return {success:false, error: new Error(`ErrCaughtException: ${error}`)}
        }
    }

    
    /**
     * resetPuzzle is used only when the refresh button is clicked because the user wants a new puzzle. The refresh
     * button is ratelimited both on the client side as well as the server side. If they want a new gameboard, we would
     * request the gameboard and provide the result to the resetPuzzle function. This does NOT affact any of the existing
     * eventListeners. Instead, it simply resets all of the states to their default configurations
     * with the new gameboard being drawn by the initCaptcha function
     * @param newPuzzleChallenge 
     * @returns 
     */
    resetPuzzle(newPuzzleChallenge:PuzzleChallenge):{success:boolean, error:Error | null} {
        this.gameBoard = newPuzzleChallenge.gameBoard

        this.maxNumberOfMovesAllowed = newPuzzleChallenge.maxNumberOfMovesAllowed
        this.clickCountTracker = 0
        
        this.totalTimeAllowed = newPuzzleChallenge.timeToSolve_ms //reset in csae they tried and time elapsed, so we reset the time for them
        this.challengeIssuedAtTime = newPuzzleChallenge.challenge_issued_date

        this.puzzleChallenge = newPuzzleChallenge

        this.gameplayDataCollectionEnabled = newPuzzleChallenge.collect_data

        this.isSubmittingSolution = false

        this.clickChain = newPuzzleChallenge.click_chain

        this.challengeDifficulty = newPuzzleChallenge.challenge_difficulty

        //verify endpoint does not change

        //desired endpoint will not change when users asks for a different puzzle only when they refresh
        // this.desiredEndpoint = newPuzzleChallenge.users_intended_endpoint

        return this.initCaptcha()
    }


    private async computeUserPuzzleSolution(): Promise<string> {
        const orderedHashes = this.gameBoard.flat().map(tile => tile !== null ? tile.tile_grid_id : "null_tile").join("") //otherwise .join defaults to "," breaking validation
        
        const challengeCookieValue: string | Error = getCookieValue(this.CAPTCHA_COOKIE_NAME)
        if (challengeCookieValue instanceof Error) {
            throw new Error("ErrMissingHmacKey: Expected non zero length string, got: undefined")
        }
        
        if (challengeCookieValue.trim() === "") {
            throw new Error("ErrMissingHmacKey: Expected non zero length string, got: ''")
        }

        return await generateHmacWithFallback(challengeCookieValue, orderedHashes)
    }


    /*
        gatherSolution collects all of the requirements to confirm the challenge was passed
        this includes:
            1) the solution hash of the gameboard to verify the board was solved
            2) the original hmac and the fields stored in constructor to verify that nothing was tampered with
                - in particular that the time at which we issued the challenge and when the solution was submitted 
                lines up with how much time they were allocated
            3) the click chain to confirm that they did not take more clicks than they were allowed
            4) data about users gameplay for ML
    */
    private async gatherSolution():Promise<iClientSolutionSubmissionPayload> {

        /*
            to verify the board is in the correct order, we use the 
            computeSolution to take the hash of the tile_hash_ids
            NOTE: the users challenge cookie string was already embedded in the
            hash_ids of each tile, so these are integrity checked by definition
        */
        const solutionHash = await this.computeUserPuzzleSolution()

        /*
            to verify that the time is valid (ie they did not take more time than they were alloted) 
            AND none of the other states have been tampered with (including their intended endpoint), 
            we also include the integrity checked payload 
            
            NOTE: we keep the puzzleChallenge.timeToSolve_ms because we need to check against the time 
            at which the challenge was issued to see if they went over all of which are part of the hmac 
            which uses a secret the client side does not know 
        */
        const integrity_check_confirmation_payload:iPayloadVerificationAndIntegrityCheck = {
            //hash of original data with secret
            hash:this.puzzleChallenge.integrity_check, 

            integrity_check_fields: {
                //the fields set in state at the time of submission
                users_intended_endpoint:this.desiredEndpoint,
                maxNumberOfMovesAllowed:this.maxNumberOfMovesAllowed, 
                
                timeToSolve_ms:this.puzzleChallenge.timeToSolve_ms,
                challenge_issued_date:this.challengeIssuedAtTime,

                collect_data:this.gameplayDataCollectionEnabled,
                challenge_difficulty:this.challengeDifficulty
            }
        }


        /*
            to verify that the number of clicks was valid we send the click chain 
            (note that the total number of clicks they are allowed is included in the HMAC calculation)
        */
        const click_chain:iClickVerificationAndIntegrityCheck = {
            n_clicks_made: this.clickCountTracker,
            click_chain:this.clickChain,
        }

        /*
            finally we need to gather the data that was collected about how the user played the 
            game (for ML predictions) but only IF we collected data in the first place
            again notice that the collect_data field was also included in the HMAC so we can 
            confirm it was not tampered with/disabled/enabled throwing off verification
        */
        let data_collection:iDataCollected = {}
        if (this.gameplayDataCollectionEnabled) {
            data_collection = {} //point it to the actual data we collected
        }

        const resultToVerify:iClientSolutionSubmissionPayload = {
            solution:solutionHash,
            game_board:this.gameBoard,
            captcha_properties: integrity_check_confirmation_payload,
            click_properties:click_chain,
            data_collected:data_collection,
        }

        return resultToVerify
    }



    private async submitSolution() {

        try {

            if (this.isSubmittingSolution) {
                return //already submitting
            }

            this.toggleSubmitButtonLoading(true)
    
            this.isSubmittingSolution = true
    
            const elapsedTime = Date.now() - this.startTime        
            if (this.timerId !== null) {
                clearTimeout(this.timerId)
            }
    
            const usersSolution:iClientSolutionSubmissionPayload = await this.gatherSolution()


            const solutionRequest = await fetch(this.VERIFY_SOLUTION_ENDPOINT, {
                method:"POST",
                headers: {"Content-Type":"application/json"},
                credentials:"include",
                body:JSON.stringify(usersSolution),
            })

            this.toggleSubmitButtonLoading(false)
    
            if (solutionRequest.ok) {
                if (solutionRequest.status === 202) {
                    const redirectUrl = solutionRequest.headers.get("Location")
                    this.submitSolutionButton.classList.add("success")
                    this.submitSolutionButton.textContent = "Verified!"
                    return this.handleRedirectOnSuccess(redirectUrl)
                }
            } else {
                if (solutionRequest.status === 404) {
                    //if there is no cookie and you're sending a solution restart
                    //or if the cookie on our end dne, restart
                    this.showUserMessage("We are not able to process this solution. Restarting...", "error", 5_000) 
                    setTimeout(()=> {
                        document.body.classList.add('fade-out')
                        setTimeout(() => window.location.reload(), 500)
                    }, 2500)
                    return
                }
            }

            const messageToUser_type:'success' | 'warning' | 'error' = "error"

            this.showUserMessage("Incorrect solution. Please try again", messageToUser_type, 5_000) //5 seconds is enough for them to read it was wrong
            setTimeout(()=>{
                this.hideUserMessage(messageToUser_type)
            }, 5000)
    
            this.logIfDebug("Invalid solution", "warn")
            //continue timer
            this.totalTimeAllowed -= elapsedTime //update the total time to what remains in aggregate
            if (this.totalTimeAllowed <= 0) {
                this.restartIfExceedMaxTimeAllowed()
            }
            this.startTime = Date.now()
            this.startTimer(this.totalTimeAllowed)


        } catch(error) {
            this.isSubmittingSolution = false
            this.toggleSubmitButtonLoading(false)
            //throwing will be caught by the entrypoint
            throw new Error(`ErrCaughtException: while ClientCaptchaSolver.submitSolution: ${error}`)

        } finally {
            this.isSubmittingSolution = false
            this.toggleSubmitButtonLoading(false)
        }
    }





    private handleRedirectOnSuccess(redirectUrl:string | null):void {
        if (redirectUrl) {
            // this.showUserMessage("You are human! Redirecting...", "success")
            this.logIfDebug(`Redirecting to: ${redirectUrl}`, "info")
            this.cleanup() //also resets this.isSubmittingSolution to false
            document.body.classList.add('fade-out')
            window.location.href = redirectUrl
            return
        } else {
            //throwing will be caught by the submitSolution (the calling function) which will then throw 
            //after wrapping it in its own error which will be caught by the entrypoint
            throw new Error(`ErrMissingRequirement: expected redirectUrl, got: ${redirectUrl}`)
        }
    }

    //moveTile is what is called when a click occurs. We only consider "valid" clicks (ie on a tile)
    //as part of the overall click count.
    private async moveTile(event: MouseEvent) {
        try {
            const tileElement = (event.target as HTMLElement).closest('.tile')
            if (tileElement === null) {
                this.logIfDebug(`clicked on gap or non tile`, "warn")
                return //user click on gap
            }
            const tileID = (event.target as HTMLDivElement).id
            const clickedTileRow = parseInt(tileID.split('-')[0], 10)
            const clickedTileCol = parseInt(tileID.split('-')[1], 10)

            this.logIfDebug(`clicked on row: ${clickedTileRow} col: ${clickedTileCol}`)

            if (0 <= clickedTileRow && clickedTileRow < this.gameBoard.length) {
                if (0 <= clickedTileCol && clickedTileCol < this.gameBoard[0].length) {
                    const payloadOfTileClickedOn: TileImagePartitionValue | null = this.gameBoard[clickedTileRow][clickedTileCol]
                    if (payloadOfTileClickedOn === null) {
                        //return early since the user just clicked on the empty tile. This is pointless
                        //as it doesnt do anything. We do not consider it a "valid click"
                        return 
                    }
                }
            }
    
            const move = this.clickedTileCanBeSwappedWithNullTile(clickedTileRow, clickedTileCol)
            if (!move.nullIsNeighbour) {
                //disregard the click
                return 
            }

            if (move.nullTile === null) {
                //this is a bug report it
                this.logIfDebug(`Expected null neighbour coords, got null`, "error")
                return
            }
    
            this.clickCountTracker++
            this.restartIfExceedsMaxClicksAllowed() //automatically restarts if too many clicks are made
            
            //at this point we know that the user clicked on a tile that is next to the null, therefore we can swap
            //their contents in state and invoke draw!
            const nullTileRow = move.nullTile[0]
            const nullTileCol = move.nullTile[1]
    
            const tileClickedByUser:iTileProperties = {row:clickedTileRow, col:clickedTileCol, id:this.gameBoard[clickedTileRow][clickedTileCol].tile_grid_id}
            const nullTileToSwapWith:iTileProperties = {row:nullTileRow, col:nullTileCol, id:"null_tile"}
            await this.newClickChainRecord(tileClickedByUser, nullTileToSwapWith)
    
            this.swapTileContent(clickedTileRow, clickedTileCol, nullTileRow, nullTileCol)
            this.draw(clickedTileRow, clickedTileCol, nullTileRow, nullTileCol)

        } catch(error) {
            throw new Error(`ErrCaughtException: ClientCaptchaSolver.moveTile: ${error}`)
        }
    }

    /**
     * newClickChainRecord takes the tile clicked and tile swapped info to keep track of it. We input the hash of the last entry in the chain
     * (starting from the genesis click chain entry for the very first user entry), and produce an hmac over that entry which we then push 
     * into the array
     * 
     * NOTE: We ONLY consider a "valid" click as a counter-affecting click. Ie, if the user clicks a tile that is not next to the null tile such that
     * nothing happens, no tiles are swapped this is NOT considered valid and will therefore NOT be considered as part of the click chain. ONLY if the counter is
     * actually incremented will we necessarily create a click chain record.
     * 
     * @param tileClicked - tile that was clicked
     * @param tileSwapped - tile it swapped with
     */
    private async newClickChainRecord(tileClicked:iTileProperties, tileSwapped:iTileProperties):Promise<void> {
        try {
            let clickChainEntry:iClickChainEntry = {
                time_stamp:new Date().toISOString(),
                tile_clicked: tileClicked,
                tile_swapped_with: tileSwapped,
                click_count:this.clickCountTracker,
                hash:this.clickChain[this.clickChain.length-1].hash
            }
    
            const challengeCookieValue: string | Error = getCookieValue(this.CAPTCHA_COOKIE_NAME)

            if (challengeCookieValue instanceof Error) {
                throw new Error("ErrMissingHmacKey: Expected non zero length string, got: undefined")
            }
            
            if (challengeCookieValue.trim() === "") {
                throw new Error("ErrMissingHmacKey: Expected non zero length string, got: ''")
            }

            const serializedPayload = JSON.stringify(clickChainEntry)
            // console.log("payload serialized as: ", serializedPayload)

            const entryHash = await generateHmacWithFallback(challengeCookieValue, serializedPayload) 
            // console.log("generated hash: ", entryHash)
            clickChainEntry.hash = entryHash
    
            this.clickChain.push(clickChainEntry)

        } catch(error) {
            throw new Error(`ErrCaughtException: ClientCaptchaSolver.newClickChainRecord: ${error}`)
        }
    }

    private clickedTileCanBeSwappedWithNullTile(row:number, col:number):{nullIsNeighbour:boolean, nullTile:[number, number] | null}  {
        if (0 <= row && row < this.gameBoard.length) {
            if (0 <= col && col < this.gameBoard[0].length) {
                const payloadOfTileClickedOn: TileImagePartitionValue | null = this.gameBoard[row][col]
                if (payloadOfTileClickedOn === null) {
                    return {nullIsNeighbour:false, nullTile:null}
                }
                return this.tileIsNeighboursWithNull(row, col)
            }
        }
        return {nullIsNeighbour:false, nullTile:null}
    }

    //tileIsNeighboursWithNull takes the row and col of the tile that has been clicked on
    //it then looks for the null tile using only valid moves. If the tile that was clicked on does indeed have the null
    //tile next to it via a valid move, then this tile can indeed by swapped with the null tile, so we return true. Otherwise,
    //the user just clicked on a tile that isn't next to the null tile and therefore cannot be moved
    private tileIsNeighboursWithNull(row:number, col:number):{nullIsNeighbour:boolean, nullTile:[number, number] | null} {
        const possible_x = [1, -1, 0, 0]
        const possible_y = [0, 0, 1, -1]
        for (let i=0; i<4;i++) {
            const neighbour_x = row + possible_x[i]
            const neighbour_y = col + possible_y[i]
            if (0 <= neighbour_x && neighbour_x < this.gameBoard.length) {
                if (0 <= neighbour_y && neighbour_y < this.gameBoard[0].length) {
                    if (this.gameBoard[neighbour_x][neighbour_y] === null) {
                        return {nullIsNeighbour:true, nullTile:[neighbour_x, neighbour_y]}
                    }
                }
            }
        }
        return {nullIsNeighbour:false, nullTile:null}
    }

    //swaps only the contents, the tile ID's do not change
    private swapTileContent(clickedTileRow:number, clickedTileCol:number, nullTileRow:number, nullTileCol:number) {
        this.gameBoard[nullTileRow][nullTileCol] = this.gameBoard[clickedTileRow][clickedTileCol]
        this.gameBoard[clickedTileRow][clickedTileCol] = null
    }

    //draw will only draw those tiles whose contents were swapped without changing anything else about the tile like its ID
    //ensuring that the ID's of the tiles remain fixed and our state is just superimposed ontop of it via the gameBoard content
    private draw(clickedTileRow:number, clickedTileCol:number, nullTileRow:number, nullTileCol:number) {

        const clickedTile = this.gameBoard[clickedTileRow][clickedTileCol]
        this.tileElements[clickedTileRow][clickedTileCol].className = clickedTile !== null ? 'tile' : 'tile empty-tile'
        this.tileElements[clickedTileRow][clickedTileCol].style.backgroundImage = clickedTile !== null ? `url(data:image/png;base64,${clickedTile.base64_image})` : 'none'

        const nullTile = this.gameBoard[nullTileRow][nullTileCol]
        this.tileElements[nullTileRow][nullTileCol].className = nullTile !== null ? 'tile' : 'tile empty-tile'
        this.tileElements[nullTileRow][nullTileCol].style.backgroundImage = nullTile !== null ? `url(data:image/png;base64,${nullTile.base64_image})` : 'none'
    }







    //extra helpers - not core to functionality
    // private getCookieValue(name: string="deflect_challenge4"):string {
    //     return document.cookie.split("; ").find((row) => row.startsWith(`${name}=`))?.split("=")[1] || ""
    // }

    


    //max time limit to solve the puzzle before we start over
    private startTimer(duration: number) {
        if (this.timerId !== null) {
            clearTimeout(this.timerId)
        }
        this.logIfDebug(`restarting timer to duration remaining: ${duration}`)
        this.timerId = window.setTimeout(() => this.restartIfExceedMaxTimeAllowed(), duration)
    }

    private cleanup() {
        this.logIfDebug("cleaning up!")
        this.puzzleContainerElement.removeEventListener("mousedown", this.moveTile)
        this.submitSolutionButton.removeEventListener("mousedown", this.submitSolution)
        this.isSubmittingSolution = false
    }


    private restartIfExceedMaxTimeAllowed() {        
        this.logIfDebug(`Times up, restarting...`)
        this.cleanup()
        document.body.classList.add('fade-out')
        setTimeout(() => window.location.reload(), 500)
        return
    }


    private restartIfExceedsMaxClicksAllowed() {
        if (this.clickCountTracker > this.maxNumberOfMovesAllowed) {
            this.logIfDebug(`Too many clicks! Restarting...`)
            this.cleanup()
            document.body.classList.add('fade-out')
            setTimeout(() => window.location.reload(), 500)
            return
        }
    }

    private debounce<T extends (...args: any[]) => Promise<void>>(func: T, delay: number): (...args: Parameters<T>) => Promise<void> {
        let timeoutId: ReturnType<typeof setTimeout>
        const context = this
    
        return async function (...args: Parameters<T>): Promise<void> {
            if (timeoutId) clearTimeout(timeoutId)
    
            return new Promise((resolve, reject) => {
                timeoutId = setTimeout(async () => {
                    try {
                        await func.apply(context, args)
                        resolve()
                    } catch (error) {
                        reject(error)
                    }
                }, delay)
            })
        }
    }

    //NOTE: all messages are display UNDER the grid
    private showUserMessage(message: string, type: 'success' | 'warning' | 'error' = 'error', duration = 5000) {
        
        const messageElement = document.querySelector(".display-message-to-user")
        if (messageElement) {
            messageElement.className = 'display-message-to-user'
            //just add either ".success", ".warning" or ".error" depending on what you're trying to say to the user
            messageElement.classList.add('show', type)
            messageElement.textContent = message
    
            //hide the message after the specified duration
            setTimeout(() => {
                this.hideUserMessage(type)
            }, duration)
        }
    }

    private hideUserMessage(type: 'success' | 'warning' | 'error' = 'error') {
        const messageElement = document.querySelector(".display-message-to-user")
        if (messageElement) {
            messageElement.classList.remove('show')
            messageElement.classList.remove(type)
        }
    }

    /**
     * toggleSubmitButtonLoading shows the loading spinner on top of the submit button
     * @param isLoading - true if you want to show the loading spinner, false if you want to stop it
     * @returns 
     */
    private toggleSubmitButtonLoading(isLoading: boolean) {

        if (!this.submitSolutionButton) {
            return
        }
    
        if (isLoading) {
            this.submitSolutionButton.classList.add('loading')

            this.submitSolutionButton.classList.add("disabled")
            this.submitSolutionButton.disabled = true
    
        } else {

            this.submitSolutionButton.classList.remove('loading')

            this.submitSolutionButton.classList.remove("disabled")
            this.submitSolutionButton.disabled = false
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