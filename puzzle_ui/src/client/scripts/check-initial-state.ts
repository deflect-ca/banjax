
/**
    checkForInitialState allows us to check for the presence of dynamically injected initial state payload such that we can cut the extra round trip out 
    it will only request state if this is not here or if the user clicks on the refresh button
*/
export default function checkForInitialState():{success:boolean, error:Error | null, initialState:PuzzleChallenge | null} {

    try {
        const stateElement = document.getElementById("initial-game-state")

        if (!stateElement) {
            const errorPayload = {initial_state_status:stateElement}
            return {success:false, error:new Error(`ErrInitialStateNotFound: ${JSON.stringify(errorPayload)}`), initialState:null}
        }


        //to prevent parsing an empty state, we can check to see if trimming gets us to an empty string
        const rawState = stateElement.textContent?.trim()
        if (!rawState) {
            return {success: false, error: new Error("ErrInitialStateEmpty"), initialState: null}
        }

        //otherwise, get the initial state, parse it and provide it to the client side solver
        const initialState:PuzzleChallenge = JSON.parse(rawState)

        if (!initialState) {
            return {success:false, error:new Error("ErrFailedToParseInitialState"), initialState:null}
        }

        if (!isValidPuzzleChallenge(initialState)) {
            return {success:false, error:new Error(`ErrInvalidInitialPuzzleChallenge`), initialState:null}
        }

        return {success:true, error:null, initialState:initialState}

    } catch(error) {
        return {success: false, error: new Error(`ErrCaughtException: ${error.message}\nStack: ${error.stack}`), initialState: null}
    }
}

function isValidPuzzleChallenge(data: any): data is PuzzleChallenge {
    return (
        typeof data === "object" && data !== null &&
        
            //gameBoard must be a non-empty 2D array of (TileImagePartitionValue | null)
            Array.isArray(data.gameBoard) && data.gameBoard.length > 0 && data.gameBoard.every(row => Array.isArray(row) && row.length > 0) &&

            //thumbnail_base64 must be a non-empty string
            typeof data.thumbnail_base64 === "string" && data.thumbnail_base64.trim() !== "" &&

            //maxNumberOfMovesAllowed must be a positive integer
            typeof data.maxNumberOfMovesAllowed === "number" && data.maxNumberOfMovesAllowed > 0 &&

            //timeToSolve_ms must be a positive integer
            typeof data.timeToSolve_ms === "number" && data.timeToSolve_ms > 0 &&

            //click_chain must contain exactly ONE entry at the start
            Array.isArray(data.click_chain) && data.click_chain.length === 1
    )
}
