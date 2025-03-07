
export {}

declare global {

    //CLICK CHAIN REQUIREMENTS
    interface iTileProperties {
        id:string
        row:number
        col:number
    }
    
    //interface for the client chain type
    interface iClickChainEntry {
        time_stamp:string
        tile_clicked: iTileProperties
        tile_swapped_with: iTileProperties
    
        click_count:number
        hash:string
    }






    //INTEGRITY CHECK REQUIREMENTS
    interface iIntergrityCheckFields {
        //the users desired endpoint to ensure we redirect to the appropraite location on success
        users_intended_endpoint: string

        //tells us the maximum number of clicks we allowed (later compared to the click chain which admits its own integrity check)
        maxNumberOfMovesAllowed: number

        //time to solve and issuance date tells us whether or not it was completed in a reasonable amount of time
        timeToSolve_ms: number
        challenge_issued_date: string

        //whether or not to collect data tells us what to expect in the collected data object
        collect_data: boolean

        challenge_difficulty:difficulty
    }





    //interface for the solution that the client sends back to the server
    interface iClientSolutionSubmissionPayload {
        solution:string
        // game_board:(TileImagePartitionValue | null)[][]
        // captcha_properties: iPayloadVerificationAndIntegrityCheck
        // click_properties: iClickVerificationAndIntegrityCheck
        click_chain:iClickChainEntry[]
        // data_collected:iDataCollected
    }

    interface iPayloadVerificationAndIntegrityCheck {
        hash: string
        integrity_check_fields: iIntergrityCheckFields
    }

    interface iClickVerificationAndIntegrityCheck {
        n_clicks_made: number
        click_chain:iClickChainEntry[]
    }

    interface iDataCollected {

    }







    //GAME BOARD REQUIREMENTS:


    /**
     * Represents the available difficulty levels for the puzzle CAPTCHA challenge.
     * Difficulty is a function of a multiple inputs such as:
     * grid size, number of shuffles, time constraints, maximum number of moves allowed, and whether a countdown timer is shown (I was thinking like time pressure?).
     * 
     * Difficulty Levels:
     * 
     * - "easy": 
     *   - A beginner-friendly puzzle meant to be solved quickly.
     *   - 3x3 grid with very little shuffling.
     * 
     * - "medium": 
     *   - Slightly more challenging than "easy"
     *   - 3x3 grid with more shuffles and a reduced time limit.
     * 
     * - "medium_on_larger_map":
     *   - Similar to medium in terms of shuffles and time, but just with 5x5 board and center, 
     *   - it shouldn't be hard since it has a low number of shuffles
     * 
     * - "sisyphus": 
     *   - Designed to be long and tedious rather than outright difficult.
     *   - 4x4 grid with a high shuffle count & needs a lot moves to solve.
     * 
     * - "hard": 
     *   - A serious challenge
     *   - 4x4 grid with moderate shuffling complexity BUT we remove from the inside of the puzzle as opposed to the perimeter
     * 
     * - "very_hard": 
     *   - 5x5 grid with extensive shuffling and center-adjacent tiles removed for added complexity.
     *   - shorter time window increases difficulty.
     * 
     * - "painful": 
     *   - 7x7 grid with randomized tile removal.
     *   - high shuffle count combined with a tight time limit.
     * 
     * - "nightmare_fuel": 
     *   - 10x10 grid with [1000, 2000] shuffles
     *   - useful for bots and your enemies
     */
    type difficulty = "easy" | "medium" | "medium_on_larger_map" | "sisyphus" | "hard" | "very_hard" | "painful" | "nightmare_fuel"


    /**
     * TileImagePartitionKey is the key used when create the tileMap
     * TileImagePartitionValue is the value of the time map as well as the how we describe an item on the gameBoard gameBoard:(TileImagePartitionValue | null)[][]
     */
    type TileImagePartitionKey = number


    type TileImagePartitionValue = {
        base64_image: string
        tile_grid_id: string
    }
    
    type TileMap = Map<TileImagePartitionKey, TileImagePartitionValue>
    
    



    //the interface that describes the shape the the CAPTCHA challenge payload we send to users
    interface PuzzleChallenge {
        gameBoard:(TileImagePartitionValue | null)[][]
        thumbnail_base64:string
        maxNumberOfMovesAllowed:number
        timeToSolve_ms:number
        showCountdownTimer:boolean
        integrity_check:string
        collect_data:boolean
        users_intended_endpoint:string
        challenge_issued_date:string //ISO string
        click_chain:iClickChainEntry[]
        challenge_difficulty:difficulty
    }








    //LOCAL CHALLENGE SOLUTIONS WILL BE STORED IN MAP WITH KEY BEING USER CHALLENGE COOKIE STRING
    //AND VALUE BEING THE FOLLOWING INTERFACE (notes its the solution hash we expect to receive as well as 
    //the initial puzzle board but without the base64 strings to not waste memory needlessly as we keep these in memory)
    //they are both needed for the verification of the result & integrity checking respectively
    interface iLocalMapSolutionStoreValue {
        local_shuffled_gameboard:(TileGridIDOnly|null)[][]
        local_unshuffled_gameboard:(TileGridIDOnly|null)[][]
        local_preComputedSolution:string
    }

    type TileGridIDOnly = Omit<TileImagePartitionValue, 'base64_image'>
    type UserChallengeCookieValue = string

    /**This is the type that is used for the in memory map that stores the Captcha challenge solutions we need in order to validate the users submissions */
    type CaptchaSolutionCache = Map<UserChallengeCookieValue, iLocalMapSolutionStoreValue>


    //interface for the type that implements the local cache map
    interface iCAPTCHACache {
        /** 
         * stores our precomputed solution locally so that we can verify the users solution without needing to recreate the map or remember what image they used
         * 
         * NOTE: If you provide a purgeAfterMS number then this automatically sets the value to be deleted after a the milliseconds provided + 2 seconds (to account for latency)
         * otherwise it will not delete it automatically meaning you need to be sure to cleanup expired entries
        */
        set(userChallengeCookie:string, captchaPuzzleSolution:string, copyOf_unshuffled_Board:(TileGridIDOnly | null)[][], copyOf_shuffled_Board:(TileGridIDOnly | null)[][], purgeAfterMS?:number):void
        /*returns deep copy of value so you can modify it without worry of affecting the underlying type*/
        get(userChallengeCookie:string):iLocalMapSolutionStoreValue | undefined 
        /*behaves as you would expect an instance of Map().delete() to behave */
        delete(userChallengeCookie: string):boolean
    }
}

