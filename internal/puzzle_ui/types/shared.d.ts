
export {}

declare global {

    //click chain entry tile properties
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

    //data we are collecting for submission
    interface iClientSolutionSubmissionPayload {
        solution:string
        click_chain:iClickChainEntry[]
    }

    /* client side game board item satisfies the following */
    type TileImagePartitionValue = {
        base64_image: string
        tile_grid_id: string
    }

    //the interface that describes the shape the the CAPTCHA challenge payload we send to users
    interface PuzzleChallenge {
        gameBoard:(TileImagePartitionValue | null)[][]
        thumbnail_base64:string
        maxNumberOfMovesAllowed:number
        timeToSolve_ms:number
        collect_data:boolean
        click_chain:iClickChainEntry[]
    }

}

