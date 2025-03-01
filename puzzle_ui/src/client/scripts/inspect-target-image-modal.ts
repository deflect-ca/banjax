


/**
    attachThumbnailOverlay allows the user to click on the thumbnail itself to inspect the target image
*/
export default function attachThumbnailOverlay():{success:boolean, error:Error | null} {

    try {
        const thumbnail = document.getElementById("deflect-puzzle-thumbnail") as HTMLImageElement
        const modalImg = document.getElementById("thumbnail-modal-img") as HTMLImageElement
        const closeModal = document.querySelector(".thumbnail-modal-close") as Element
        const modal = document.getElementById("thumbnail-modal") as HTMLElement
        
        //if there is no thumbnail, we are not in good shape...
        if (!thumbnail) {
            const errorPayload = {modal_status:modal, modal_image_status:modalImg, close_modal_status:closeModal, thumbnail_status:thumbnail}
            return {success:false, error:new Error(`ErrFailedToAttachThumbnailInspectionAbility: ${JSON.stringify(errorPayload)}`)}
        }
       
        //otherwise if for whatever reason the thumbnail exists but we couldn't find one of these, remove the cursor: pointer style
        //so that users aren't confused by that thinking it can be clicked
        if (!modal || !modalImg || !closeModal) {
            thumbnail.style.cursor = "default"
            const errorPayload = {modal_status:modal, modal_image_status:modalImg, close_modal_status:closeModal, thumbnail_status:thumbnail}
            return {success:false, error:new Error(`ErrFailedToAttachThumbnailInspectionAbility: ${JSON.stringify(errorPayload)}`)}
        }
    
        //otherwise, we provide the ability to inspect the thumbnail more closely
    
        //opens the modal when you click the thumbnail
        thumbnail.addEventListener("click", () => {
            modal.style.display = "flex"
            modalImg.src = thumbnail.src
        })
        
        //closes the modal when you click on the x
        closeModal.addEventListener("click", () => {
            modal.style.display = "none"
        })
        
        //closes the moodal when you click anywhere on the page outside the image
        modal.addEventListener("click", (event) => {
            if (event.target === modal) {
                modal.style.display = "none"
            }
        })
        return {success:true, error:null}

    } catch(error) {
        return {success:false, error: new Error(`ErrCaughtException: ${error}`)}
    }
}


