
/**
    attachInfoOverlay allows the user to click on the info icon in the submission section to pull up the instructions overlay and see an example gif
    with more detailed instructions on how the puzzle works
*/
export default function attachInfoOverlay():{success:boolean, error:Error | null} {

    try {
        //detailed-instructions-overlay
        const info_icon = document.getElementById("detailed-instructions-info-icon") as HTMLElement
        const closeModal = document.querySelector(".detailed-instructions-modal-close") as Element
        const overlayModal = document.getElementById("detailed-instructions-overlay") as HTMLElement

        if (!info_icon || !closeModal || !overlayModal) {
            const errorPayload = {info_icon_status:info_icon, close_modal_status:closeModal, overlay_modal_status:overlayModal}
            return {success:false, error:new Error(`ErrFailedToAttachInstructionsOverlay: ${JSON.stringify(errorPayload)}`)}
        }


        //if we have access to everything we need we can have the cursor be a pointer so users know the can click it
        info_icon.style.cursor = "pointer"

        // //opens the modal when you click the thumbnail
        info_icon.addEventListener("click", () => {
            overlayModal.style.display = "flex"
        })
        
        // //closes the modal when you click on the x
        closeModal.addEventListener("click", () => {
            overlayModal.style.display = "none"
        })
        
        // //closes the moodal when you click anywhere on the page outside the image
        overlayModal.addEventListener("click", (event) => {
            if (event.target === overlayModal) {
                overlayModal.style.display = "none"
            }
        })
        return {success:true, error:null}

    } catch(error) {
        return {success:false, error:new Error(`ErrCaughtException: ${error}`)}
    }
}