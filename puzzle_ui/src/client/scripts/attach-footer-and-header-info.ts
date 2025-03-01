
/**
    attachFooterHeaderHostname allows us to dynamically inject the footer and header hostname in to match the hostname the requester was accessing
*/
export default function attachFooterHeaderHostname(users_intended_endpoint:string):{success:boolean, error:Error | null} {

    try {

        const footerSiteName = document.querySelector(".website-title-footer")
        const headerSiteName = document.querySelector(".website-title")

        if (!footerSiteName && !headerSiteName) {
            const errorPayload = {footer_status:footerSiteName, header_status:headerSiteName}
            return {success:false, error:new Error(`ErrFailedToAttachHostname: ${JSON.stringify(errorPayload)}`)}
        }

        //otherwise, attach it where possible 

        if (footerSiteName) {
            const desired_endpoint_url = new URL(users_intended_endpoint)
            footerSiteName.textContent = desired_endpoint_url.hostname
        }
    
        if (headerSiteName) {
            const desired_endpoint_url = new URL(users_intended_endpoint)
            headerSiteName.textContent = desired_endpoint_url.hostname
        }
        

        return {success:true, error:null}

    } catch(error) {
        //because its most likely that you didnt provide something that could be expressed as url (ie TypeError: Failed to construct 'URL': Invalid URL)
        return {success:false, error:new Error(`ErrCaughtException: while attachFooterHeaderHostname(users_intended_endpoint:${users_intended_endpoint}) ${error}`)}
    }
}