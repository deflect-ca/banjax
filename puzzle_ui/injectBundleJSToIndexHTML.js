import path from "path"
import fs from "fs"


export default function injectBundleJSToIndexHTML(writeToDestination = "dist/index.html") {
    const bundlePath = path.resolve('dist', 'client', 'scripts', 'bundle.js')
    const svgPath = path.resolve("src", 'deflect_logo.svg')
    const htmlPath = path.resolve('src', 'index.html')

    if (!fs.existsSync(bundlePath)) {
        throw new Error(`Error: ${bundlePath} not found.`)
    }

    if (!fs.existsSync(htmlPath)) {
        throw new Error(`Error: ${htmlPath} not found.`)
    }

    const bundleContent = fs.readFileSync(bundlePath, 'utf-8')
    const svgContent = fs.existsSync(svgPath) ? fs.readFileSync(svgPath, 'utf-8') : '<!-- Missing SVG -->'
    let htmlContent = fs.readFileSync(htmlPath, 'utf-8')

    //replace the "LOGO_PLACEHOLDER" that we wrote as a comment in the index.html in src with the inlined js bundle
    htmlContent = htmlContent.replace(
        /<!-- LOGO_PLACEHOLDER: This will be replaced with the inlined deflect_logo.svg during the build process -->/,
        svgContent
    )

    //replace the "BUNDLE_PLACEHOLDER" that we wrote as a comment in the index.html in src with the inlined js bundle
    htmlContent = htmlContent.replace(
        /<!-- BUNDLE_PLACEHOLDER: This will be replaced with the inlined bundle.js during the build process -->/,
        `<script>${bundleContent}</script>`
    )

    fs.writeFileSync(writeToDestination, htmlContent)
    console.log(`Successfully inlined bundle.js and replaced logo placeholder in ${writeToDestination}`)
}

