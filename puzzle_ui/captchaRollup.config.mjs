import obfuscatorPlugin from 'rollup-plugin-obfuscator'
import typescript from '@rollup/plugin-typescript'
import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import postcss from 'rollup-plugin-postcss'
import terser from '@rollup/plugin-terser'
import babel from '@rollup/plugin-babel'
import dotenv from 'dotenv'







//load the appropriate .env file based on NODE_ENV
dotenv.config({path: process.env.NODE_ENV === 'production' ? '.env.production' : '.env.development'})

/*
    In the index.html, we specify: <script src="./scripts/bundle.js" type="module"></script>
    This will cause user browser to request the rollup bundle which specifies as its entrypoint the
    entrypoint-deflect-captcha.ts which is the entrypoint to the captcha.

    This allows us to use bundled dependencies for hmac operations to support legacy browsers which need
    not necessarily admit the subtle.crypto api that modern browsers do. Therefore, it is important
    to ALWAYS use the generateHmacWithFallback() in any of the client-side code.

    For server-side code, do whatever you want
*/
export default {
    input: 'src/client/scripts/entrypoint-deflect-captcha.ts', //entry point
    output: {
        file: 'dist/client/scripts/bundle.js',
        format: 'iife', //or 'esm' if using modules in HTML but iife is important for us because we need to support legacy browseres
        name: 'DeflectCaptcha', //this is the name of the global variable for access if needed
        sourcemap: process.env.SOURCE_MAP === 'true',
    },
    plugins: [

        resolve({
            extensions: ['.js', '.ts']
        }),          
        commonjs(), 
        typescript(), 
        postcss({
            // NOTE: You could extract as it would extract css is a seperate file - we dont want that as we want 1 bundle to serve with everything it needs to run so we use inject to inline everything into the bundle
            //extract: false, 

            inject: true,  //inlines the css directly into the js bundle
            minimize: process.env.MINIFY_CSS === 'true',
            sourceMap: process.env.SOURCE_MAP === 'true'
        }),
        process.env.OBFUSCATE === "true" &&
            obfuscatorPlugin({
                compact: true,
                controlFlowFlattening: true,
                deadCodeInjection: true,
                debugProtection: true,
                stringArray: true,
                rotateStringArray: true,
                stringArrayThreshold: 0.75
            }),
        //for legacy support we add babel for es5 transpilation
        babel({
            babelHelpers: 'bundled',
            presets: [
                ['@babel/preset-env', {
                    targets: "> 0.25%, not dead, IE 11",
                    useBuiltIns: 'entry', //forces Babel to use explicit polyfill imports instead of dynamically injecting them where it sees fit.
                    corejs: 3             //specifies the version of core-js (v3)
                }]
            ]
        }),
        terser()
    ].filter(Boolean), //to remove false or undefined that results when process.env.OBFUSCASE !== "true"
}