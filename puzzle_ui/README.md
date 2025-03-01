


This is the client side of the Deflect captcha puzzle



## Setting up the Deflect CAPTCHA UI

After cloning this repository, follow these steps to set up the UI for development and production use.

### Install Dependencies**
- The UI is built using Node.js and Rollup. 
- Ensure you have Node.js installed (v18 or later). 
- Then, install the required dependencies:

cd puzzle_ui
npm install


- Once thats done, create a .env.production and .env.development file. Populate them as follows:

# .env.production
MINIFY_CSS=true
SOURCE_MAP=false
OBFUSCATE=true

# .env.development
MINIFY_CSS=false
SOURCE_MAP=true
OBFUSCATE=false


- Finally, run the following commands:

npm run clean
npm run build


## If you want to make changes to the UI and automatically rebundle you can use: npm run dev

In package.json you'll find the following commands:

npm run dev
    - deletes client and rebuilds from scratch, bundling all dependencies, and watching for changes to client side code before rebundling (uses dev env variables)

npm run build
    - runs Rollup to bundle client-side code

npm run clean
    - clears the dist/ directory if you want a fresh build

npm run watch
    - watches for changes in client code & automatically rebundles

npm run prod
    - deletes client and rebuilds from scratch, bundling all dependencies (uses prod env variables)





Workflow for development:

    npm run dev





Workflow for production

    npm run prod

    - The frontend bundle (bundle.js) includes all dependencies except the Deflect logo, which is served separately but can be integrated along with the initial challenge request so that everything is served all at once
    