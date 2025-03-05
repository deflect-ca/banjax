## Deflect CAPTCHA puzzle Client Side

## Table of Contents

<details>
<summary> Introduction - <em>Overview of the type of puzzle and our goals.</em></summary>

- [Introduction](#introduction)
  - [State-Space Search Problem](#state-space-search-problem)
    - [Why State-Space Search?](#objective)
      - [The High Level Objective](#the-high-level-objective)
      - [What We Have Achieved & What Comes Next](#what-we-have-achieved--what-comes-next)
</details>

<details>
<summary> User Interaction and Client Side System Design - <em>How users engage with the puzzle & High-level design.</em></summary>

- [How the client side works](#how-the-client-side-works)
- [User Interaction Flow](#how-the-client-side-works)
  - [Receiving a Challenge](#receiving-a-challenge)
  - [Solving & Submitting](#solving-and-submitting)
  - [Accesssibility Considerations](#accessability-considerations)
</details>


<details>
<summary> Security - <em>How we prevent tampering & automated solvers.</em></summary>

- [Security Principles](#security-principles)
  - [Preventing Automated Solvers](#preventing-automated-solvers)
  - [Rate Limiting](#rate-limiting)
    - [Client Side Rate Limiting](#client-side-rate-limiting)
    - [Server Side Rate Limiting](#server-side-rate-limiting)
  - [Click-Chain Validation](#client-side-integrity-checking)
  - [Client-Side Integrity Checks](#client-side-integrity-checking)
  - [Trust Boundaries: Client vs. Server](#trust-boundaries)
</details>

   
<details open>
<summary> Developer Guide - <em>Understanding the filesystem & Instructions for setting up, deploying, and contributing to the project.</em></summary>

- [Developer Guide](#developer-guide)
  - [Languages & Tools](#languages--tools)
    - [Languages](#languages)
    - [Tools](#tools)
  - [Project Structure](#project-structure)
  - [Deployment Guide](#deployment-guide)
    - [Serving In Production](#serving-in-production)
  - [Contributing](#contributing)
    - [Setting up the development environment](#setting-up-the-development-environment)
        - [Package.json Commands](#package.json-commands)
        - [Typical Development Workflow](#typical-development-workflow)
        - [Typical Production Workflow](#typical-production-workflow)
</details>


---


# Introduction

## State-Space Search Problem

- A state-space search problem is a computer science task that involves finding a solution by navigating through a set of states

#### Components of a state-space search problem 

- States: A set of possible configurations of a problem
- Start state: The initial configuration of the problem
- Goal state: The desired configuration of the problem
- Actions: The actions that can be taken to move from one state to another
- Goal test: A specification of what constitutes a solution

- Examples of state-space search:

    - Solving puzzles like the 8-puzzle or Rubik's cube
    - A robot navigating through a maze

[For more on State Space Search problems see wiki/State_space_search](https://en.wikipedia.org/wiki/State_space_search)

### Why State-Space Search?

- This puzzle was designed as an experiment—it is intentionally built as a state-space search problem.
- The motivation behind this is that bots, LLMs, and automated solvers are not particularly strong at this class of problem, but humans also struggle with it—just in different ways.
- The hypothesis is that humans and bots will approach the puzzle in fundamentally different ways, and by analyzing how they play, we may uncover meaningful differences.

#### The High Level Objective

- This is not a reverse Turing test—the objective isn’t just to prove whether someone is a bot or not. Instead, the goal is to study how people play compared to automated systems.
- In the future, we may develop an API for major LLMs to play, allowing us to collect gameplay data and run comparative analyses.
- The ultimate aim is to train an in-house model that uses gameplay behavior as a distinguishing factor, rather than relying solely on conventional CAPTCHA mechanisms.

#### What We Have Achieved & What Comes Next

- The puzzle itself is complete: we can cryptographically verify whether a submitted solution is correct or incorrect, with each challenge being unique to the user.
- However, correctness alone is only half the solution—the real challenge is distinguishing how the game is played and whether that behavior indicates a human or a bot.
- In theory, this could mean that getting the exact right solution may not even be necessary. If we weight behavioral analysis more heavily than correctness, we could allow slightly incorrect solutions as long as the player's interactions strongly indicate human behavior.
- The really neat part of the project will be in collecting and analyzing gameplay data, identifying patterns that separate human problem-solving strategies from automated solvers.

---



# User Interaction and Client Side System Design

## How the Client Side Works

- The Deflect CAPTCHA client operates as a self-contained, pre-bundled system delivered to the user's browser in a single request. This ensures a seamless experience without requiring additional external dependencies or network requests beyond the initial page load.

## User Interaction Flow

### Receiving a Challenge

1) The client receives an `index.html` file containing:
    - Prebundled CSS, JavaScript, dependencies, and polyfills.  
    - The initial game state, injected at the time of delivery.
    - If no initial state is found, the puzzle phones home to request a challenge.
2) The puzzle immediately starts, prompting the user to solve it.
3) The challenge issued to the user has the following structure:

    ```
        type CAPTCHAChallenge struct {
            GameBoard             [][]*Tile         `json:"gameBoard"`
            ThumbnailBase64       string            `json:"thumbnail_base64"`
            MaxAllowedMoves       int               `json:"maxNumberOfMovesAllowed"`
            TimeToSolveMS         int               `json:"timeToSolve_ms"`
            ShowCountdownTimer    bool              `json:"showCountdownTimer"`
            IntegrityCheckHash    string            `json:"integrity_check"`
            CollectDataEnabled    bool              `json:"collect_data"`
            UserDesiredEndpoint   string            `json:"users_intended_endpoint"`
            ChallengeIssuedAtDate string            `json:"challenge_issued_date"`
            ClickChain            []ClickChainEntry `json:"click_chain"`
            ChallengeDifficulty   string            `json:"challenge_difficulty"`
        }
    ```

### Solving & Submitting

1) The puzzle consists of an nxn grid, where one tile is missing.
2) The user can only move tiles adjacent to the missing space by clicking on them. Clicking a tile swaps its position with the missing tile.
3) The objective is to rearrange the tiles until they recreate the original reference image.

4) Each tile contains:
    ```
    type Tile struct {
        Base64Image string `json:"base64_image"`
        TileGridID  string `json:"tile_grid_id"`
    }
    ```
- Where:
    - Base64Image: Encoded PNG of the puzzle segment.
    - TileGridID: A hashed identifier derived from:
        - Hmac(The tile's base64 image + The user's challenge cookie + A server-side secret)
    - The TileGridID ensures that each puzzle instance is unique and prevents replay attacks.

- When the user clicks Solve, the system:
    1) Extracts the TileGridID of each tile in order.
    2) Concatenates them into a single string.
    3) Computes an HMAC hash of the string using the challenge cookie as a key.
    4) Submits this computed hash as the solution.

### Accessibility Considerations
    
- These are as of yet not addressed and remain and important TODO
- Perhaps an auditory challenge for the visually impaired?


---



# Security

## Security Principles

- The following outlines the client-side security mechanisms implemented in Deflect CAPTCHA to prevent spam, mitigate automated solvers, and ensure the integrity of submitted solutions. 

### Preventing Automated Solvers

- State-Space Search Problem

    - Deflect CAPTCHA is designed as a state-space search problem—a well-studied class of problems in computer science where solving involves transitioning through valid states.

- As mentioned in the introduction:

    - Bots and LLMs struggle with this type of problem due to combinatorial complexity.
    - Humans also find it difficult, but they approach it differently, which allows us to analyze behavioral patterns.
    - We can study interactions over time to differentiate bots from real users based on how they play rather than solely correctness.

- Configurable Difficulty to Deter Bots:
    - Configurations dynamically adjust puzzle difficulty based on detected behavior. 
        - If a bot is suspected, we have the capability of making the puzzle exponentially harder:

            ```
            profiles:
                easy:
                    nPartitions: 9  # 3x3 grid
                    nShuffles: [5, 8]
                    maxNumberOfMovesAllowed: 160
                    timeToSolve_ms: 1_200_000  # 20 minutes

                medium:
                    nPartitions: 16  # 4x4 grid
                    nShuffles: [5, 8]
                    maxNumberOfMovesAllowed: 200
                    timeToSolve_ms: 900_000  # 15 minutes

                painful:
                    nPartitions: 49  # 7x7 grid
                    nShuffles: [30, 50]
                    maxNumberOfMovesAllowed: 300
                    timeToSolve_ms: 420_000

                nightmare_fuel:
                    nPartitions: 100  # 10x10 grid
                    nShuffles: [1000, 2000]
                    maxNumberOfMovesAllowed: 6000
                    timeToSolve_ms: 360_000
            ```

- How This Prevents Bots:

    1) Exponential increase in complexity makes brute-force infeasible.
    2) Maximum move limits prevent infinite search-based solvers.
    3) Hard time limits ensure bots cannot iterate endlessly.
    4) Adaptability: If we detect bot-like behavior, we increase difficulty dynamically.

### Rate Limiting

#### Client-Side Rate Limiting

- Client-side protections prevent spamming by users pressing submit repeatedly (especially useful under heavy load). This is enforced via delays and UI locking mechanisms to slow down consecutive attempts

#### Server-Side Rate Limiting

- Server-side rate limiting is designed to:

    1) Throttle requests to prevent brute-force guessing.
    2) Enforce a max of 4 solution submissions per unit time.
    3) Ensure users run out of time before brute-forcing a solution.

### Click-Chain Validation

- Each puzzle challenge is unique per user and validated via a cryptographic click-chain (similar to how a block chain works)

    - A unique puzzle board is generated for each user, where each tile has a hashed ID derived from the tile’s image and the user’s challenge cookie.
    - A Genesis Block (initial entry) is created, linked to the user’s challenge cookie and an internal secret.
    - Each valid move is appended to the click-chain, referencing the previous move's hash, ensuring an immutable sequence.
    - Solution validation: The final board state is verified against the expected target solution.

- Security Benefits:

    - Ensures puzzle integrity – every move is logged and cryptographically linked.
    - Prevents tampering – since the chain is HMAC-signed, users cannot forge solutions.
    - Stops replay attacks – the secret key ensures that click-chains are tied to individual challenges.


### Client-Side Integrity Checks

- To prevent tampering or bypassing, the server side will perform integrity checks:

    1) Ensuring the click-chain hash is valid.
    2) Confirming that move sequences are logically possible.
    3) Detecting unnatural solving patterns indicative of automation.

For more on how this works, see [Server-Side Documentation](../internal/puzzle-util/README.md).


### Trust Boundaries: Client vs. Server

- The client only knows its cookie and board state.
- The server holds the entropy for challenge verification (a secret only we know concatenated with the users challenge cookie)
    - Even with the entire click-chain, users cannot forge a solution because the secret key remains unknown to them.

---


# Developer Guide

## Languages & Tools

### Languages

- The Client-Side Puzzle UI is written in TypeScript (v4.0+ recommended).
- No frameworks (e.g., React, Vue) are used—event listeners are attached directly to ensure maximum compatibility with legacy browsers as these frameworks depend a lot on ES6+ features which break older environments even when using transpilation.

### Tools

#### Bundler: Rollup
    
- Rollup is used to bundle, optimize, and minify the client-side JavaScript, CSS, and dependencies into a single deliverable.
    
##### What is Being included by Rollup

- The following assets are bundled and optimized:

    1) JavaScript - All client-side logic and dependencies (when using production environment variables the JS will be obfuscated)
    2) CSS - Embedded directly into `index.html`.
    3) Polyfills - Ensures compatibility with older browsers. (The required polyfills are imported in the entrypoint-deflect-captcha.ts file such that rollup knows what is needed when bundling)
    4) utility functions required for compatibility with legacy environments.

###### How Rollup Works in This Project
    
- Entry Point: entrypoint-deflect-captcha.ts 
    - Specified in the `input` field of the rollup

- Bundling Process:
    - The script is compiled and minified.
    - Polyfills are included for older browsers.
    - The final bundle is injected into index.html.

- Rollup Configuration Breakdown:

    - JavaScript and TypeScript:

        - The entrypoint-deflect-captcha.ts script serves as the entry point.
        - Babel is used to transpile the code, ensuring compatibility with older browsers.
        - TypeScript is processed using @rollup/plugin-typescript.

    - CSS Handling:

        - By default, CSS is embedded directly into index.html.
        - If you want to bundle CSS inside bundle.js, uncomment the PostCSS plugin in rollup.config.js.

    - Legacy Browser Support:

        - Babel targets Internet Explorer 11+.
        - Ensures compatibility by using core-js for polyfills.
    
    - Security & Performance Enhancements:

        - The bundle is obfuscated in production (rollup-plugin-obfuscator).
        - Minification is done using terser.

##### Compatibility with Legacy Browsers

- One of the **most important requirements** for this project is ensuring that it runs on **legacy browsers**. 
- Some older browsers do not support modern cryptographic APIs and other tooling we take for granted today, so we must fallback to pre-bundled dependencies when necessary.

- These tools are all included in the `src/client/scripts/utils` directory and are imported by the event listener attachment functions that need them
    - Since these are being imported into the entrypoint (via these event listener attachment functions), rollup knows to include them in the `bundle.js`

    Example: Modern browsers support crypto.subtle, but legacy browsers do not. For this reason we have a util function:

    ```
    import {HmacSHA256, enc} from 'crypto-js'

    export async function generateHmacWithFallback(key: string, message: string): Promise<string> {
        if (window.crypto && window.crypto.subtle) {
            const encKey = new TextEncoder().encode(key)
            const encMessage = new TextEncoder().encode(message)
            const cryptoKey = await crypto.subtle.importKey('raw', encKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
            const signature = await crypto.subtle.sign('HMAC', cryptoKey, encMessage)
            return Array.from(new Uint8Array(signature)).map((b) => b.toString(16).padStart(2, '0')).join('')
        } else {
            return HmacSHA256(message, key).toString(enc.Hex)
        }
    }
    ```

    For browsers that support crypto.subtle, they will use the standard API provided by the browser. However, for those that do not, we have bundled `crypto-js`
    such that their browsers can still invoke the `generateHmacWithFallback()` function


###### Polyfills

- For legacy browsers that do not support native ES6+ features, rollup bundles all the polyfills needed

- At the top of the entrypoint-deflect-captcha.ts file, the necessary polyfills are explicitly imported:
    ```
    import 'core-js/stable'
    import 'regenerator-runtime/runtime'
    ```

- Each polyfill serves a different purpose, for example:
    
    - core-js/stable: Provides shims for missing JavaScript features.
    - regenerator-runtime/runtime: Ensures async/await support for older browsers.


## Project Structure

```
    .
    ├── README.md                        <- You are here
    ├── captchaRollup.config.mjs                            <- Rollup config for bundling
    ├── dist                                                <- Production-ready build output
    │   ├── client
    │   │   └── scripts
    │   │       └── bundle.js                               <- Bundled JS for the client
    │   └── index.html                                      <- Fully self-contained, bundled page. **This is the ONLY thing that need be served by the server.**
    ├── injectBundleJSToIndexHTML.js                        <- Post-bundling script injector
    ├── package-lock.json
    ├── package.json
    ├── src                                                 <- Main source directory
    │   ├── client
    │   │   ├── scripts                                     <- Client-side logic
    │   │   │   ├── attach-footer-and-header-info.ts
    │   │   │   ├── check-initial-state.ts
    │   │   │   ├── client-captcha-solver.ts
    │   │   │   ├── entrypoint-deflect-captcha.ts           <- Main entrypoint, initializes everything
    │   │   │   ├── inspect-target-image-modal.ts
    │   │   │   ├── puzzle-instructions-info-button.ts
    │   │   │   ├── request-different-puzzle.ts
    │   │   │   └── utils                                   <- Helper functions (containing functions with prebundled dependencies as fallbacks for legacy browsers)
    │   │   │       ├── cookie-utils.ts
    │   │   │       └── hmac-utils.ts
    │   │   └── styles                                      <- CSS for the UI (Note: Currently ALL css is already injected directly into the <style></style> tags of the `index.html` - these are here for convenience)
    │   │       ├── main.css
    │   │       ├── puzzle-container.css
    │   │       ├── puzzle-grid.css
    │   │       ├── puzzle-instructions.css
    │   │       ├── puzzle-messages-to-user.css
    │   │       ├── puzzle-refresh.css
    │   │       ├── puzzle-submission.css
    │   │       └── puzzle-thumbnail.css
    │   ├── deflect_logo.svg                                <- Deflect Logo (injected into `index.html` during bundling)
    │   └── index.html                                      <- The HTML template **before** bundling (**not to be served to user**)
    ├── tsconfig.json                                       <- TypeScript configuration
    └── types                                               <- Shared type definitions
        └── shared.d.ts 
```


### types (`puzzle_ui/types`)

- Contains TypeScript type definitions shared across the UI.

### src (`puzzle_ui/src`)

#### src/index.html

- `src/index.html` is the template HTML file **before** bundling. 
- It gets modified during the build process to embed scripts, styles, and the Deflect logo.

#### src/deflect_logo.svg

- The Deflect CAPTCHA logo injected into the final `index.html`.

#### src/client

- Houses all scripts and styles required for the CAPTCHA UI.

##### src/client/scripts

- The core client side logic that runs in the browser

- **Entrypoint:** `entrypoint-deflect-captcha.ts`
    - Initializes the CAPTCHA system.
    - Checks if an initial state was injected or needs to be fetched.
    - Handles error reporting and retry logic.
    - Implements a fallback mechanism for worst-case scenarios.

###### src/client/scripts/utils

- These are utilities that are prebundled with the dependencies required for legacy browsers to function. 
    - For example, not all browsers admit crypto.subtle API. Therefore, we provide `hmac-utils.ts` such that all browsers can either use their `crypto.subtle` API should they have it, or fallback to the pre bundled depdency (`crypto-js`)

- `cookie-utils.ts`: Handles cookies for authentication and state management.
- `hmac-utils.ts`: Cryptographic helper functions.

##### src/client/styles

- Defines the visual styling for different puzzle components.

- By default, styles are embedded directly into `index.html`.

- If you prefer to bundle CSS with JS, you must:
    1) Enable the postcss Rollup hook.
    2) Uncomment the import statements in `entrypoint-deflect-captcha.ts`.
    3) Remove the <style></style> tags from `src/index.html`.

### dist (`puzzle_ui/dist`)

- Contains the production-ready assets.

- Key files:
    - `dist/index.html`: The final, self-contained page (fully bundled).
    - `dist/client/scripts/bundle.js`: The compiled JavaScript bundle.

- **Note:**
    - The `index.html` already includes all required `scripts/styles`.
    - *Only* `index.html` and the user's cookie are needed for deployment.

### root (`puzzle_ui/`)

- houses `injectBundleJSToIndexHTML.js`
    
- This is a custom Rollup hook that modifies index.html after bundling.

- Automatically injects bundle.js into index.html, ensuring that:

    1) All assets are inline (to be served in a single request).
    2) The Deflect CAPTCHA system remains self-contained.

## Deployment Guide

### Serving in Production

- The bundling process ensures that all required assets are packaged into a **single deliverable** for easy deployment. This includes:

1) JavaScript - Bundled with Rollup, optimized, and obfuscated (for production only) & is injected directly into `index.html` via the `injectBundleJSToIndexHTML.js` script.
2) Deflect Logo SVG - Also injected directly into index.html via the `injectBundleJSToIndexHTML.js` script.
3) CSS - Embedded directly inside `index.html`. 
    **Note:** The css may also be included with the `bundle.js` if you:
        1) remmove it from `index.html`
        2) uncomment the entrypoint `*.css` imports
        3) uncomment the postcss() rollup code
4) Polyfills - Included to support legacy browsers (which is an important requirement).

#### What needs to be served?

- This means that the only *file* you need to serve is: `dist/index.html`
- You must also attach a *challenge cookie* along with the `dist/index.html` response payload using the cookie name: `deflect_challenge4`
- That's it. Nothing else is required.
    
#### You do **not** need to serve:

- Logos, JS, CSS, or external assets—they are already embedded in the `index.html`.
- Separate API endpoints for fetching assets—everything needed is in the single file.

#### What the Server Needs to Do

- To properly issue a unique challenge per user, the **server** can follow one of two procedures:

- **1) Recommended Approach (Production Best Practice):** inject the initial state into index.html
    - The server reads index.html before serving it.
    - The server injects a dynamically generated initial state (per user).
    - The user receives index.html with the puzzle state already embedded.
    - This is how Deflect works in production and ensures a seamless, efficient challenge issuance.
    

- **2) Alternative Approach:** do not inject the initial state into index.html, but have an endpoint prepared to handle a request for the puzzle state
    - If the initial state is not injected, the puzzle will immediately phone home requesting it from the server.
    - In this case, the server must provide an endpoint to handle these state requests dynamically.
    - This approach may be useful for development but is not recommended for production.
    

- **Note:** You *will* need to have the endpoint to serve a puzzle state on request regardless of what option you choose as the puzzle includes a rate limited "refresh" button that requets a new puzzle state and updates the current state. This was included to provide the user the option of trying a different one if they deem the current board too difficult. However, it is still recommended to inject the initial state into `index.html` as this is a requirement for how Deflect works.

- For details on how the server should inject the initial state, refer to the [Server-Side Documentation](../internal/puzzle-util/README.md).

## Contributing

### Setting Up the Development Environment
 
- Step 1) Clone this repository

- Step 2) Install dependencies

    ### The UI is built using Node.js and Rollup. Ensure you have Node.js installed (v18 or later). Then, install the required dependencies:
    ```
    cd puzzle_ui
    npm install
    ```

- Step 3) Create a **.env.production** and **.env.development** files

    #### .env.production:
    ```    
    MINIFY_CSS=true
    SOURCE_MAP=false
    OBFUSCATE=true
    ```

    #### .env.development:
    ```
    MINIFY_CSS=false
    SOURCE_MAP=true
    OBFUSCATE=false
    ```

- Step 4) run the following commands:
    ```
    npm run clean
    npm run build
    ```

#### Package.json Commands

- ```npm run dev```
    - deletes the dist/ directory and rebuilds from scratch, bundling all dependencies, and watching for changes to client side code before rebundling (uses dev env variables)

- ```npm run build```
    - runs Rollup to bundle client-side code (which injects the bundle into the` index.html`)

- ```npm run clean```
    - clears the dist/ directory if you want a fresh build

- ```npm run watch```
    - watches for changes in client code & automatically rebundles

- ```npm run prod```
    - deletes the dist/ directory and rebuilds from scratch using production environment variables



#### Typical Development Workflow

- Either run:
    ```
    1) npm run clean
    2) npm run build
    ```
- Or:
    ```
    1) npm run dev
    ```

- The only difference is that the npm run dev will continue monitoring for changes such that when you make a change, it will automatically clean and build such that your server serves the most recent one

- **In both cases**, you must serve from **`dist/index.html`**

- This will not only include the html, but also the css as well as the js and all dependencies and polyfills
- The only thing that remains to do when serving it is to inject the initial state at runtime. Since each puzzle is unique to the user, the initial state cannot be precomputed and must be dynamically generated. The server handles this by issuing a state-specific challenge upon request. This is injected directly into the `index.html` as per Deflect requirements. For more details, check the [Server-Side Documentation](../internal/puzzle-util/README.md).
    - **Note:** If the initial state is **not injected** at runtime, the puzzle **will automatically request it** from the server. In this case, you **must have an endpoint** to handle this request and provide the state dynamically.

#### Typical Production Workflow
 - run: 
    ```
        npm run prod
    ```
- You can now serve the CAPTCHA directly from `dist/index.html`
    - This will contain the HTML, CSS, JS, Polyfills & all dependencies (such as for calculating HMAC)
    - It is also obfuscated via rollup
    - The only thing that remains to do when serving it is to inject the initial state at runtime. Since each puzzle is unique to the user, the initial state cannot be precomputed and must be dynamically generated. The server handles this by issuing a state-specific challenge upon request. This is injected directly into the `index.html` as per Deflect requirements. For more details, check the [Server-Side Documentation](../internal/puzzle-util/README.md).
        - **Note:** If the initial state is **not injected** at runtime, the puzzle **will automatically request it** from the server. In this case, you **must have an endpoint** to handle this request and provide the state dynamically.

---
