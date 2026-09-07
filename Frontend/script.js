/* =========================================================
   LINKSHIELD - MAIN FRONTEND LOGIC
   ========================================================= */

// FastAPI endpoint.
//
// Change this URL if your backend runs on another host/port.
const API_URL = "http://127.0.0.1:8000/analyze";


/* =========================================================
   DOM ELEMENTS
   ========================================================= */

const scanForm = document.getElementById("scan-form");

const urlInput = document.getElementById("url-input");

const scanButton = document.getElementById("scan-button");

const buttonText = document.getElementById("button-text");

const buttonLoader = document.getElementById("button-loader");

const inputError = document.getElementById("input-error");

const resultsSection = document.getElementById("results-section");

const newScanButton = document.getElementById("new-scan-button");


/* =========================================================
   FORM SUBMISSION
   ========================================================= */

scanForm.addEventListener("submit", async function (event) {

    // Prevent the browser from refreshing the page.
    event.preventDefault();

    const url = urlInput.value.trim();

    // Remove any previous error.
    hideError();


    // ---------------------------------------------------------
    // Basic frontend validation
    // ---------------------------------------------------------

    if (!url) {
        showError("Please enter a URL.");
        return;
    }


    // The frontend only performs basic validation.
    // The actual URL parsing and security analysis happens
    // inside the FastAPI backend.

    if (!looksLikeUrl(url)) {
        showError("Please enter a valid website URL.");
        return;
    }


    // Show loading state.
    setLoading(true);


    try {

        /* -----------------------------------------------------
           Send URL to FastAPI
           ----------------------------------------------------- */

        const response = await fetch(API_URL, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })
        });


        /* -----------------------------------------------------
           Handle HTTP errors
           ----------------------------------------------------- */

        if (!response.ok) {

            let message = "Unable to analyze the URL.";

            try {
                const errorData = await response.json();

                if (errorData.detail) {
                    message = errorData.detail;
                }

            } catch (error) {
                // Ignore JSON parsing error.
            }

            throw new Error(message);
        }


        /* -----------------------------------------------------
           Convert backend response to JSON
           ----------------------------------------------------- */

        const data = await response.json();


        /* -----------------------------------------------------
           Display results
           ----------------------------------------------------- */

        displayResults(data);

        resultsSection.classList.remove("hidden");

        // Scroll smoothly to the result.
        resultsSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    }


    catch (error) {

        console.error("LinkShield scan error:", error);

        showError(
            error.message ||
            "Something went wrong while analyzing the URL."
        );

    }


    finally {

        // Restore button after request finishes.
        setLoading(false);
    }

});


/* =========================================================
   NEW SCAN
   ========================================================= */

newScanButton.addEventListener("click", function () {

    resultsSection.classList.add("hidden");

    urlInput.value = "";

    hideError();

    urlInput.focus();

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });

});


/* =========================================================
   BASIC URL VALIDATION
   ========================================================= */

function looksLikeUrl(value) {

    try {

        /*
         * URL() requires a protocol.
         *
         * If the user enters:
         *
         * google.com
         *
         * we temporarily add https:// only for validation.
         */

        const normalized =
            /^https?:\/\//i.test(value)
                ? value
                : `https://${value}`;

        const parsedUrl = new URL(normalized);

        return Boolean(parsedUrl.hostname);

    }

    catch (error) {

        return false;

    }

}


/* =========================================================
   LOADING STATE
   ========================================================= */

function setLoading(isLoading) {

    if (isLoading) {

        scanButton.disabled = true;

        buttonText.classList.add("hidden");

        buttonLoader.classList.remove("hidden");

    }

    else {

        scanButton.disabled = false;

        buttonText.classList.remove("hidden");

        buttonLoader.classList.add("hidden");

    }

}


/* =========================================================
   ERROR MESSAGE
   ========================================================= */

function showError(message) {

    inputError.textContent = message;

    inputError.classList.remove("hidden");

}


function hideError() {

    inputError.textContent = "";

    inputError.classList.add("hidden");

}


/* =========================================================
   ENTER KEY EXPERIENCE
   ========================================================= */

// Automatically focus the URL field when the page loads.

window.addEventListener("DOMContentLoaded", function () {

    urlInput.focus();

});