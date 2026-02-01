// API Key from VirusTotal API
const API_KEY = "34bded9119d71d2bdb7b618982d73752f07e3c66f5ab57cbb038723cd25b1d5d";

// Utility function to get DOM elements by ID
const getElement = id => document.getElementById(id);

// Updates the result display section with given content 
const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
}

// Shows a loading spinner and message
const showLoading = message => updateResult(`
        <div class = "loading>
            <p>${message}</p>
            <div class = "spinner"</div>
        </div>
    `);

// Displays an error message
const showError = message => updateResult(`<p class = "error"${message}</p>`);

// Generic function to make authenticated API requests to VirusTotal
async function makeRequest(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            "x-apikey": API_KEY,
            ...options.headers
        }
    });

    // Handle failed requests gracefully
    if (!response.ok) {
        const error = await response.json().catch(() => 
        ({ error: {message: response.statusText} }));
        throw new Error(error.error?.message || 'Request failed!');
    }

    return response.json(); // Parse response JSON
}

// Handles the proccess of scanning a URL using VirusTotal
async function scanURL() {
    const url = getElement('urlInput').value.trim();
    if (!url) return showError("Please enter a URL!");

    try {
        new URL(url);
    } catch {
        return showError("Please enter a valid URL (e.g., https://example.com");
    }

    try {
        showLoading("Submitting URL for scanning...");

        const encodedUrl = encodeURIComponent(url);

        // Submit URL to VirusTotal
        const submitResult = await makeRequest("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded"
            },
            body: `url = ${encodedUrl}`
        });

        if (!submitResult.data?.id) {
            throw new Error("Failed to get analysis ID");
        }

        // Delay before results
        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        await pollAnalysisResults(submitResult.data.id);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

