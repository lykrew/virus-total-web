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
            ({ error: { message: response.statusText } }));
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

// Handles the proccess of scanning a file using VirusTotal
async function scanFile() {
    const file = getElement('fileInput').files[0];
    if (!file) return showError("Please select a file!");
    if (file.size > 32 * 1024 * 1024) return showError("File size exceeds 32MB limit.");

    try {
        showLoading("Uploading File...");

        const formData = new FormData();
        formData.append("file", file);

        // Upload file to VirusTotal
        const uploadResult = await makeRequest("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            body: formData
        });

        if (!uploadResult.data?.id) {
            throw new Error("Failed to get file ID!");
        }

        // Delay before pulling for analysis results
        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        const analysisResult = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${uploadResult.data.id}`);

        if (!analysisResult.data?.id) {
            throw new Error("Failed to get analysis results!");
        }

        await pollAnalysisResults(analysisResult.data.id, file.name);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Polls VirusTotal for analysis results, retrying untill complete or timeout
async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while(attempts < maxAttempts) {
        try {
            showLoading(`Analyzing${fileName ? ` ${fileName}` : ''}... (${((maxAttempts - attempts) * interval / 1000).toFixed(0)}s remaining)`);

            const report = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${analysisId}`);
            const status = report.data?.attributes?.status;

            if (!status) throw new Error("Invalid analysis response!");

            if (status === "completed") {
                showFormattedResult(report);
                break;
            }

            if (status === "failed") {
                throw new Error("Analysis failed!");
            }

            if (++attempts >= maxAttempts) {
                throw new Error("Analysis timeout - please try again")
            }

            // Increase interval between retries 
            interval = Math.min(interval * 1.5, 8000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

// Formats and displays analysis in the UI
function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) return showError("Invalid response format!");

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    if (!total) return showError("No analysis results available!");
    
    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'Malicious' },
        suspicious: { color: 'suspicious', label: 'Suspicious' },
        harmless: { color: 'safe', label: 'Clean' },
        undetected: { color: 'undetected', label: 'Undetected' }
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key]);
        return acc;
    }, {});

    // Determine overall vardict
    const verdict = stats.malicious > 0 ? "Malicious" : stats.suspicious > 0 ? "Suspicious" : "Safe";
    const verdictClass = stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "safe";
    // 34:33
}