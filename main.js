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


