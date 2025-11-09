const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const toggleFormsButton = document.getElementById("toggle-forms");
document.getElementById("toggle-forms").addEventListener("click", () => {
    if (registerForm.style.display == "none") {
        registerForm.style.display = "block";
        loginForm.style.display = "none";
        toggleFormsButton.textContent = "Nazad na prijavu.";
    } else {
        registerForm.style.display = "none";
        loginForm.style.display = "block";
        toggleFormsButton.textContent = "Nemaš račun? Registriraj se.";
    }
});