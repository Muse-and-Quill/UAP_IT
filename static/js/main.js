// ===== THEME TOGGLE WITH PERSISTENCE =====
const toggleBtn = document.getElementById('theme-toggle');
const body = document.body;

// Load theme from localStorage
const savedTheme = localStorage.getItem('theme');
if(savedTheme === 'dark'){
  body.classList.add('dark');
  toggleBtn.textContent = '☀️ Light Mode';
} else {
  body.classList.remove('dark');
  toggleBtn.textContent = '🌙 Dark Mode';
}

// Toggle theme and save to localStorage
toggleBtn.addEventListener('click', () => {
  body.classList.toggle('dark');
  if(body.classList.contains('dark')){
    toggleBtn.textContent = '☀️ Light Mode';
    localStorage.setItem('theme', 'dark');
  } else {
    toggleBtn.textContent = '🌙 Dark Mode';
    localStorage.setItem('theme', 'light');
  }
});


// ===== PARTICLES.JS CONFIG =====
if (window.particlesJS) {
  particlesJS("particles-root", {
    "particles": {
      "number": { "value": 40, "density": { "enable": true, "value_area": 800 } },
      "color": { "value": "#800000" },
      "shape": { "type": "circle" },
      "opacity": { "value": 0.3, "random": true },
      "size": { "value": 3, "random": true },
      "line_linked": { "enable": false },
      "move": { "enable": true, "speed": 0.6, "direction": "none", "random": true }
    },
    "interactivity": {
      "detect_on": "canvas",
      "events": { "onhover": { "enable": true, "mode": "repulse" } }
    },
    "retina_detect": true
  });
}
// ===== PRELOADER =====
const preloader = document.getElementById('preloader');
const mainContent = document.getElementById('mainContent');

window.addEventListener('load', () => {
  // Show preloader at least 1–2 seconds for effect
  setTimeout(() => {
    preloader.style.opacity = '0';
    preloader.style.visibility = 'hidden';
    if (mainContent) {
      mainContent.style.opacity = '1';
    }
  }, 4000); // adjust delay (2000ms = 2 seconds)
});

// ===== OTP BUTTON CLICK =====
document.getElementById('send-otp').addEventListener('click', () => {
  alert('OTP will be sent to your registered email!');
  // Implement AJAX POST to Flask route for sending OTP
});

// Optional: Smooth focus animation for password input
const resetInput = document.querySelector('#reset-form input[name="new_password"]');
resetInput.addEventListener('focus', () => {
  resetInput.style.borderColor = '#b71c1c';
  resetInput.style.boxShadow = '0 0 10px rgba(183,28,28,0.3)';
});

resetInput.addEventListener('blur', () => {
  resetInput.style.borderColor = '#ccc';
  resetInput.style.boxShadow = 'none';
});
// Smooth focus effect for forgot password inputs
document.querySelectorAll('.forgot-card input').forEach(input => {
  input.addEventListener('focus', () => {
    input.style.borderColor = '#b71c1c';
    input.style.boxShadow = '0 0 10px rgba(183,28,28,0.3)';
  });
  input.addEventListener('blur', () => {
    input.style.borderColor = '#ccc';
    input.style.boxShadow = 'none';
  });
});
// Smooth focus for OTP input
const otpInput = document.querySelector('.otp-card input[name="otp"]');
otpInput.addEventListener('focus', () => {
  otpInput.style.borderColor = '#b71c1c';
  otpInput.style.boxShadow = '0 0 10px rgba(183,28,28,0.3)';
});
otpInput.addEventListener('blur', () => {
  otpInput.style.borderColor = '#ccc';
  otpInput.style.boxShadow = 'none';
});
