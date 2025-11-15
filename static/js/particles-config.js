// expects particles.min.js to expose particlesJS
if (window.particlesJS) {
  particlesJS('particles-root', {
    particles: {
      number: { value: 16 },
      color: { value: '#7a0b12' },
      shape: { type: 'circle' },
      opacity: { value: 0.22 },
      size: { value: 4 },
      move: { speed: 0.6 }
    },
    interactivity: { events: { onhover: { enable: false } } },
    retina_detect: true
  });
}
