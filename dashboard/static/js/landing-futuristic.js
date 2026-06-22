/* ========================================
   FUTURISTIC LANDING PAGE - ANIMATIONS
   GSAP ScrollTrigger + Framer Motion Style
   ======================================== */

// Mouse Follow Glow Effect
const mouseGlow = document.querySelector('.mouse-glow');
let mouseX = 0;
let mouseY = 0;
let targetX = 0;
let targetY = 0;

document.addEventListener('mousemove', (e) => {
  targetX = e.clientX;
  targetY = e.clientY;
  mouseGlow.classList.add('active');
});

document.addEventListener('mouseleave', () => {
  mouseGlow.classList.remove('active');
});

// Smooth mouse follow with requestAnimationFrame
function animateMouseGlow() {
  mouseX += (targetX - mouseX) * 0.15;
  mouseY += (targetY - mouseY) * 0.15;
  
  mouseGlow.style.transform = `translate(${mouseX}px, ${mouseY}px)`;
  requestAnimationFrame(animateMouseGlow);
}

animateMouseGlow();

// ========================================
// PARALLAX SCROLL EFFECT
// ========================================

window.addEventListener('scroll', () => {
  const orbs = document.querySelectorAll('[class*="gradient-orb"], [class*="ambient-light"]');
  const scrollY = window.pageYOffset;

  orbs.forEach((orb, index) => {
    const speed = 0.3 + index * 0.05;
    orb.style.transform = `translateY(${scrollY * speed}px)`;
  });
});

// ========================================
// INTERSECTION OBSERVER FOR SCROLL REVEALS
// ========================================

const observerOptions = {
  threshold: 0.1,
  rootMargin: '0px 0px -100px 0px'
};

const scrollObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.classList.add('active');
      
      // Stagger cards in grid
      const grid = entry.target.closest('.features-grid, .showcase-grid, .pricing-grid');
      if (grid) {
        const cards = grid.querySelectorAll('.feature-card, .showcase-item, .pricing-card');
        const index = Array.from(cards).indexOf(entry.target);
        entry.target.style.animationDelay = `${index * 0.1}s`;
      }
      
      scrollObserver.unobserve(entry.target);
    }
  });
}, observerOptions);

document.addEventListener('DOMContentLoaded', () => {
  // Observe all reveal elements
  document.querySelectorAll('.reveal, .feature-card, .showcase-item, .pricing-card, .testimonial-card').forEach((el) => {
    el.classList.add('reveal');
    scrollObserver.observe(el);
  });
});

// ========================================
// FLOATING PARTICLES/STARS GENERATOR
// ========================================

function generateStars() {
  const container = document.querySelector('.particles-container');
  const starCount = 50;

  for (let i = 0; i < starCount; i++) {
    const star = document.createElement('div');
    star.className = 'star';
    
    const x = Math.random() * window.innerWidth;
    const y = Math.random() * window.innerHeight;
    const delay = Math.random() * 3;
    const duration = 2 + Math.random() * 3;
    
    star.style.left = x + 'px';
    star.style.top = y + 'px';
    star.style.animationDelay = delay + 's';
    star.style.animationDuration = duration + 's';
    
    container.appendChild(star);
  }
}

generateStars();

// ========================================
// SCROLL INDICATOR/SMOOTHING
// ========================================

document.addEventListener('DOMContentLoaded', () => {
  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.querySelector(anchor.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });
});

// ========================================
// MAGNETIC BUTTON HOVER
// ========================================

const buttons = document.querySelectorAll('.btn');
buttons.forEach(button => {
  button.addEventListener('mousemove', (e) => {
    const rect = button.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;
    
    const distance = Math.sqrt(x * x + y * y);
    
    if (distance < 80) {
      const angle = Math.atan2(y, x);
      const tx = Math.cos(angle) * (80 - distance) * 0.15;
      const ty = Math.sin(angle) * (80 - distance) * 0.15;
      
      button.style.transform = `translate(${tx}px, ${ty}px)`;
    }
  });

  button.addEventListener('mouseleave', () => {
    button.style.transform = '';
  });
});

// ========================================
// FEATURE CARD MOUSE TRACKING GLOW
// ========================================

document.querySelectorAll('.feature-card').forEach(card => {
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;
    
    card.style.setProperty('--x', x + '%');
    card.style.setProperty('--y', y + '%');
  });

  card.addEventListener('mouseleave', () => {
    card.style.setProperty('--x', '50%');
    card.style.setProperty('--y', '50%');
  });
});

// ========================================
// COUNTER ANIMATION FOR STATS
// ========================================

function animateCounter(el) {
  if (el.hasAttribute('data-animated')) return;
  el.setAttribute('data-animated', 'true');

  const finalValue = parseInt(el.textContent);
  const duration = 2000;
  const steps = 60;
  const increment = finalValue / steps;

  let current = 0;

  const interval = setInterval(() => {
    current++;
    el.textContent = Math.floor(increment * current);

    if (current >= steps) {
      el.textContent = finalValue;
      clearInterval(interval);
    }
  }, duration / steps);
}

const counterObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      animateCounter(entry.target);
      counterObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.5 });

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.stat-number').forEach(counter => {
    counterObserver.observe(counter);
  });
});

// ========================================
// GSAP SCROLL ANIMATIONS (if GSAP loaded)
// ========================================

if (typeof gsap !== 'undefined') {
  gsap.registerPlugin(ScrollTrigger);

  // Hero section entrance animation
  gsap.from('.hero-content', {
    opacity: 0,
    y: 50,
    duration: 1.2,
    ease: 'power3.out'
  });

  // Feature cards stagger
  document.querySelectorAll('.feature-card').forEach((card, index) => {
    gsap.from(card, {
      scrollTrigger: {
        trigger: card,
        start: 'top 80%',
        markers: false
      },
      opacity: 0,
      y: 40,
      duration: 0.8,
      delay: index * 0.1,
      ease: 'power3.out'
    });
  });

  // Pricing cards stagger
  document.querySelectorAll('.pricing-card').forEach((card, index) => {
    gsap.from(card, {
      scrollTrigger: {
        trigger: card,
        start: 'top 80%'
      },
      opacity: 0,
      y: 40,
      duration: 0.8,
      delay: index * 0.1,
      ease: 'power3.out'
    });
  });

  // Testimonials slide in
  document.querySelectorAll('.testimonial-card').forEach((card) => {
    gsap.from(card, {
      scrollTrigger: {
        trigger: card,
        start: 'top 85%'
      },
      opacity: 0,
      x: -50,
      duration: 0.8,
      ease: 'power3.out'
    });
  });

  // Section titles
  document.querySelectorAll('.section-title').forEach((title) => {
    gsap.from(title, {
      scrollTrigger: {
        trigger: title,
        start: 'top 85%'
      },
      opacity: 0,
      y: 30,
      duration: 0.8,
      ease: 'power3.out'
    });
  });

  // Parallax sections
  document.querySelectorAll('.section').forEach((section) => {
    gsap.to(section, {
      scrollTrigger: {
        trigger: section,
        start: 'top center',
        end: 'bottom center',
        scrub: 1,
        markers: false
      },
      y: -50,
      opacity: 1,
      ease: 'power1.out'
    });
  });
}

// ========================================
// NAVBAR SCROLL EFFECT
// ========================================

let lastScrollY = 0;
const navbar = document.querySelector('nav');

window.addEventListener('scroll', () => {
  const currentScrollY = window.scrollY;

  if (currentScrollY > 50) {
    navbar.style.background = 'rgba(0, 0, 0, 0.6)';
    navbar.style.borderBottom = '1px solid rgba(255, 150, 220, 0.15)';
  } else {
    navbar.style.background = 'rgba(0, 0, 0, 0.4)';
    navbar.style.borderBottom = '1px solid rgba(255, 150, 220, 0.1)';
  }

  lastScrollY = currentScrollY;
});

// ========================================
// LOAD EXTERNAL GSAP (optional enhancement)
// ========================================

// You can load GSAP from CDN for advanced animations
// Just add this script tag in the HTML:
// <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
// <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/ScrollTrigger.min.js"></script>

console.log('✨ Futuristic Premium Landing Page Loaded');
