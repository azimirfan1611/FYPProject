/* ========================================
   ORIGINAL LANDING PAGE ANIMATIONS - SIMPLE
   ======================================== */

document.addEventListener('DOMContentLoaded', () => {
  generateParticles();
  initializeScrollAnimations();
  initializeFAQ();
});

/* ========================================
   GENERATE FLOATING PARTICLES
   ======================================== */

function generateParticles() {
  const container = document.getElementById('particles');
  const particleCount = 50;

  for (let i = 0; i < particleCount; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    
    const x = Math.random() * window.innerWidth;
    const y = Math.random() * window.innerHeight;
    const duration = 15 + Math.random() * 25;
    const delay = Math.random() * 5;
    
    particle.style.left = x + 'px';
    particle.style.top = y + 'px';
    particle.style.width = (1 + Math.random() * 3) + 'px';
    particle.style.height = particle.style.width;
    particle.style.animationDuration = duration + 's';
    particle.style.animationDelay = delay + 's';
    
    container.appendChild(particle);
  }
}

/* ========================================
   SCROLL REVEAL ANIMATIONS
   ======================================== */

function initializeScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('active');
        
        // Stagger effect for cards in a grid
        if (entry.target.parentElement.classList.contains('grid')) {
          const cards = entry.target.parentElement.querySelectorAll('.scroll-reveal');
          const index = Array.from(cards).indexOf(entry.target);
          entry.target.style.animationDelay = `${index * 0.1}s`;
        }
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
  });

  // Observe all scroll-reveal elements
  document.querySelectorAll('.scroll-reveal').forEach(el => {
    observer.observe(el);
  });
}

/* ========================================
   FAQ ACCORDION
   ======================================== */

function initializeFAQ() {
  const faqItems = document.querySelectorAll('.faq-item');

  faqItems.forEach(item => {
    const question = item.querySelector('.faq-question');
    
    question.addEventListener('click', () => {
      // Close other items
      faqItems.forEach(otherItem => {
        if (otherItem !== item) {
          otherItem.classList.remove('active');
        }
      });
      
      // Toggle current item
      item.classList.toggle('active');
    });
  });
}

/* ========================================
   PARALLAX SCROLL EFFECT
   ======================================== */

window.addEventListener('scroll', () => {
  const blobs = document.querySelectorAll('.aurora-gradient');
  const scrollY = window.pageYOffset;

  blobs.forEach((blob, index) => {
    const speed = 0.3 + index * 0.1;
    blob.style.transform = `translateY(${scrollY * speed}px)`;
  });
});

console.log('✨ Original Premium Landing Page Loaded');
