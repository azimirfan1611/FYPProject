/* ========================================
   PREMIUM SAAS LANDING PAGE - INTERACTIONS
   ======================================== */

// Initialize everything on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initializeScrollAnimations();
  initializeParticleSystem();
  initializeFAQ();
  initializeCounterAnimation();
  initializeSmoothScroll();
  initializeMagneticButtons();
});

/* ========================================
   SCROLL REVEAL ANIMATIONS
   ======================================== */

function initializeScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('reveal');
        
        // Stagger effect for cards in a grid
        if (entry.target.parentElement.classList.contains('grid')) {
          const index = Array.from(entry.target.parentElement.children).indexOf(entry.target);
          entry.target.style.animationDelay = `${index * 0.1}s`;
        }
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  });

  // Observe all scroll-reveal elements
  document.querySelectorAll('.scroll-reveal').forEach(el => {
    observer.observe(el);
  });

  // Also observe phase cards
  document.querySelectorAll('.phase-card').forEach((el, index) => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(40px)';
    
    const observer2 = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.style.animation = `revealCard 0.8s ease-out ${index * 0.15}s forwards`;
          observer2.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });
    
    observer2.observe(el);
  });
}

/* ========================================
   PARTICLE SYSTEM
   ======================================== */

function initializeParticleSystem() {
  const container = document.querySelector('.particles-container');
  const particleCount = 60;

  for (let i = 0; i < particleCount; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    
    const x = Math.random() * window.innerWidth;
    const y = Math.random() * window.innerHeight;
    const duration = 15 + Math.random() * 20;
    const delay = Math.random() * 5;
    
    particle.style.left = x + 'px';
    particle.style.top = y + 'px';
    particle.style.width = (1 + Math.random() * 3) + 'px';
    particle.style.height = particle.style.width;
    particle.style.animationDuration = duration + 's';
    particle.style.animationDelay = delay + 's';
    
    // Random drift direction
    const xOffset = (Math.random() - 0.5) * 200;
    particle.style.setProperty('--x-offset', xOffset + 'px');
    
    container.appendChild(particle);
  }
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
   COUNTER ANIMATIONS
   ======================================== */

function initializeCounterAnimation() {
  const counters = document.querySelectorAll('.stat-number');

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting && !entry.target.hasAttribute('data-counted')) {
        entry.target.setAttribute('data-counted', 'true');
        animateCounter(entry.target);
      }
    });
  }, { threshold: 0.5 });

  counters.forEach(counter => observer.observe(counter));
}

function animateCounter(element) {
  const text = element.textContent;
  const number = parseInt(text.replace(/\D/g, ''));
  const suffix = text.replace(/\d/g, '');
  
  const duration = 2000; // 2 seconds
  const steps = 60;
  const stepValue = number / steps;
  
  let current = 0;
  const interval = setInterval(() => {
    current++;
    const value = Math.floor(stepValue * current);
    element.textContent = value + suffix;
    
    if (current >= steps) {
      element.textContent = number + suffix;
      clearInterval(interval);
    }
  }, duration / steps);
}

/* ========================================
   SMOOTH SCROLL
   ======================================== */

function initializeSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });
}

/* ========================================
   MAGNETIC BUTTON HOVER
   ======================================== */

function initializeMagneticButtons() {
  const buttons = document.querySelectorAll('.btn');

  buttons.forEach(button => {
    button.addEventListener('mousemove', (e) => {
      const rect = button.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      
      const distance = Math.sqrt(x * x + y * y);
      
      if (distance < 100) {
        const angle = Math.atan2(y, x);
        const tx = Math.cos(angle) * (100 - distance) * 0.1;
        const ty = Math.sin(angle) * (100 - distance) * 0.1;
        
        button.style.transform = `translate(${tx}px, ${ty}px)`;
      }
    });

    button.addEventListener('mouseleave', () => {
      button.style.transform = '';
    });
  });
}

/* ========================================
   PARALLAX SCROLL EFFECT
   ======================================== */

window.addEventListener('scroll', () => {
  const blobs = document.querySelectorAll('.aurora-blob');
  const scrollY = window.pageYOffset;

  blobs.forEach((blob, index) => {
    const speed = 0.5 + index * 0.1;
    blob.style.transform = `translateY(${scrollY * speed}px)`;
  });
});

/* ========================================
   INTERSECTION OBSERVER FOR PHASE CARDS
   ======================================== */

const phaseObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.style.opacity = '1';
      entry.target.style.transform = 'translateY(0)';
    }
  });
}, { threshold: 0.2 });

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.phase-card').forEach(card => {
    phaseObserver.observe(card);
  });
});
