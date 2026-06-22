/* Scroll Animation Trigger Script - Framer-style animations */

const observerOptions = {
  threshold: 0.1,
  rootMargin: '0px 0px -50px 0px'
};

const scrollObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.style.animation = '';
      void entry.target.offsetWidth; // Trigger reflow
      
      // Determine animation based on element type
      const element = entry.target;
      
      if (element.classList.contains('terminal') || element.classList.contains('card')) {
        element.style.animation = 'fadeInUp 0.8s ease-out forwards';
      } else if (element.tagName === 'H1' || element.tagName === 'H2') {
        element.style.animation = 'fadeInDown 0.8s ease-out forwards';
      } else if (element.tagName === 'TABLE') {
        element.style.animation = 'fadeInUp 0.8s ease-out forwards';
        // Stagger row animations
        const rows = element.querySelectorAll('tbody tr');
        rows.forEach((row, index) => {
          row.style.animation = `fadeInUp 0.8s ease-out forwards`;
          row.style.animationDelay = `${index * 0.1}s`;
          row.style.opacity = '0';
        });
      } else if (element.tagName === 'BUTTON' || element.classList.contains('btn')) {
        element.style.animation = 'scaleIn 0.6s ease-out forwards';
      } else if (element.classList.contains('badge-critical') || 
                 element.classList.contains('badge-high') ||
                 element.classList.contains('badge-medium') ||
                 element.classList.contains('badge-low')) {
        element.style.animation = 'scaleIn 0.5s ease-out forwards';
      } else {
        element.style.animation = 'fadeInUp 0.7s ease-out forwards';
      }
      
      scrollObserver.unobserve(entry.target);
    }
  });
}, observerOptions);

// Observe all animatable elements
document.addEventListener('DOMContentLoaded', () => {
  // Elements to animate
  const animatableSelectors = [
    '.terminal',
    '.card',
    '.panel',
    'h1',
    'h2',
    'h3',
    'table',
    'button',
    '.btn',
    'a[href^="/scan"]',
    '[class*="badge-"]',
    'input',
    'form'
  ];
  
  animatableSelectors.forEach(selector => {
    document.querySelectorAll(selector).forEach(element => {
      // Skip navigation elements
      if (!element.closest('nav')) {
        element.style.opacity = '0';
        scrollObserver.observe(element);
      }
    });
  });
  
  // Add parallax effect to background elements
  window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    const parallaxElements = document.querySelectorAll('[data-parallax]');
    
    parallaxElements.forEach(element => {
      const speed = element.dataset.parallax || 0.5;
      element.style.transform = `translateY(${scrolled * speed}px)`;
    });
  });
  
  // Enhance interactive elements with glow on scroll
  const floatingElements = document.querySelectorAll('.terminal, .card, .panel');
  floatingElements.forEach(element => {
    element.addEventListener('mouseenter', () => {
      element.style.boxShadow = `0 16px 48px rgba(102, 126, 234, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2)`;
    });
    
    element.addEventListener('mouseleave', () => {
      element.style.boxShadow = '';
    });
  });
  
  // Animate counters/numbers when they come into view
  const countElements = document.querySelectorAll('[data-count]');
  countElements.forEach(element => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        const target = parseInt(element.dataset.count);
        const duration = 2000;
        const start = Date.now();
        
        const animate = () => {
          const elapsed = Date.now() - start;
          const progress = Math.min(elapsed / duration, 1);
          const current = Math.floor(target * progress);
          element.textContent = current;
          
          if (progress < 1) {
            requestAnimationFrame(animate);
          }
        };
        
        animate();
        observer.unobserve(element);
      }
    }, { threshold: 0.5 });
    
    observer.observe(element);
  });
});

// Add fade-in animation to flash messages
const flashMessages = document.querySelectorAll('[role="alert"]');
flashMessages.forEach((msg, index) => {
  msg.style.animation = `fadeInDown 0.5s ease-out ${index * 0.2}s both`;
});

// Smooth scroll behavior
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

// Text reveal animation for headings
const headings = document.querySelectorAll('h1, h2, h3');
headings.forEach(heading => {
  heading.style.backgroundSize = '200% 200%';
  heading.style.animation = 'gradientShift 4s ease infinite';
});
