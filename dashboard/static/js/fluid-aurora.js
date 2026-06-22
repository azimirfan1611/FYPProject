/* Simplex Noise Implementation */
class SimplexNoise {
  constructor(seed = 0) {
    this.p = [];
    for (let i = 0; i < 256; i++) {
      this.p[i] = Math.floor((Math.sin(i + seed) + 1) * 128);
    }
    this.p = this.p.concat(this.p);
  }

  fade(t) {
    return t * t * t * (t * (t * 6 - 15) + 10);
  }

  lerp(t, a, b) {
    return a + t * (b - a);
  }

  grad(hash, x, y) {
    const h = hash & 15;
    const u = h < 8 ? x : y;
    const v = h < 8 ? y : x;
    return ((h & 1) === 0 ? u : -u) + ((h & 2) === 0 ? v : -v);
  }

  noise(x, y) {
    const xi = Math.floor(x) & 255;
    const yi = Math.floor(y) & 255;
    
    const xf = x - Math.floor(x);
    const yf = y - Math.floor(y);
    
    const u = this.fade(xf);
    const v = this.fade(yf);
    
    const aa = this.p[this.p[xi] + yi];
    const ab = this.p[this.p[xi] + yi + 1];
    const ba = this.p[this.p[xi + 1] + yi];
    const bb = this.p[this.p[xi + 1] + yi + 1];
    
    const x1 = this.lerp(u, this.grad(aa, xf, yf), this.grad(ba, xf - 1, yf));
    const x2 = this.lerp(u, this.grad(ab, xf, yf - 1), this.grad(bb, xf - 1, yf - 1));
    
    return this.lerp(v, x1, x2);
  }
}

/* Fluid Aurora System */
class FluidAurora {
  constructor() {
    this.canvas = null;
    this.ctx = null;
    this.width = 0;
    this.height = 0;
    
    this.noise = new SimplexNoise(Date.now());
    this.time = 0;
    this.timeScale = 0.0005;
    
    this.mouseX = 0;
    this.mouseY = 0;
    this.mouseVelX = 0;
    this.mouseVelY = 0;
    this.prevMouseX = 0;
    this.prevMouseY = 0;
    
    this.blobs = [];
    this.particleCount = 8;
    
    this.init();
  }

  init() {
    // Create canvas
    this.canvas = document.createElement('canvas');
    this.canvas.id = 'fluid-aurora-canvas';
    document.body.insertBefore(this.canvas, document.body.firstChild);
    
    this.ctx = this.canvas.getContext('2d');
    this.resize();
    
    // Load CSS
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = '/static/css/fluid-aurora.css';
    document.head.appendChild(link);
    
    // Initialize blobs
    for (let i = 0; i < this.particleCount; i++) {
      this.blobs.push({
        x: Math.random() * this.width,
        y: Math.random() * this.height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        size: 200 + Math.random() * 300,
        hue: 280 + Math.random() * 80,
        offset: Math.random() * 1000,
      });
    }
    
    // Event listeners
    document.addEventListener('mousemove', (e) => this.onMouseMove(e));
    
    // Window resize
    window.addEventListener('resize', () => this.resize());
    
    // Start animation
    this.animate();
  }

  resize() {
    this.width = window.innerWidth;
    this.height = window.innerHeight;
    this.canvas.width = this.width;
    this.canvas.height = this.height;
  }

  onMouseMove(event) {
    this.mouseVelX = event.clientX - this.prevMouseX;
    this.mouseVelY = event.clientY - this.prevMouseY;
    this.prevMouseX = event.clientX;
    this.prevMouseY = event.clientY;
    this.mouseX = event.clientX;
    this.mouseY = event.clientY;
  }

  updateBlobs() {
    const friction = 0.98;
    const mouseInfluence = 0.0003;
    
    for (let blob of this.blobs) {
      // Noise-based movement
      const noiseX = this.noise.noise(
        blob.x * 0.001 + this.time,
        blob.y * 0.001
      );
      const noiseY = this.noise.noise(
        blob.x * 0.001,
        blob.y * 0.001 + this.time
      );
      
      // Apply noise as velocity
      blob.vx += noiseX * 0.1;
      blob.vy += noiseY * 0.1;
      
      // Mouse force field influence
      const dx = this.mouseX - blob.x;
      const dy = this.mouseY - blob.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const maxDist = 500;
      
      if (dist < maxDist) {
        const force = (1 - dist / maxDist) * mouseInfluence;
        blob.vx += (dx / dist) * force * 200;
        blob.vy += (dy / dist) * force * 200;
      }
      
      // Apply velocity
      blob.x += blob.vx;
      blob.y += blob.vy;
      
      // Friction
      blob.vx *= friction;
      blob.vy *= friction;
      
      // Wrap around edges
      if (blob.x < -blob.size) blob.x = this.width + blob.size;
      if (blob.x > this.width + blob.size) blob.x = -blob.size;
      if (blob.y < -blob.size) blob.y = this.height + blob.size;
      if (blob.y > this.height + blob.size) blob.y = -blob.size;
      
      // Continuous oscillation
      blob.size = 200 + Math.sin(this.time * 0.001 + blob.offset) * 100;
    }
  }

  draw() {
    // Clear with dark navy background
    this.ctx.fillStyle = '#0a0a1a';
    this.ctx.fillRect(0, 0, this.width, this.height);
    
    // Draw blobs with soft blending
    this.ctx.globalCompositeOperation = 'screen';
    this.ctx.filter = 'blur(80px)';
    
    for (let blob of this.blobs) {
      const gradient = this.ctx.createRadialGradient(
        blob.x, blob.y, 0,
        blob.x, blob.y, blob.size
      );
      
      // Color based on hue
      const hue = blob.hue + Math.sin(this.time * 0.001 + blob.offset) * 20;
      
      gradient.addColorStop(0, `hsla(${hue}, 100%, 60%, 0.4)`);
      gradient.addColorStop(0.4, `hsla(${hue}, 100%, 50%, 0.2)`);
      gradient.addColorStop(0.7, `hsla(${hue + 20}, 100%, 40%, 0.1)`);
      gradient.addColorStop(1, `hsla(${hue + 40}, 100%, 30%, 0)`);
      
      this.ctx.fillStyle = gradient;
      this.ctx.beginPath();
      this.ctx.arc(blob.x, blob.y, blob.size, 0, Math.PI * 2);
      this.ctx.fill();
    }
    
    this.ctx.globalCompositeOperation = 'source-over';
    this.ctx.filter = 'none';
  }

  animate() {
    this.time += 1;
    
    this.updateBlobs();
    this.draw();
    
    requestAnimationFrame(() => this.animate());
  }
}

// Initialize on load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new FluidAurora();
  });
} else {
  new FluidAurora();
}
