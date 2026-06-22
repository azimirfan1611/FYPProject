/**
 * Timezone Detection & Setup
 * Automatically detects user's timezone and syncs it with the server
 */

(function() {
  'use strict';

  // Detect user's timezone using JavaScript
  function detectTimezone() {
    try {
      // Modern browser API
      if (typeof Intl !== 'undefined' && typeof Intl.DateTimeFormat !== 'undefined') {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
      }
    } catch (e) {
      console.warn('[TZ] Failed to detect timezone:', e);
    }
    return 'Asia/Singapore';
  }

  // Send timezone to server
  function syncTimezone() {
    const tz = detectTimezone();
    
    // Also store in localStorage
    try {
      localStorage.setItem('user_timezone', tz);
    } catch (e) {
      // localStorage not available
    }

    const xhr = new XMLHttpRequest();
    
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        if (xhr.status === 200) {
          console.log('[TZ] Timezone synced:', tz);
          // Reload page to apply timezone changes to already-rendered templates
          setTimeout(() => {
            window.location.reload();
          }, 500);
        } else {
          console.warn('[TZ] Failed to sync timezone:', xhr.status);
        }
      }
    };
    
    xhr.open('POST', '/api/set-timezone', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    try {
      xhr.send(JSON.stringify({ timezone: tz }));
    } catch (e) {
      console.error('[TZ] Failed to send timezone:', e);
    }
  }

  // Run when document is ready
  function init() {
    // Only sync if user is authenticated (check for token in session)
    const isAuthenticated = document.body.dataset.authenticated === 'true' || 
                           document.querySelector('[data-authenticated="true"]') !== null ||
                           window.location.pathname.includes('/dashboard') ||
                           window.location.pathname.includes('/scan') ||
                           window.location.pathname.includes('/trends') ||
                           window.location.pathname.includes('/schedules');
    
    if (isAuthenticated) {
      // Get stored timezone
      const storedTz = localStorage.getItem('user_timezone');
      const detectedTz = detectTimezone();
      
      // If timezone changed or not set, sync immediately
      if (!storedTz || storedTz !== detectedTz) {
        console.log('[TZ] Syncing timezone:', detectedTz);
        syncTimezone();
      } else {
        console.log('[TZ] Timezone already set:', storedTz);
      }
    }
  }

  // Handle both DOMContentLoaded and immediate execution
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Also sync on visibility change (in case timezone changes dynamically)
  document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
      const detectedTz = detectTimezone();
      const storedTz = localStorage.getItem('user_timezone');
      
      if (detectedTz !== storedTz) {
        console.log('[TZ] Timezone changed, re-syncing');
        syncTimezone();
      }
    }
  });

  // Expose timezone detection globally for debugging
  window.TimezoneDetector = {
    detect: detectTimezone,
    sync: syncTimezone,
    current: detectTimezone()
  };
})();
