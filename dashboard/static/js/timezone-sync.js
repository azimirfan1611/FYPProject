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
    return 'UTC';
  }

  // Send timezone to server
  function syncTimezone() {
    const tz = detectTimezone();
    const xhr = new XMLHttpRequest();
    
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        if (xhr.status === 200) {
          console.log('[TZ] Timezone synced:', tz);
          // Store in localStorage as backup
          try {
            localStorage.setItem('user_timezone', tz);
          } catch (e) {
            // localStorage not available
          }
        } else {
          console.warn('[TZ] Failed to sync timezone:', xhr.status);
        }
      }
    };
    
    xhr.open('POST', '/api/set-timezone', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({ timezone: tz }));
  }

  // Run when document is ready
  function init() {
    // Only sync if user is authenticated (check for token in session)
    const isAuthenticated = document.body.dataset.authenticated === 'true' || 
                           document.querySelector('[data-authenticated="true"]') !== null ||
                           localStorage.getItem('auth_token');
    
    if (isAuthenticated) {
      syncTimezone();
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
      syncTimezone();
    }
  });

  // Expose timezone detection globally for debugging
  window.TimezoneDetector = {
    detect: detectTimezone,
    sync: syncTimezone,
    current: detectTimezone()
  };
})();
