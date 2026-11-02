/* Redirect stale admin sessions to a first-party MFA challenge after a protected API call. */
(() => {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const response = await nativeFetch(...args);
    if (response.status !== 403) return response;
    const target = args[0] instanceof Request ? args[0].url : String(args[0]);
    if (target.includes('/api/auth/mfa/')) return response;
    try {
      const payload = await response.clone().json();
      if (payload && payload.error_code === 'mfa_step_up_required') {
        const returnTo = window.location.pathname + window.location.search;
        window.location.assign('/security/step-up?return_to=' + encodeURIComponent(returnTo));
      } else if (payload && payload.error_code === 'mfa_enrollment_required') {
        window.location.assign('/security/setup');
      }
    } catch (_) {}
    return response;
  };
})();
