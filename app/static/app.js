// Auto-refresh every 30 seconds
setTimeout(() => window.location.reload(), 30000);

// Collapsible check sections
document.querySelectorAll('.check-section-header').forEach(h => {
  h.addEventListener('click', () => {
    const body = h.nextElementSibling;
    body.style.display = body.style.display === 'none' ? 'block' : 'none';
  });
});
