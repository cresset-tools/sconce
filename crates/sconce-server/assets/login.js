// Sign-in page: password show/hide toggle and a submit-in-progress label.
const form = document.getElementById('loginform');
const pw = form.querySelector('input[name=password]');
const toggle = document.getElementById('pwtoggle');

toggle.addEventListener('click', () => {
  const hidden = pw.type === 'password';
  pw.type = hidden ? 'text' : 'password';
  toggle.textContent = hidden ? 'Hide' : 'Show';
});

form.addEventListener('submit', () => {
  document.getElementById('loginsubmit').textContent = 'Signing in…';
});
