'use strict';

// No inline handlers: the CSP allows only scripts from the same origin.
document.addEventListener('click', function (event) {
  var button = event.target.closest('[data-copy]');
  if (!button) return;
  var field = document.getElementById(button.getAttribute('data-copy'));
  if (!field) return;
  var original = button.textContent;
  var done = function () {
    button.textContent = 'Copied';
    setTimeout(function () { button.textContent = original; }, 2000);
  };
  field.select();
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(field.value).then(done, function () { document.execCommand('copy'); done(); });
  } else {
    document.execCommand('copy');
    done();
  }
});

document.addEventListener('focusin', function (event) {
  if (event.target.matches('input[readonly]')) event.target.select();
});

document.addEventListener('submit', function (event) {
  var message = event.target.getAttribute('data-confirm');
  if (message && !window.confirm(message)) event.preventDefault();
});
