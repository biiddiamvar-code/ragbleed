(function () {
  var SCRIPT_TAG = document.currentScript;
  var TARGET_ID = (SCRIPT_TAG && SCRIPT_TAG.getAttribute('data-target')) || 'ragbleed-widget';
  var COUNT = parseInt((SCRIPT_TAG && SCRIPT_TAG.getAttribute('data-count')) || '5', 10);
  var API_URL = 'https://ragbleed.com/api/latest.json';

  var SEVERITY_COLOR = {
    low: '#4FD0C0',
    medium: '#E0A94D',
    high: '#B8394B'
  };

  function injectStyles() {
    if (document.getElementById('ragbleed-widget-styles')) return;
    var style = document.createElement('style');
    style.id = 'ragbleed-widget-styles';
    style.textContent = [
      '.ragbleed-w{font-family:ui-monospace,"IBM Plex Mono",monospace;background:#0E1013;border:1px solid #33373F;padding:16px;max-width:420px;}',
      '.ragbleed-w-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid #33373F;}',
      '.ragbleed-w-title{color:#F2EEE3;font-size:11px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;}',
      '.ragbleed-w-title a{color:#F2EEE3;text-decoration:none;}',
      '.ragbleed-w-badge{color:#B8394B;font-size:10px;}',
      '.ragbleed-w-row{display:block;text-decoration:none;padding:9px 0;border-bottom:1px solid #1A1D22;}',
      '.ragbleed-w-row:last-child{border-bottom:none;padding-bottom:0;}',
      '.ragbleed-w-meta{display:flex;gap:8px;align-items:center;font-size:10px;color:#9a9488;margin-bottom:4px;}',
      '.ragbleed-w-sev{display:inline-block;width:7px;height:7px;border-radius:50%;}',
      '.ragbleed-w-caseid{color:#9a9488;}',
      '.ragbleed-w-titletext{color:#B7B1A2;font-size:12.5px;line-height:1.4;font-family:Georgia,serif;}',
      '.ragbleed-w-row:hover .ragbleed-w-titletext{color:#F2EEE3;}',
      '.ragbleed-w-empty{color:#9a9488;font-size:12px;}'
    ].join('');
    document.head.appendChild(style);
  }

  function render(target, data) {
    var cases = (data.cases || []).slice(0, COUNT);
    var html = '<div class="ragbleed-w">';
    html += '<div class="ragbleed-w-head">';
    html += '<span class="ragbleed-w-title"><a href="https://ragbleed.com" target="_blank" rel="noopener">RAGBLEED<span style="color:#B8394B">.</span></a></span>';
    html += '<span class="ragbleed-w-badge">LATEST CASES</span>';
    html += '</div>';

    if (!cases.length) {
      html += '<div class="ragbleed-w-empty">No cases available.</div>';
    } else {
      cases.forEach(function (c) {
        var color = SEVERITY_COLOR[c.severity] || '#9a9488';
        html += '<a class="ragbleed-w-row" href="' + c.url + '" target="_blank" rel="noopener">';
        html += '<div class="ragbleed-w-meta">';
        html += '<span class="ragbleed-w-sev" style="background:' + color + '"></span>';
        html += '<span class="ragbleed-w-caseid">#' + c.caseId + '</span>';
        html += '<span>' + c.filedDisplay + '</span>';
        html += '</div>';
        html += '<div class="ragbleed-w-titletext">' + c.title + '</div>';
        html += '</a>';
      });
    }

    html += '</div>';
    target.innerHTML = html;
  }

  function init() {
    var target = document.getElementById(TARGET_ID);
    if (!target) return;
    injectStyles();
    target.innerHTML = '<div class="ragbleed-w"><div class="ragbleed-w-empty">Loading RAGBleed cases…</div></div>';

    fetch(API_URL)
      .then(function (res) { return res.json(); })
      .then(function (data) { render(target, data); })
      .catch(function () {
        target.innerHTML = '<div class="ragbleed-w"><div class="ragbleed-w-empty">Could not load RAGBleed cases.</div></div>';
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
