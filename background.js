// Rebuilt HTTP Analyzer - Stable Working Version
// Minimal, reliable, single-file background logic
// Features: request + response capture, headers, simple UI, clear + export, persistence

console.log('[HTTP Analyzer] Background starting...');
// Track tabs where the panel should persist
const activeTabs = new Set();
// Per-tab panel position: 'right' or 'left'
const activePanelPosition = new Map();

// In-memory store
let store = [];
const MAX_ITEMS = 50;
let filterDomain = null; // e.g. example.com (matches exact or subdomains)

// Rate-limit tracking: map key -> count of recent 429s (key = host|path)
const recent429 = new Map();
const RECENT_429_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

// Hold timestamps for cleanup: key -> array of timestamps
const recent429Times = new Map();

// --- Tagging / Scoring Rules ----------------------------------------------
// Lightweight rules to identify interesting endpoints.
const SENSITIVE_PARAM_RE = /\b(pass(word)?|token|jwt|api_?key|secret|session|csrf|sso|saml|code|state|redirect_uri|returnUrl|grant_type|file|upload|private_key|credit_card|ssn)\b/i;
const pathRe = (r) => new RegExp(r, 'i');
function getHeader(headers, name) {
	const h = (headers || []).find(x => x.name?.toLowerCase() === name.toLowerCase());
	return h?.value || '';
}
function hasHeader(headers, name, re) {
	const v = getHeader(headers, name);
	return re ? re.test(v) : !!v;
}

const RULES = [
	{ id: 'AUTH_LOGIN', label: 'AUTH', weight: 30, test: (r) => pathRe('/(login|signin|auth|oauth|oidc|saml|token|sessions?)').test(r.path) },
	{ id: 'AUTH_TOKEN', label: 'AUTH', weight: 20, test: (r) => hasHeader(r.reqHeaders, 'Authorization') || /(^|;)\s*session/i.test(r.reqCookie || '') },
	{ id: 'OAUTH', label: 'OAUTH', weight: 25, test: (r) => pathRe('/(authorize|callback)').test(r.path) || /openid|scope/i.test(r.query || '') },
	{ id: 'ACCOUNT', label: 'ACCOUNT', weight: 15, test: (r) => pathRe('/(me|profile|account|settings|user|reset-password)').test(r.path) },
	{ id: 'FILE_UPLOAD', label: 'UPLOAD', weight: 20, test: (r) => pathRe('/(upload|import)').test(r.path) || hasHeader(r.reqHeaders, 'Content-Type', /multipart\/form-data/i) },
	{ id: 'ADMIN_PATH', label: 'ADMIN', weight: 25, test: (r) => pathRe('/(admin|root|debug|status|metrics|actuator|health|graphiql|playground)').test(r.path) },
	{ id: 'GRAPHQL', label: 'GRAPHQL', weight: 20, test: (r) => pathRe('/graphql').test(r.path) || hasHeader(r.reqHeaders, 'Content-Type', /graphql/i) },
	{ id: 'WEBSOCKET', label: 'WS', weight: 20, test: (r) => hasHeader(r.reqHeaders, 'Upgrade', /websocket/i) || /^wss?:\/\//i.test(r.url) },
	{ id: 'CORS_WIDE', label: 'CORS', weight: 10, test: (r) => hasHeader(r.resHeaders, 'Access-Control-Allow-Origin', /^\s*\*\s*$/) },
	{ id: 'SENSITIVE_PARAMS', label: 'SENSITIVE', weight: 20, test: (r) => SENSITIVE_PARAM_RE.test(r.query || '') || SENSITIVE_PARAM_RE.test(r.bodyText || '') },
	{ id: 'PII', label: 'PII', weight: 25, test: (r) => /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/.test(r.bodyText || '') || /\b\d{3}-\d{2}-\d{4}\b/.test(r.bodyText || '') }, // email or SSN in body
	{ id: 'TECH', label: 'TECH', weight: 10, test: (r) => hasHeader(r.resHeaders, 'Server') || hasHeader(r.resHeaders, 'X-Powered-By') },
	{ id: 'FRAMEWORK', label: 'FRAMEWORK', weight: 10, test: (r) => hasHeader(r.resHeaders, 'X-AspNet-Version') || /react|angular|vue/i.test(r.bodyText || '') },
	{ id: 'CDN', label: 'CDN', weight: 5, test: (r) => /cloudfront|akamai|fastly/i.test(r.host) },
	{ id: 'ERROR_STATUS', label: 'ERROR', weight: 10, test: (r) => (r.status || 0) >= 400 },
	{ id: 'RATE_LIMIT', label: 'RATE-LIMIT', weight: 18, test: (r) => !!r.recent429 },
	{ id: 'EXPORT_DOWNLOAD', label: 'EXPORT', weight: 10, test: (r) => pathRe('/(export|download)').test(r.path) || /\.(csv|xlsx?|zip)$/i.test(r.path) },
];

function computeTagsAndScore(rec) {
	let u;
	try { u = new URL(rec.url); } catch (e) { u = { pathname: rec.url || '', search: '' }; }
	const r = {
		url: rec.url,
		path: u.pathname || '',
		method: rec.method || 'GET',
		query: u.search || '',
		bodyText: rec.requestBody ? JSON.stringify(rec.requestBody) : '',
		reqHeaders: rec.requestHeaders || [],
		resHeaders: rec.response?.responseHeaders || [],
		status: rec.response?.statusCode || 0,
		reqCookie: getHeader(rec.requestHeaders, 'Cookie') || ''
	};

	const tags = [];
	let score = 0;
	for (const rule of RULES) {
		try {
			if (rule.test(r)) { tags.push(rule.label); score += rule.weight; }
		} catch (e) { /* ignore rule errors */ }
	}
	const uniqueTags = Array.from(new Set(tags));
	return { tags: uniqueTags, score };
}

// Helper: push entry safely
function addOrUpdateRequest(details) {
	let existing = store.find(r => r.id === details.requestId);
	if (!existing) {
		existing = {
			id: details.requestId,
			method: details.method,
			url: details.url,
			host: (()=>{try{return new URL(details.url).host;}catch(e){return ''}})(),
			timestamp: Date.now(),
			requestHeaders: details.requestHeaders || [],
			requestBody: details.requestBody || null,
			response: null,
			tags: [],
			score: 0
		};
		store.unshift(existing);
		if (store.length > MAX_ITEMS) store.pop();
		// Initial classification
		const deco = computeTagsAndScore(existing);
		existing.tags = deco.tags; existing.score = deco.score;
	} else {
		// Merge request headers/body if late
		if (details.requestHeaders) existing.requestHeaders = details.requestHeaders;
		if (details.requestBody) existing.requestBody = details.requestBody;
		// Re-classify on update
		const deco = computeTagsAndScore(existing);
		existing.tags = deco.tags; existing.score = deco.score;
	}
}

// Request capture (headers + optional body meta)
chrome.webRequest.onBeforeSendHeaders.addListener(
	details => {
		if (details.url.startsWith('chrome-extension://') || details.url.startsWith('chrome://')) return;
		addOrUpdateRequest(details);
	},
	{ urls: ['<all_urls>'] },
	['requestHeaders', 'extraHeaders']
);

// Capture request body for sensitive param detection
chrome.webRequest.onBeforeRequest.addListener(
	details => {
		if (details.url.startsWith('chrome-extension://') || details.url.startsWith('chrome://')) return;
		const entry = store.find(r => r.id === details.requestId);
		if (entry && details.requestBody) {
			entry.requestBody = details.requestBody;
			// Re-classify with body
			const deco = computeTagsAndScore(entry);
			entry.tags = deco.tags; entry.score = deco.score;
		}
	},
	{ urls: ['<all_urls>'] },
	['requestBody']
);

// Response capture
chrome.webRequest.onResponseStarted.addListener(
	details => {
		const entry = store.find(r => r.id === details.requestId);
		if (entry) {
			entry.response = {
				statusCode: details.statusCode,
				statusLine: details.statusLine || `HTTP ${details.statusCode}`,
				responseHeaders: details.responseHeaders || [],
				timestamp: Date.now(),
				fromCache: !!details.fromCache
			};
			// Re-classify when response arrives
			const deco = computeTagsAndScore(entry);
			entry.tags = deco.tags; entry.score = deco.score;
		}
			// RATE-LIMIT tracking: if 429, increment bucket for host+path
			if (details.statusCode === 429) {
				try {
					const key = (()=>{try{return new URL(details.url).host + '|' + new URL(details.url).pathname;}catch(e){return details.url;}})();
					const now = Date.now();
					if (!recent429Times.has(key)) recent429Times.set(key, []);
					recent429Times.get(key).push(now);
					// prune older than window
					recent429Times.set(key, recent429Times.get(key).filter(ts => ts > now - RECENT_429_WINDOW_MS));
					recent429.set(key, recent429Times.get(key).length);
					// mark any store entries matching this key
					store.forEach(s => {
						try { const k2 = new URL(s.url).host + '|' + new URL(s.url).pathname; if (k2 === key) { s.recent429 = true; const deco2 = computeTagsAndScore(s); s.tags = deco2.tags; s.score = deco2.score; } } catch(e){}
					});
				} catch (e) { /* ignore */ }
			}
	},
	{ urls: ['<all_urls>'] },
	['responseHeaders', 'extraHeaders']
);

// Simple UI injection
function inject(tabId) {
	const side = activePanelPosition.get(tabId) || 'right';
	chrome.tabs.executeScript(tabId, {
		code: `
			(function(){
				const _side = '${side}';
				if (document.getElementById('http-analyzer-panel')) return;
				const root = document.createElement('div');
				root.id = 'http-analyzer-panel';
				root.innerHTML = \
					'<div style="position:fixed;top:0;'+(_side==='right'? 'right:0;':'left:0;')+'width:500px;height:100vh;z-index:2147483647;' +
					'background:#0a0a0a;color:#e0e0e0;font:11px Consolas,Monaco,monospace;' +
					(_side==='right'? 'border-left:3px solid #00ff41;box-shadow:-4px 0 16px rgba(0,0,0,.6);' : 'border-right:3px solid #00ff41;box-shadow:4px 0 16px rgba(0,0,0,.6);') +
					'display:flex;flex-direction:column;">' +
						'<div style="padding:8px 10px;background:#111;border-bottom:2px solid #00ff41;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">' +
							'<span style="color:#00ff41;font-size:13px;font-weight:700;letter-spacing:.5px;">HTTP ANALYZER</span>' +
							'<input id="http-filter-input" placeholder="domain" title="Limit display to domain (matches subdomains)" style="background:#000;color:#00ff41;border:1px solid #00ff41;padding:4px 6px;font-size:10px;width:120px;border-radius:3px;" />' +
							'<button id="http-filter-set" style="background:#002200;color:#00ff41;border:1px solid #00ff41;padding:4px 6px;cursor:pointer;font-size:10px;">SET</button>' +
							'<button id="http-filter-clear" style="background:#222;color:#ccc;border:1px solid #555;padding:4px 6px;cursor:pointer;font-size:10px;">CLR</button>' +
							'<button id="http-toggle-side" style="background:#222;color:#00ff41;border:1px solid #00ff41;padding:4px 6px;cursor:pointer;font-size:10px;">'+(_side==='right'? 'Move Left':'Move Right')+'</button>' +
							'<button id="http-clear" style="margin-left:auto;background:#222;color:#00ff41;border:1px solid #00ff41;padding:4px 8px;cursor:pointer;font-size:10px;">CLEAR</button>' +
							'<button id="http-export" style="background:#222;color:#00ff41;border:1px solid #00ff41;padding:4px 8px;cursor:pointer;font-size:10px;">EXPORT</button>' +
							'<button id="http-close" style="background:#331010;color:#ff5555;border:1px solid #882222;padding:4px 8px;cursor:pointer;font-size:10px;">X</button>' +
						'</div>' +
						'<div id="http-body" style="flex:1;overflow-y:auto;padding:10px 12px;line-height:1.3;background:#050505;"><div style="color:#555;text-align:center;padding:25px;font-size:12px;">Waiting for traffic...</div></div>' +
					'</div>';
				document.body.appendChild(root);
				if (_side === 'right') { document.body.style.marginRight = '480px'; document.body.style.marginLeft = ''; }
				else { document.body.style.marginLeft = '480px'; document.body.style.marginRight = ''; }

				function formatHeaders(arr, color){
					if(!arr||!arr.length) return '<div style="color:#555;font-style:italic;padding:4px 0;">(none)</div>';
					return arr.map(h => '<div style="display:flex;gap:8px;align-items:flex-start;padding:2px 0;">' +
							'<span style="color:'+color+';font-weight:600;min-width:110px;overflow:hidden;text-overflow:ellipsis;">'+escapeHtml(h.name)+':</span>' +
							'<span style="color:#ccc;overflow-wrap:anywhere;word-break:break-word;max-width:calc(100% - 120px);">'+escapeHtml(h.value||'')+'</span>' +
						'</div>').join('');
				}

				// Escape HTML to avoid injected content breaking the panel
				function escapeHtml(s){
					if (s === null || s === undefined) return '';
					s = String(s);
					return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
				}
				function escAttr(s){ return escapeHtml(s).replace(/"/g,'&quot;'); }

				function fmtTime(t){const d=new Date(t);return d.toLocaleTimeString();}

				function render(data){
					// Maintain only ids that still exist
					if (window.__httpOpenIds) {
						window.__httpOpenIds = new Set(Array.from(window.__httpOpenIds).filter(id => data.some(it => it.id == id)));
					} else {
						window.__httpOpenIds = new Set();
					}
					if(!data.length){
						body.innerHTML='<div style="color:#555;text-align:center;padding:25px;font-size:12px;">No HTTP requests captured yet.</div>';
						return;
					}
					body.innerHTML = data.map(item=>{
						const sc = item.response? item.response.statusCode: null;
						const statusColor = !sc? '#444' : (sc>=500? '#ff3366' : sc>=400? '#ff8844' : sc>=300? '#ffaa33' : '#44dd55');
						const score = item.score||0;
						const scoreBorder = score>=40? '#ff3366' : score>=25? '#ffaa33' : score>=15? '#44dd55' : '#555';
						const isOpen = window.__httpOpenIds.has(item.id);
						const arrow = '<span class="exp-arrow" style="display:inline-block;transition:transform .2s;color:#888;margin-right:6px;'+(isOpen?'transform:rotate(90deg);':'')+'">▶</span>';
						return '<div style="border:1px solid #1d1d1d;margin:10px 0;border-radius:6px;background:#101010;overflow:hidden;position:relative;">' +
							'<div class="row" style="display:flex;align-items:center;gap:6px;padding:9px 10px;cursor:pointer;background:linear-gradient(90deg,#121212,#0d0d0d);border-left:4px solid '+(sc?statusColor:'#222')+';" data-id="'+item.id+'">' +
								arrow +
								'<span style="display:inline-block;padding:3px 8px;border-radius:10px;font-size:10px;font-weight:700;background:#222;color:#00ff41;min-width:46px;text-align:center;">'+item.method+'</span>' +
								(sc? '<span style="display:inline-block;padding:3px 8px;border-radius:10px;font-size:10px;font-weight:700;background:'+statusColor+';color:#000;min-width:46px;text-align:center;">'+sc+'</span>' : '<span style="color:#666;font-size:10px;padding:3px 6px;">[...]</span>') +
								'<span title="'+escAttr(item.url)+'" style="flex:1;min-width:0;font-size:11px;color:#e0e0e0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">'+escapeHtml(item.url)+'</span>' +
								((item.tags && item.tags.length) ? item.tags.map(function(t){ return '<span style="background:#1b1b1b;color:#9fd;border:1px solid #2a2;padding:2px 6px;border-radius:8px;font-size:9px;">'+t+'</span>'; }).join('') : '') +
								'<span style="background:#222;color:#fff;border:1px solid '+scoreBorder+';padding:2px 6px;border-radius:10px;font-size:10px;min-width:28px;text-align:center;">'+score+'</span>' +
								'<span style="color:#666;font-size:10px;">'+fmtTime(item.timestamp)+'</span>' +
							'</div>' +
							'<div id="details-'+item.id+'" style="display:'+(isOpen?'block':'none')+';padding:0 0 10px 0;background:#0c0c0c;border-top:1px solid #1d1d1d;">' +
								'<div style="padding:10px 14px 4px 18px;">' +
									'<div style="color:#00ff41;font-weight:700;margin:0 0 6px;font-size:11px;">REQUEST</div>' +
									'<div style="border:1px solid #1d1d1d;background:#090909;border-radius:4px;padding:8px 10px;">' +
										'<div style="color:#00ff41;font-weight:600;margin-bottom:4px;font-size:10px;opacity:.85;">HEADERS</div>' +
										formatHeaders(item.requestHeaders,'#00ff41') +
										(item.requestBody? '<div style="color:#00b7ff;font-weight:600;margin:10px 0 4px;font-size:10px;">BODY</div><pre style="background:#050505;border:1px solid #1d1d1d;padding:6px;border-radius:4px;overflow:auto;max-height:140px;white-space:pre-wrap;color:#ccc;">'+escapeHtml(JSON.stringify(item.requestBody, null, 2))+'</pre>' : '') +
									'</div>' +
								'</div>' +
								'<div style="padding:4px 14px 0 34px;position:relative;">' +
									'<div style="position:absolute;left:20px;top:10px;bottom:15px;width:2px;background:linear-gradient(#1d1d1d,#222);"></div>' +
									'<div style="color:#44dd55;font-weight:700;margin:4px 0 6px;font-size:11px;">RESPONSE</div>' +
									(item.response ? (
										'<div style="border:1px solid #1d1d1d;background:#0a120a;border-radius:4px;padding:8px 10px;">' +
											'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
												'<span style="background:'+statusColor+';color:#000;padding:3px 8px;border-radius:12px;font-size:10px;font-weight:700;">'+sc+'</span>' +
												'<span style="color:#888;font-size:10px;">'+escapeHtml(item.response.statusLine||'')+'</span>' +
												'</div>' +
											'<div style="color:#44dd55;font-weight:600;margin-bottom:4px;font-size:10px;opacity:.85;">HEADERS</div>' +
											formatHeaders(item.response.responseHeaders,'#44dd55') +
										'</div>'
									) : '<div style="color:#555;font-size:10px;font-style:italic;">Awaiting response...</div>') +
								'</div>' +
							'</div>' +
						'</div>';
					}).join('');

					// Attach row handlers
					body.querySelectorAll('.row').forEach(row => {
						row.addEventListener('click', () => {
							const d = document.getElementById('details-'+row.dataset.id);
							if (d) {
								const willOpen = d.style.display==='none';
								d.style.display = willOpen? 'block':'none';
								if (!window.__httpOpenIds) window.__httpOpenIds = new Set();
								if (willOpen) window.__httpOpenIds.add(row.dataset.id); else window.__httpOpenIds.delete(row.dataset.id);
							}
							const arrowEl = row.querySelector('.exp-arrow');
							if (arrowEl) {
								if (d && d.style.display==='block') { arrowEl.style.transform='rotate(90deg)'; }
								else { arrowEl.style.transform='rotate(0deg)'; }
							}
						});
					});
				}

				const body = document.getElementById('http-body');
				const filterInput = document.getElementById('http-filter-input');
				document.getElementById('http-filter-set').onclick = ()=>chrome.runtime.sendMessage({action:'setFilter', value: filterInput.value});
				document.getElementById('http-filter-clear').onclick = ()=>{ filterInput.value=''; chrome.runtime.sendMessage({action:'setFilter', value:''}); };
				document.getElementById('http-clear').onclick = ()=>chrome.runtime.sendMessage({action:'clear'});
				document.getElementById('http-export').onclick = ()=>chrome.runtime.sendMessage({action:'export'});
				document.getElementById('http-close').onclick = ()=>{ root.remove(); document.body.style.marginRight=''; document.body.style.marginLeft=''; };
				document.getElementById('http-toggle-side').onclick = ()=>{
					const newSide = (_side === 'right') ? 'left' : 'right';
					chrome.runtime.sendMessage({action:'setPosition', value: newSide}, res => {
						if (res && res.ok) {
							// update DOM in-place
							if (newSide === 'left') {
								root.style.left = '0'; root.style.right = ''; root.style.borderLeft = '';
								root.style.borderRight = '3px solid #00ff41';
								document.body.style.marginLeft = '480px'; document.body.style.marginRight = '';
								document.getElementById('http-toggle-side').textContent = 'Move Right';
							} else {
								root.style.right = '0'; root.style.left = ''; root.style.borderRight = '';
								root.style.borderLeft = '3px solid #00ff41';
								document.body.style.marginRight = '480px'; document.body.style.marginLeft = '';
								document.getElementById('http-toggle-side').textContent = 'Move Left';
							}
						}
					});
				};
				// Load existing filter
				chrome.runtime.sendMessage({action:'getFilter'}, res => { if(res && res.value){ filterInput.value = res.value; } });

				// Poll background for data every 3s
				function poll(){
					chrome.runtime.sendMessage({action:'snapshot'}, res => { if(res && res.data) render(res.data); });
				}
				poll();
				setInterval(poll, 3000);
			})();
		`
		}, () => {
			if (chrome.runtime.lastError) {
				console.error('[HTTP Analyzer] Inject error:', chrome.runtime.lastError.message);
			} else {
				console.log('[HTTP Analyzer] UI injected (tab ' + tabId + ')');
				activeTabs.add(tabId);
			}
		});
}

// Browser action click -> inject
chrome.browserAction.onClicked.addListener(tab => {
	// If already active, do nothing (panel will auto reappear after reload)
	if (!activeTabs.has(tab.id)) {
		console.log('[HTTP Analyzer] Activating persistence on tab', tab.id);
		inject(tab.id);
	} else {
		// Optionally could toggle off; keeping persistent per request
		console.log('[HTTP Analyzer] Already active on tab', tab.id, '- reinjecting if needed');
		inject(tab.id);
	}
});

// Re-inject after page reload / navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
	if (activeTabs.has(tabId) && changeInfo.status === 'complete') {
		console.log('[HTTP Analyzer] Tab reload/navigation detected, ensuring panel present (tab ' + tabId + ')');
		inject(tabId);
	}
});

// Clean up closed tabs
chrome.tabs.onRemoved.addListener(tabId => {
	if (activeTabs.delete(tabId)) {
		console.log('[HTTP Analyzer] Cleaned up closed tab', tabId);
	}
	// cleanup position map too
	if (activePanelPosition.has(tabId)) activePanelPosition.delete(tabId);
});

// Messaging API
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
	if (msg.action === 'snapshot') {
		let data = store;
		if (filterDomain) {
			data = data.filter(item => {
				const h = item.host || (()=>{try{return new URL(item.url).host;}catch(e){return ''}})();
				if (!h) return false;
				return h === filterDomain || h.endsWith('.' + filterDomain);
			});
		}
		sendResponse({data: data.slice(0, MAX_ITEMS)});
	} else if (msg.action === 'clear') {
		store = [];
		sendResponse({ok:true});
	} else if (msg.action === 'setFilter') {
		filterDomain = (msg.value || '').trim() || null;
		sendResponse({ok:true, value: filterDomain});
	} else if (msg.action === 'setPosition') {
		// set position for the sender tab
		if (sender && sender.tab && typeof msg.value === 'string') {
			activePanelPosition.set(sender.tab.id, msg.value === 'left' ? 'left' : 'right');
			sendResponse({ok:true});
		} else sendResponse({ok:false});
	} else if (msg.action === 'getPosition') {
		if (sender && sender.tab) sendResponse({value: activePanelPosition.get(sender.tab.id) || 'right'});
		else sendResponse({value: 'right'});
	} else if (msg.action === 'getFilter') {
		sendResponse({value: filterDomain});
	} else if (msg.action === 'export') {
		const blob = new Blob([JSON.stringify(store, null, 2)], {type:'application/json'});
		const url = URL.createObjectURL(blob);
		chrome.downloads.download({ url, filename: 'http_analyzer_export.json', saveAs: true });
		sendResponse({ok:true});
	}
	return true;
});

console.log('[HTTP Analyzer] Ready. Click the extension icon on a page to open the panel.');

// Periodic cleanup of recent429Times to keep memory bounded
setInterval(() => {
	const now = Date.now();
	for (const [key, arr] of recent429Times.entries()) {
		const pruned = arr.filter(ts => ts > now - RECENT_429_WINDOW_MS);
		if (pruned.length) recent429Times.set(key, pruned);
		else { recent429Times.delete(key); recent429.delete(key); }
	}
}, 60 * 1000);

