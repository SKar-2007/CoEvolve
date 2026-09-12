// ========================================
// CoEvolve — Frontend Scripts
// Scroll animations + API integration
// ========================================

// ---- SCROLL REVEAL ----
document.addEventListener('DOMContentLoaded', () => {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    document.querySelectorAll('.scroll-reveal').forEach(el => observer.observe(el));
});

// ---- SMOOTH SCROLL ----
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

// ---- DEMO: RUN EPISODE ----
async function runEpisode() {
    const btn = document.getElementById('run-btn');
    const output = document.getElementById('output');
    const apiUrl = document.getElementById('api-url').value;
    const vulnClass = document.getElementById('vuln-class').value;
    const lang = document.getElementById('lang').value;

    btn.disabled = true;
    btn.textContent = 'RUNNING...';
    output.innerHTML = '';

    const log = (msg, cls = '') => {
        const line = document.createElement('div');
        line.className = `terminal-line ${cls}`;
        line.textContent = msg;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    };

    log(`> Starting training episode...`, 'info');
    log(`> Vulnerability: ${vulnClass}`, 'info');
    log(`> Language: ${lang}`, 'info');
    log(`> API: ${apiUrl}`, 'info');
    log('', '');

    try {
        const resp = await fetch(`${apiUrl}/training/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                vulnerability_class: vulnClass,
                language: lang,
                context_hint: '',
                max_retries: 3,
                use_react: true
            })
        });

        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
        }

        const data = await resp.json();

        log('=== EPISODE COMPLETE ===', 'success');
        log('', '');
        log(`Episode ID:   ${data.episode_id}`);
        log(`Status:       ${data.status}`, data.status === 'completed' ? 'success' : 'error');
        log(`Difficulty:   Tier ${data.difficulty_tier}`);
        log(`Judge:        ${data.judge_outcome === 1 ? 'VULNERABLE' : 'SECURE'}`, data.judge_outcome === 1 ? 'error' : 'success');
        log(`Rule Distilled: ${data.rule_distilled ? 'YES' : 'NO'}`, data.rule_distilled ? 'info' : '');
        log(`Regression:   ${data.regression_passed ? 'PASSED' : 'FAILED'}`, data.regression_passed ? 'success' : 'error');
        log(`Duration:     ${data.duration_s}s`);
        log('', '');

        if (data.rule_text) {
            log('=== DISTILLED RULE ===', 'info');
            log(data.rule_text);
            log('', '');
        }

        log('=== ELO CHANGES ===', 'info');
        log(`Attacker: ${data.elo_before.attacker} → ${data.elo_after.attacker}`);
        log(`Developer: ${data.elo_before.developer} → ${data.elo_after.developer}`);

        // Update metrics
        updateMetrics(apiUrl);

    } catch (err) {
        log(`ERROR: ${err.message}`, 'error');
        log('', '');
        log('Make sure the API server is running:', '');
        log(`  cd "CoEvolve Sandbox" && make run-api`, 'info');
    }

    btn.disabled = false;
    btn.textContent = 'RUN EPISODE';
}

// ---- METRICS ----
async function updateMetrics(apiUrl) {
    try {
        const [metricsResp, eloResp] = await Promise.all([
            fetch(`${apiUrl}/metrics`),
            fetch(`${apiUrl}/elo`)
        ]);

        if (metricsResp.ok) {
            const m = await metricsResp.json();
            document.getElementById('m-episodes').textContent = m.total_episodes || 0;
            document.getElementById('m-secure').textContent = `${Math.round((m.secure_rate || 0) * 100)}%`;
            document.getElementById('m-rules').textContent = m.rules_count || 0;
        }

        if (eloResp.ok) {
            const e = await eloResp.json();
            document.getElementById('m-attacker').textContent = Math.round(e.attacker || 1500);
            document.getElementById('m-developer').textContent = Math.round(e.developer || 1500);
        }

        document.getElementById('m-status').textContent = 'ONLINE';
        document.getElementById('m-status').style.color = '#2ECC71';
    } catch (err) {
        document.getElementById('m-status').textContent = 'OFFLINE';
        document.getElementById('m-status').style.color = '#E63946';
    }
}

// ---- ELO CHART ----
let eloChart = null;

async function initChart(apiUrl) {
    const ctx = document.getElementById('eloChart');
    if (!ctx) return;

    try {
        const resp = await fetch(`${apiUrl}/elo/history`);
        if (!resp.ok) return;

        const data = await resp.json();
        const history = data.history || [];

        const labels = history.map((_, i) => `Ep ${i + 1}`);
        const attackerData = history.map(h => h.attacker || 1500);
        const developerData = history.map(h => h.developer || 1500);

        // If no history, show placeholder
        if (labels.length === 0) {
            labels.push('Start');
            attackerData.push(1500);
            developerData.push(1500);
        }

        if (eloChart) eloChart.destroy();

        eloChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {
                        label: 'Attacker Elo',
                        data: attackerData,
                        borderColor: '#E63946',
                        backgroundColor: 'rgba(230, 57, 70, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 3,
                        fill: false
                    },
                    {
                        label: 'Developer Elo',
                        data: developerData,
                        borderColor: '#FFD166',
                        backgroundColor: 'rgba(255, 209, 102, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 3,
                        fill: false
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#888',
                            font: { family: 'Rajdhani', size: 12 }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#555', font: { family: 'Rajdhani' } },
                        grid: { color: '#1E1E1E' }
                    },
                    y: {
                        ticks: { color: '#555', font: { family: 'Rajdhani' } },
                        grid: { color: '#1E1E1E' },
                        min: 1300,
                        max: 1700
                    }
                }
            }
        });
    } catch (err) {
        // Chart init failed — show placeholder
    }
}

// ---- INIT ----
document.addEventListener('DOMContentLoaded', () => {
    const apiUrl = document.getElementById('api-url')?.value || 'http://localhost:8000';
    updateMetrics(apiUrl);
    initChart(apiUrl);

    // Auto-refresh metrics every 30s
    setInterval(() => {
        const url = document.getElementById('api-url')?.value || 'http://localhost:8000';
        updateMetrics(url);
        initChart(url);
    }, 30000);
});

// Make runEpisode available globally
window.runEpisode = runEpisode;
