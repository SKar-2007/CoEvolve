// ========================================
// CoEvolve — Frontend Scripts (SSE)
// ========================================

// ---- SCROLL REVEAL ----
document.addEventListener('DOMContentLoaded', () => {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

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

// ---- AGENT STATUS ----
function setAgentStatus(agent, status, msg) {
    const row = document.getElementById(`agent-${agent}`);
    if (!row) return;
    row.className = `agent-row ${status}`;
    row.querySelector('.agent-msg').textContent = msg;
}

function resetAgents() {
    ['attacker', 'developer', 'judge', 'distiller'].forEach(a => {
        setAgentStatus(a, '', 'Idle');
    });
}

// ---- ELO UPDATE ----
function updateElo(before, after) {
    document.getElementById('elo-attacker').textContent = Math.round(after.attacker || before[0]);
    document.getElementById('elo-developer').textContent = Math.round(after.developer || before[1]);
}

// ---- DEMO: RUN EPISODE (SSE) ----
async function runEpisode() {
    const btn = document.getElementById('run-btn');
    const output = document.getElementById('output');
    const apiUrl = document.getElementById('api-url').value;
    const vulnClass = document.getElementById('vuln-class').value;
    const lang = document.getElementById('lang').value;

    btn.disabled = true;
    btn.textContent = 'RUNNING...';
    output.innerHTML = '';
    resetAgents();

    const log = (msg, cls = '') => {
        const line = document.createElement('div');
        line.className = `term-line ${cls}`;
        line.textContent = msg;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    };

    log(`> Starting episode...`, 'info');
    log(`> Vuln: ${vulnClass} | Lang: ${lang}`, 'info');
    log('', '');

    try {
        const evtSource = new EventSource(
            `${apiUrl}/training/stream?vulnerability_class=${vulnClass}&language=${lang}`
        );

        evtSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            switch (data.type) {
                case 'start':
                    log(`> Episode started`, 'info');
                    updateElo(data.elo, data.elo);
                    break;

                case 'agent':
                    setAgentStatus(data.agent, data.status, data.message);
                    if (data.status === 'working') {
                        log(`> ${data.agent.toUpperCase()}: ${data.message}`, 'info');
                    } else if (data.status === 'done') {
                        log(`> ${data.agent.toUpperCase()}: ${data.message}`, 'success');
                    }
                    break;

                case 'elo':
                    updateElo(data.before, data.after);
                    log(`> Elo updated: ATK ${Math.round(data.after.attacker)} | DEV ${Math.round(data.after.developer)}`, 'info');
                    break;

                case 'complete':
                    log('', '');
                    log('=== COMPLETE ===', 'success');
                    log(`ID:       ${data.episode_id}`);
                    log(`Outcome:  ${data.outcome === 1 ? 'VULNERABLE' : 'SECURE'}`, data.outcome === 1 ? 'error' : 'success');
                    log(`Rule:     ${data.rule_distilled ? 'YES' : 'NO'}`, data.rule_distilled ? 'info' : '');
                    log(`Duration: ${data.duration_s}s`);
                    evtSource.close();
                    btn.disabled = false;
                    btn.textContent = 'RUN';
                    break;

                case 'error':
                    log(`ERROR: ${data.message}`, 'error');
                    setAgentStatus('judge', 'error', 'Failed');
                    evtSource.close();
                    btn.disabled = false;
                    btn.textContent = 'RUN';
                    break;
            }
        };

        evtSource.onerror = () => {
            log('Connection lost. Retrying...', 'error');
            evtSource.close();
            btn.disabled = false;
            btn.textContent = 'RUN';
        };

    } catch (err) {
        log(`ERROR: ${err.message}`, 'error');
        log('Start API: make run-api', 'info');
        btn.disabled = false;
        btn.textContent = 'RUN';
    }
}

window.runEpisode = runEpisode;
