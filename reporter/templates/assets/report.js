/**
 * Security Report Interactive Features
 * Provides JSON viewing, copying, and interactivity
 */

// Store raw data sections
let rawData = {};

/**
 * Initialize the report
 */
function initReport(data) {
    rawData = data;
    console.log('Security Report initialized with', Object.keys(data).length, 'sections');
}

/**
 * Show JSON modal for a specific section
 */
function showJSON(sectionId) {
    const modal = document.getElementById('json-modal');
    const content = document.getElementById('json-content');
    const title = document.getElementById('json-title');
    
    if (!modal || !content) {
        console.error('JSON modal elements not found');
        return;
    }
    
    // Get section data
    const sectionData = rawData[sectionId];
    
    if (!sectionData) {
        content.innerHTML = '<p style="color: red;">Dados não encontrados para esta seção.</p>';
    } else {
        // Format JSON with syntax highlighting
        content.innerHTML = syntaxHighlight(JSON.stringify(sectionData, null, 2));
    }
    
    // Update title
    const sectionTitles = {
        'full': 'Dados Completos do Relatório',
        'metrics': 'Todas as Métricas',
        'ports': 'Dados de Portas e Conexões',
        'authentication': 'Dados de Autenticação',
        'firewall': 'Dados de Firewall e SELinux',
        'vulnerabilities': 'Dados de Vulnerabilidades',
        'network': 'Dados de Rede',
        'permissions': 'Dados de Permissões',
        'alerts': 'Todos os Alertas'
    };
    
    if (title) {
        title.textContent = sectionTitles[sectionId] || 'Dados Brutos';
    }
    
    // Show modal
    modal.classList.add('active');
    
    // Prevent body scroll
    document.body.style.overflow = 'hidden';
}

/**
 * Close JSON modal
 */
function closeJSON() {
    const modal = document.getElementById('json-modal');
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = 'auto';
    }
}

/**
 * Copy JSON content to clipboard
 */
function copyJSON() {
    const content = document.getElementById('json-content');
    if (!content) return;
    
    // Get plain text (remove HTML formatting)
    const text = content.innerText || content.textContent;
    
    // Copy to clipboard
    navigator.clipboard.writeText(text).then(() => {
        // Show feedback
        const btn = document.querySelector('.copy-btn');
        const originalText = btn.textContent;
        btn.textContent = '✓ Copiado!';
        btn.style.background = '#28a745';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
        }, 2000);
    }).catch(err => {
        console.error('Erro ao copiar:', err);
        alert('Erro ao copiar. Use Ctrl+C manualmente.');
    });
}

/**
 * Syntax highlighting for JSON
 */
function syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, 
        function (match) {
            let cls = 'json-number';
            
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                } else {
                    cls = 'json-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            
            return '<span class="' + cls + '">' + match + '</span>';
        }
    );
}

/**
 * Toggle expandable sections
 */
function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (!section) return;
    
    const isHidden = section.style.display === 'none';
    section.style.display = isHidden ? 'block' : 'none';
    
    // Update toggle icon
    const toggle = section.previousElementSibling.querySelector('.toggle-icon');
    if (toggle) {
        toggle.textContent = isHidden ? '▼' : '▶';
    }
}

/**
 * Smooth scroll to section
 */
function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

/**
 * Filter recommendations by priority
 */
function filterRecommendations(priority) {
    const recommendations = document.querySelectorAll('.recommendation');
    
    recommendations.forEach(rec => {
        if (priority === 'all' || rec.classList.contains('priority-' + priority)) {
            rec.style.display = 'block';
        } else {
            rec.style.display = 'none';
        }
    });
    
    // Update active filter button
    const buttons = document.querySelectorAll('.filter-btn');
    buttons.forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.priority === priority) {
            btn.classList.add('active');
        }
    });
}

/**
 * Export section as text
 */
function exportSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (!section) return;
    
    const text = section.innerText || section.textContent;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${sectionId}.txt`;
    a.click();
    
    URL.revokeObjectURL(url);
}

/**
 * Print report
 */
function printReport() {
    window.print();
}

/**
 * Initialize tooltips
 */
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    
    tooltips.forEach(el => {
        el.addEventListener('mouseenter', (e) => {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = el.dataset.tooltip;
            tooltip.style.position = 'absolute';
            tooltip.style.background = '#333';
            tooltip.style.color = 'white';
            tooltip.style.padding = '8px 12px';
            tooltip.style.borderRadius = '5px';
            tooltip.style.fontSize = '0.85em';
            tooltip.style.zIndex = '10000';
            tooltip.style.pointerEvents = 'none';
            
            document.body.appendChild(tooltip);
            
            const rect = el.getBoundingClientRect();
            tooltip.style.left = rect.left + 'px';
            tooltip.style.top = (rect.top - tooltip.offsetHeight - 5) + 'px';
            
            el._tooltip = tooltip;
        });
        
        el.addEventListener('mouseleave', (e) => {
            if (el._tooltip) {
                el._tooltip.remove();
                el._tooltip = null;
            }
        });
    });
}

/**
 * Close modal when clicking outside
 */
document.addEventListener('click', (e) => {
    const modal = document.getElementById('json-modal');
    if (modal && e.target === modal) {
        closeJSON();
    }
});

/**
 * Keyboard shortcuts
 */
document.addEventListener('keydown', (e) => {
    // ESC to close modal
    if (e.key === 'Escape') {
        closeJSON();
    }
    
    // Ctrl/Cmd + P to print
    if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
        e.preventDefault();
        printReport();
    }
});

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log('Security Report JavaScript loaded');
    initTooltips();
    
    // Add smooth scroll behavior
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
    
    // Add animation on scroll
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });
    
    document.querySelectorAll('.section').forEach(section => {
        section.style.opacity = '0';
        section.style.transform = 'translateY(20px)';
        section.style.transition = 'opacity 0.6s, transform 0.6s';
        observer.observe(section);
    });
});

console.log('🔒 Security Report - Modo Local v1.0');
