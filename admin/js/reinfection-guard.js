jQuery(document).ready(function($) {
    var cy           = null;
    var maxSteps     = 15; // Safety cap for polling
    var currentSteps = 0;

    /**
     * Resolve full REST API URL safely across all WordPress permalink structures.
     */
    function getApiUrl(route) {
        var base = (typeof NEXURA_rg !== 'undefined' && NEXURA_rg.rest_url) ? NEXURA_rg.rest_url : '/wp-json/';
        base = base.replace(/\/+$/, '');
        route = route.replace(/^\/+/, '');
        if (base.indexOf('?') !== -1) {
            return base + '&rest_route=/' + route;
        }
        return base + '/' + route;
    }

    // Prevent accidental reload if enter key is pressed in target input
    $('#nexura_investigation_target').on('keydown', function(e) {
        if (e.which === 13) {
            e.preventDefault();
            $('#nexura_start_investigation').trigger('click');
        }
    });

    $('#nexura_start_investigation').on('click', function(e) {
        e.preventDefault();

        var targetFile = $('#nexura_investigation_target').val().trim();

        currentSteps = 0;
        updateStatus('Initializing investigation...');
        $('#nexura_investigation_progress_bar').css('width', '15%');
        $('#nexura_investigation_status').css('display', 'flex');
        $('#nexura_start_investigation').prop('disabled', true);
        $('#nexura_clear_investigation').hide();
        
        $('#nexura_reinfection_graph_container').html(
            '<div class="nexura-card nexura-fade-in">' +
                '<div class="nexura-rg-empty-state">' +
                    '<span class="spinner is-active" style="float:none;margin-bottom:14px;width:28px;height:28px;"></span>' +
                    '<h3 style="color:var(--nexura-text-primary);font-size:16px;font-weight:700;margin:0 0 6px 0;">Scanning Persistence Vectors...</h3>' +
                    '<p style="color:var(--nexura-text-muted);font-size:13.5px;margin:0;">Analyzing drop-ins, cron hooks, DB options, config files, and unauthorized file writers.</p>' +
                '</div>' +
            '</div>'
        );

        $.ajax({
            url:    getApiUrl('nexura/v1/reinfection/init'),
            method: 'POST',
            beforeSend: function(xhr) {
                if (typeof NEXURA_rg !== 'undefined' && NEXURA_rg.nonce) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_rg.nonce);
                }
            },
            data: { target_file: targetFile },
            success: function(response) {
                if (response && response.success) {
                    processNextStep();
                } else {
                    showError((response && response.message) || 'Failed to initialize investigation.');
                }
            },
            error: function(xhr) {
                var err = 'API error while initializing.';
                if (xhr.responseJSON && xhr.responseJSON.message) {
                    err += ' (' + xhr.responseJSON.message + ')';
                }
                showError(err);
            }
        });
    });

    /**
     * Poll the backend one step at a time.
     */
    function processNextStep() {
        currentSteps++;
        if (currentSteps > maxSteps) {
            showError('Investigation timed out. Please try again.');
            return;
        }

        var progressPct = Math.min(92, 15 + (currentSteps * 16));
        $('#nexura_investigation_progress_bar').css('width', progressPct + '%');

        $.ajax({
            url:    getApiUrl('nexura/v1/reinfection/step'),
            method: 'POST',
            beforeSend: function(xhr) {
                if (typeof NEXURA_rg !== 'undefined' && NEXURA_rg.nonce) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_rg.nonce);
                }
            },
            success: function(response) {
                if (!response || !response.success) {
                    showError((response && response.message) || 'Step failed.');
                    return;
                }

                if (response.done) {
                    $('#nexura_investigation_progress_bar').css('width', '100%');
                    updateStatus('Analysis complete. Rendering report...');
                    renderResults(response.report || {});
                    resetUI();
                } else {
                    var stepName = response.step || currentSteps;
                    updateStatus('Analyzing ' + stepName + ' persistence... (step ' + currentSteps + ')');
                    setTimeout(processNextStep, 350);
                }
            },
            error: function(xhr) {
                var err = 'API error during analysis step.';
                if (xhr.responseJSON && xhr.responseJSON.message) {
                    err += ' (' + xhr.responseJSON.message + ')';
                }
                showError(err);
            }
        });
    }

    /**
     * Render the investigation results in modular full-width cards.
     */
    function renderResults(report) {
        var container = $('#nexura_reinfection_graph_container');
        container.empty();
        $('#nexura_clear_investigation').show();

        if (!report || !report.evidence || report.evidence.length === 0) {
            container.html(
                '<div class="nexura-card nexura-fade-in">' +
                    '<div class="nexura-rg-empty-state">' +
                        '<div style="width:54px;height:54px;border-radius:50%;background:var(--nexura-green-bg);color:var(--nexura-green);display:flex;align-items:center;justify-content:center;margin:0 auto 16px auto;">' +
                            '<svg width="30" height="30" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>' +
                        '</div>' +
                        '<h3 style="color:var(--nexura-green);font-size:18px;margin:0 0 8px 0;font-weight:700;">Site Appears Clean</h3>' +
                        '<p style="color:var(--nexura-text-secondary);margin:0;font-size:14px;">No persistence mechanisms, hidden drop-ins, or malicious background triggers were detected.</p>' +
                    '</div>' +
                '</div>'
            );
            return;
        }

        var level = report.risk_level || report.overall_risk || 'Critical';
        var score = report.risk_score || 0;
        var count = report.evidence.length;
        var targetFile = report.target_file || 'Site-Wide Audit';

        var levelBadgeClass = 'critical';
        var kpiIconClass = 'critical';
        if (level === 'Low') {
            levelBadgeClass = 'safe';
            kpiIconClass = 'safe';
        } else if (level === 'Medium') {
            levelBadgeClass = 'warning';
            kpiIconClass = 'warning';
        }

        var isPro = (typeof NEXURA_rg !== 'undefined' && (NEXURA_rg.is_pro === true || NEXURA_rg.is_pro === 1 || NEXURA_rg.is_pro === '1' || NEXURA_rg.is_pro === 'true'));
        var upgradeUrl = (typeof NEXURA_rg !== 'undefined' && NEXURA_rg.upgrade_url) ? NEXURA_rg.upgrade_url : 'admin.php?page=nexura-pricing';

        var kpiTargetVal = targetFile;

        // 1. KPI Summary Ribbon (4 columns across full width)
        var kpiHtml =
            '<div class="nexura-rg-summary-ribbon nexura-fade-in">' +
                '<div class="nexura-rg-kpi-card">' +
                    '<div class="nexura-rg-kpi-icon ' + kpiIconClass + '">' +
                        '<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>' +
                    '</div>' +
                    '<div>' +
                        '<div class="nexura-rg-kpi-label">Risk Level</div>' +
                        '<div class="nexura-rg-kpi-val"><span class="nexura-badge ' + levelBadgeClass + '">' + level.toUpperCase() + '</span></div>' +
                    '</div>' +
                '</div>' +
                '<div class="nexura-rg-kpi-card">' +
                    '<div class="nexura-rg-kpi-icon ' + kpiIconClass + '">' +
                        '<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>' +
                    '</div>' +
                    '<div>' +
                        '<div class="nexura-rg-kpi-label">Risk Score</div>' +
                        '<div class="nexura-rg-kpi-val">' + score + '<span style="font-size:14px;color:var(--nexura-text-muted);font-weight:500;">/100</span></div>' +
                    '</div>' +
                '</div>' +
                '<div class="nexura-rg-kpi-card">' +
                    '<div class="nexura-rg-kpi-icon critical">' +
                        '<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>' +
                    '</div>' +
                    '<div>' +
                        '<div class="nexura-rg-kpi-label">Persistence Vectors</div>' +
                        '<div class="nexura-rg-kpi-val">' + count + ' Detected</div>' +
                    '</div>' +
                '</div>' +
                '<div class="nexura-rg-kpi-card">' +
                    '<div class="nexura-rg-kpi-icon accent">' +
                        '<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>' +
                    '</div>' +
                    '<div style="min-width:0;">' +
                        '<div class="nexura-rg-kpi-label">Target Analyzed</div>' +
                        '<div class="nexura-rg-kpi-val" style="font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:monospace;color:var(--nexura-accent-light);">' + $('<div>').text(kpiTargetVal).html() + '</div>' +
                    '</div>' +
                '</div>' +
            '</div>';

        container.append(kpiHtml);

        // 2. Cytoscape Relationship Graph Card (Dedicated full-width card)
        var graphCard = $(
            '<div class="nexura-card nexura-fade-in" style="margin-bottom:24px;">' +
                '<h2>' +
                    '<div class="nexura-rg-header-flex">' +
                        '<div style="display:flex;align-items:center;gap:10px;">' +
                            '<span class="nexura-card-icon">' +
                                '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>' +
                            '</span>' +
                            'Attack Vector & Persistence Map' +
                        '</div>' +
                        '<div class="nexura-rg-graph-legend">' +
                            '<div class="nexura-rg-legend-item"><span class="nexura-rg-legend-dot target"></span> Malware Target</div>' +
                            '<div class="nexura-rg-legend-item"><span class="nexura-rg-legend-dot critical"></span> High Risk (>=85)</div>' +
                            '<div class="nexura-rg-legend-item"><span class="nexura-rg-legend-dot high"></span> Medium Risk (60-84)</div>' +
                            '<div class="nexura-rg-legend-item"><span class="nexura-rg-legend-dot medium"></span> Low Risk (<60)</div>' +
                            '<button id="nexura_cy_fit_btn" class="nexura-btn nexura-btn-secondary" style="padding:4px 12px;font-size:12px;margin-left:8px;" title="Recenter and Fit Map">Fit View</button>' +
                        '</div>' +
                    '</div>' +
                '</h2>' +
                '<div class="nexura-rg-graph-canvas-wrap">' +
                    '<div id="nexura_cy_graph"></div>' +
                '</div>' +
            '</div>'
        );

        container.append(graphCard);

        // Build Graph Elements
        var elements = [];
        var targetLabel = report.target_file ? report.target_file.split(/[\/\\]/).pop() : 'Malware Target';
        elements.push({
            data: { id: 'target', name: targetLabel, type: 'malware', risk: 100 }
        });

        $.each(report.evidence || [], function(i, item) {
            var nodeId = 'node_' + i;
            var nodeLabel = item.path ? item.path.split(/[\/\\]/).pop() : (item.hook || item.option || item.type || 'persistence');
            elements.push({
                data: {
                    id:   nodeId,
                    name: nodeLabel,
                    type: item.type || 'persistence',
                    risk: item.risk || 50,
                    desc: item.evidence || item.path || (item.hook ? 'Hook: ' + item.hook : '') || (item.option ? 'Option: ' + item.option : '') || ''
                }
            });
            elements.push({
                data: {
                    source: nodeId,
                    target: 'target',
                    label:  'Persists'
                }
            });
        });

        if (typeof cytoscape !== 'undefined') {
            cy = cytoscape({
                container: document.getElementById('nexura_cy_graph'),
                elements:  elements,
                style: [
                    {
                        selector: 'node',
                        style: {
                            'label':                 'data(name)',
                            'background-color':      '#ea580c',
                            'border-width':          2,
                            'border-color':          '#fed7aa',
                            'color':                 '#f1f5f9',
                            'text-outline-width':    2,
                            'text-outline-color':    '#0b0f1a',
                            'font-size':             '11px',
                            'font-weight':           600,
                            'font-family':           'Inter, system-ui, -apple-system, sans-serif',
                            'text-valign':           'bottom',
                            'text-margin-y':         '6px',
                            'text-wrap':             'ellipsis',
                            'text-max-width':        '120px',
                            'width':                 '38px',
                            'height':                '38px'
                        }
                    },
                    {
                        selector: 'node[type="malware"]',
                        style: {
                            'background-color':      '#ef4444',
                            'border-color':          '#fca5a5',
                            'border-width':          3,
                            'shape':                 'hexagon',
                            'width':                 '54px',
                            'height':                '54px',
                            'font-size':             '12px',
                            'font-weight':           700
                        }
                    },
                    {
                        selector: 'node[risk >= 85]',
                        style: {
                            'background-color':      '#ef4444',
                            'border-color':          '#fca5a5'
                        }
                    },
                    {
                        selector: 'node[risk >= 60][risk < 85]',
                        style: {
                            'background-color':      '#ea580c',
                            'border-color':          '#fed7aa'
                        }
                    },
                    {
                        selector: 'node[risk < 60]',
                        style: {
                            'background-color':      '#eab308',
                            'border-color':          '#fef08a'
                        }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'width':                 2,
                            'line-color':            'rgba(99, 102, 241, 0.45)',
                            'target-arrow-color':    '#818cf8',
                            'target-arrow-shape':    'triangle',
                            'curve-style':           'bezier'
                        }
                    }
                ],
                layout: {
                    name:       'concentric',
                    concentric: function(node) {
                        return node.data('type') === 'malware' ? 10 : 1;
                    },
                    levelWidth: function() { return 1; },
                    padding:    45,
                    fit:        true
                },
                wheelSensitivity: 0.3
            });

            function fitCyGraph() {
                if (cy) {
                    cy.resize();
                    cy.fit(null, 40);
                    cy.center();
                }
            }

            // Trigger multiple fit passes as DOM layout settles
            setTimeout(fitCyGraph, 50);
            setTimeout(fitCyGraph, 200);
            setTimeout(fitCyGraph, 500);

            $('#nexura_cy_fit_btn').on('click', function(e) {
                e.preventDefault();
                fitCyGraph();
            });

            $(window).on('resize', function() {
                fitCyGraph();
            });
        } else {
            $('#nexura_cy_graph').html('<div style="padding:40px;text-align:center;color:var(--nexura-text-muted);">Visual graph library initializing...</div>');
        }

        // 3. Findings Table Card with Client-Side Pagination & Filtering
        var allEvidence = report.evidence || [];
        var remediatedMap = {}; // Track remediated items across page navigation
        var pageSize = 10;
        var currentPage = 1;
        var filteredEvidence = allEvidence.slice();

        var tableCard = $(
            '<div class="nexura-card nexura-fade-in">' +
                '<h2>' +
                    '<div class="nexura-rg-header-flex">' +
                        '<div style="display:flex;align-items:center;gap:10px;">' +
                            '<span class="nexura-card-icon">' +
                                '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>' +
                            '</span>' +
                            'Detected Persistence Mechanisms (' + count + ')' +
                        '</div>' +
                        '<div style="display:flex;align-items:center;gap:10px;">' +
                            '<input type="text" id="nexura_rg_filter_input" placeholder="Search by path or type..." style="height:34px;font-size:12.5px;padding:4px 12px;width:220px;border-radius:var(--nexura-radius-sm);">' +
                        '</div>' +
                    '</div>' +
                '</h2>' +
                '<p style="color:var(--nexura-text-secondary);margin:-6px 0 16px 0;font-size:13.5px;">' +
                    (isPro ? 'Review all identified persistent components and neutralize them individually with one click.' : 'Review all identified persistent components and locations below.') +
                '</p>' +
                (!isPro ?
                    '<div class="nexura-rg-pro-callout">' +
                        '<div class="nexura-rg-pro-callout-icon">' +
                            '<svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>' +
                        '</div>' +
                        '<div class="nexura-rg-pro-callout-body">' +
                            '<h4>Need 1-Click Automated Remediation?</h4>' +
                            '<p>You can inspect and remove these components manually via FTP/cPanel, or upgrade to <strong>Nexura Pro</strong> to instantly quarantine malicious files, sanitize database entries, and verify against recurring reinfections with a single click.</p>' +
                        '</div>' +
                        '<div class="nexura-rg-pro-callout-action">' +
                            '<a href="' + upgradeUrl + '" target="_blank" class="nexura-btn nexura-btn-primary" style="white-space:nowrap;padding:8px 18px;font-size:13px;">' +
                                'Upgrade to Pro' +
                            '</a>' +
                        '</div>' +
                    '</div>' : '') +
                '<div class="nexura-rg-table-responsive">' +
                    '<table class="nexura-rg-table">' +
                        '<thead>' +
                            '<tr>' +
                                '<th style="width:75px;">Risk</th>' +
                                '<th style="width:170px;">Mechanism Type</th>' +
                                '<th>Evidence / File Location</th>' +
                                (isPro ? '<th style="width:140px;text-align:right;">Action</th>' : '') +
                            '</tr>' +
                        '</thead>' +
                        '<tbody id="nexura_rg_table_body"></tbody>' +
                    '</table>' +
                '</div>' +
                '<div id="nexura_rg_pagination_bar" class="nexura-rg-pagination-bar"></div>' +
            '</div>'
        );

        container.append(tableCard);

        function renderPagination() {
            var totalItems = filteredEvidence.length;
            var totalPages = Math.ceil(totalItems / pageSize) || 1;
            if (currentPage > totalPages) currentPage = totalPages;

            var startIdx = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
            var endIdx = Math.min(currentPage * pageSize, totalItems);

            var pageBar = $('#nexura_rg_pagination_bar');
            pageBar.empty();

            var infoHtml =
                '<div class="nexura-rg-pagination-info">' +
                    'Showing <strong>' + startIdx + '–' + endIdx + '</strong> of <strong>' + totalItems + '</strong> persistence mechanisms' +
                '</div>';

            var controlsHtml = '<div class="nexura-rg-pagination-controls">';

            // Prev button
            controlsHtml +=
                '<button class="nexura-rg-page-btn" data-page="' + (currentPage - 1) + '" ' + (currentPage <= 1 ? 'disabled' : '') + '>' +
                    '« Prev' +
                '</button>';

            // Page numbers
            for (var p = 1; p <= totalPages; p++) {
                if (totalPages > 7) {
                    if (p > 1 && p < totalPages && Math.abs(p - currentPage) > 2) {
                        if (p === 2 || p === totalPages - 1) {
                            controlsHtml += '<span style="color:var(--nexura-text-muted);padding:0 4px;">...</span>';
                        }
                        continue;
                    }
                }
                var activeClass = (p === currentPage ? 'active' : '');
                controlsHtml += '<button class="nexura-rg-page-btn ' + activeClass + '" data-page="' + p + '">' + p + '</button>';
            }

            // Next button
            controlsHtml +=
                '<button class="nexura-rg-page-btn" data-page="' + (currentPage + 1) + '" ' + (currentPage >= totalPages ? 'disabled' : '') + '>' +
                    'Next »' +
                '</button>';

            controlsHtml += '</div>';

            pageBar.append(infoHtml);
            pageBar.append(controlsHtml);

            // Bind click handlers for pagination buttons
            pageBar.find('.nexura-rg-page-btn').on('click', function(e) {
                e.preventDefault();
                var targetPage = parseInt($(this).data('page'), 10);
                if (targetPage && targetPage !== currentPage && targetPage >= 1 && targetPage <= totalPages) {
                    currentPage = targetPage;
                    renderTableRows();
                    renderPagination();
                }
            });
        }

        function renderTableRows() {
            var tbody = $('#nexura_rg_table_body');
            tbody.empty();

            var totalItems = filteredEvidence.length;
            if (totalItems === 0) {
                tbody.html(
                    '<tr>' +
                        '<td colspan="' + (isPro ? 4 : 3) + '" style="text-align:center;padding:30px;color:var(--nexura-text-muted);">' +
                            'No persistence mechanisms match your filter.' +
                        '</td>' +
                    '</tr>'
                );
                return;
            }

            var startIdx = (currentPage - 1) * pageSize;
            var endIdx = Math.min(startIdx + pageSize, totalItems);
            var pageItems = filteredEvidence.slice(startIdx, endIdx);

            $.each(pageItems, function(idxOnPage, item) {
                var originalIdx = item._origIdx !== undefined ? item._origIdx : (startIdx + idxOnPage);
                var rowRisk = item.risk || 50;
                var badgeClass = 'warning';
                if (rowRisk >= 85) badgeClass = 'critical';
                else if (rowRisk < 50) badgeClass = 'safe';

                var safeType = $('<div>').text(item.type || 'persistence').html();

                var loc = item.path || item.hook || item.option || item.evidence || 'N/A';
                var safeLoc = $('<div>').text(loc).html();
                var locColHtml =
                    '<td>' +
                        '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">' +
                            '<span class="nexura-rg-code" style="word-break:break-all;">' + safeLoc + '</span>' +
                            '<button type="button" class="nexura-copy-path-btn" data-path="' + safeLoc + '" title="Copy location to clipboard">' +
                                '<svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>' +
                                '<span>Copy</span>' +
                            '</button>' +
                        '</div>' +
                    '</td>';

                var isRemediated = remediatedMap[originalIdx] === true || item.remediated === true;
                var rowBg = isRemediated ? 'background:rgba(16, 185, 129, 0.08);' : '';

                var actionColHtml = '';
                if (isPro) {
                    if (isRemediated) {
                        actionColHtml =
                            '<span class="nexura-rg-remediated-badge">' +
                                '<svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>' +
                                'Remediated' +
                            '</span>';
                    } else {
                        var btnLabel = (item.type === 'html_defacement') ? 'Delete' : 'Remediate';
                        actionColHtml =
                            '<button class="nexura-btn nexura-btn-secondary nexura-remediate-btn" style="font-size:12px;padding:6px 14px;" data-index="' + originalIdx + '" ' +
                                'data-type="' + (item.type || '') + '" ' +
                                'data-path="' + (item.path || '') + '" ' +
                                'data-hook="' + (item.hook || '') + '" ' +
                                'data-option="' + (item.option || '') + '">' +
                                btnLabel +
                            '</button>';
                    }
                }

                var rowHtml =
                    '<tr id="nexura-finding-row-' + originalIdx + '" style="' + rowBg + '">' +
                        '<td><span class="nexura-badge ' + badgeClass + '">' + rowRisk + '</span></td>' +
                        '<td style="color:var(--nexura-text-primary);font-weight:600;">' + safeType + '</td>' +
                        locColHtml +
                        (isPro ? '<td style="text-align:right;">' + actionColHtml + '</td>' : '') +
                    '</tr>';

                tbody.append(rowHtml);
            });

            // Bind Copy Path buttons
            tbody.find('.nexura-copy-path-btn').on('click', function(e) {
                e.preventDefault();
                var btn = $(this);
                var text = btn.data('path');
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function() {
                        btn.addClass('copied').find('span').text('Copied!');
                        setTimeout(function() {
                            btn.removeClass('copied').find('span').text('Copy');
                        }, 2000);
                    });
                } else {
                    var temp = $('<input>');
                    $('body').append(temp);
                    temp.val(text).select();
                    document.execCommand('copy');
                    temp.remove();
                    btn.addClass('copied').find('span').text('Copied!');
                    setTimeout(function() {
                        btn.removeClass('copied').find('span').text('Copy');
                    }, 2000);
                }
            });

            // Re-bind Remediate buttons for current page (Pro only)
            if (isPro) {
                tbody.find('.nexura-remediate-btn').on('click', function(e) {
                    e.preventDefault();
                    var btn = $(this);
                    var idx = btn.data('index');
                    var rowId = '#nexura-finding-row-' + idx;

                    btn.prop('disabled', true).text('Remediating...');

                    $.ajax({
                        url:    getApiUrl('nexura/v1/reinfection/remediate'),
                        method: 'POST',
                        beforeSend: function(xhr) {
                            if (typeof NEXURA_rg !== 'undefined' && NEXURA_rg.nonce) {
                                xhr.setRequestHeader('X-WP-Nonce', NEXURA_rg.nonce);
                            }
                        },
                        data: {
                            type:   btn.data('type'),
                            path:   btn.data('path'),
                            hook:   btn.data('hook'),
                            option: btn.data('option')
                        },
                        success: function(res) {
                            if (res && res.success) {
                                remediatedMap[idx] = true;
                                btn.replaceWith(
                                    '<span class="nexura-rg-remediated-badge">' +
                                        '<svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>' +
                                        'Remediated' +
                                    '</span>'
                                );
                                $(rowId).css('background', 'rgba(16, 185, 129, 0.08)');
                            } else {
                                btn.prop('disabled', false).text('Remediate');
                                alert((res && res.message) || 'Remediation failed.');
                            }
                        },
                        error: function(xhr) {
                            btn.prop('disabled', false).text('Remediate');
                            var msg = 'Remediation request failed.';
                            if (xhr.responseJSON && xhr.responseJSON.message) {
                                msg += ' (' + xhr.responseJSON.message + ')';
                            }
                            alert(msg);
                        }
                    });
                });
            }
        }

        // Initialize original indices & restore any previously remediated state
        $.each(allEvidence, function(i, item) {
            item._origIdx = i;
            if (item.remediated) {
                remediatedMap[i] = true;
            }
        });

        // Filter search input binding
        $('#nexura_rg_filter_input').on('input', function() {
            var q = $(this).val().toLowerCase().trim();
            if (!q) {
                filteredEvidence = allEvidence.slice();
            } else {
                filteredEvidence = $.grep(allEvidence, function(item) {
                    var str = (item.type || '') + ' ' + (item.path || '') + ' ' + (item.hook || '') + ' ' + (item.option || '') + ' ' + (item.evidence || '');
                    return str.toLowerCase().indexOf(q) !== -1;
                });
            }
            currentPage = 1;
            renderTableRows();
            renderPagination();
        });

        // Initial table and pagination render
        renderTableRows();
        renderPagination();
    }

    /* ---- helpers ---- */

    function updateStatus(msg) {
        $('#nexura_investigation_status_text').text(msg);
    }

    function showError(msg) {
        $('#nexura_reinfection_graph_container').html(
            '<div class="nexura-card nexura-fade-in">' +
                '<div class="nexura-rg-empty-state">' +
                    '<div style="width:50px;height:50px;border-radius:50%;background:var(--nexura-red-bg);color:var(--nexura-red);display:flex;align-items:center;justify-content:center;margin:0 auto 16px auto;">' +
                        '<svg width="26" height="26" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>' +
                    '</div>' +
                    '<h3 style="color:var(--nexura-red);font-size:16px;margin:0 0 8px 0;font-weight:700;">Investigation Encountered an Error</h3>' +
                    '<p style="color:var(--nexura-text-secondary);margin:0;font-size:13.5px;">' + $('<div>').text(msg).html() + '</p>' +
                '</div>' +
            '</div>'
        );
        resetUI();
    }

    function resetUI() {
        $('#nexura_start_investigation').prop('disabled', false);
        $('#nexura_investigation_status').hide();
    }

    // Clear previous investigation handler
    $('#nexura_clear_investigation').on('click', function(e) {
        e.preventDefault();
        var btn = $(this);
        btn.prop('disabled', true).text('Clearing...');

        $.ajax({
            url:    getApiUrl('nexura/v1/reinfection/clear'),
            method: 'POST',
            beforeSend: function(xhr) {
                if (typeof NEXURA_rg !== 'undefined' && NEXURA_rg.nonce) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_rg.nonce);
                }
            },
            success: function() {
                if (typeof NEXURA_rg !== 'undefined') {
                    NEXURA_rg.last_report = null;
                }
                $('#nexura_investigation_target').val('');
                btn.hide().prop('disabled', false).html(
                    '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg> Clear Results'
                );
                $('#nexura_reinfection_graph_container').html(
                    '<div class="nexura-card nexura-fade-in">' +
                        '<div class="nexura-rg-empty-state">' +
                            '<svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color:var(--nexura-text-muted);margin-bottom:12px;opacity:0.6;">' +
                                '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>' +
                            '</svg>' +
                            '<p style="color:var(--nexura-text-muted);font-size:14px;margin:0;">No investigation results yet. Click "Investigate Root Cause" to start scanning.</p>' +
                        '</div>' +
                    '</div>'
                );
            },
            error: function() {
                btn.prop('disabled', false).html('Clear Results');
                alert('Failed to clear investigation results.');
            }
        });
    });

    // Auto-restore previous investigation report on page load / reload
    if (typeof NEXURA_rg !== 'undefined' && NEXURA_rg.last_report && NEXURA_rg.last_report.evidence && NEXURA_rg.last_report.evidence.length > 0) {
        if (NEXURA_rg.last_report.target_file) {
            $('#nexura_investigation_target').val(NEXURA_rg.last_report.target_file);
        }
        $('#nexura_clear_investigation').show();
        renderResults(NEXURA_rg.last_report);
    }
});




