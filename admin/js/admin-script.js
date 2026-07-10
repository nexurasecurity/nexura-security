/**
 * Nexura Security Admin Scripts
 */
jQuery(document).ready(function($) {
    // Robust JSON data filter to handle prepended malware scripts or PHP notices
    // This ensures our scanner works EVEN IF the site is currently hacked and outputting garbage!
    $.ajaxSetup({
        dataFilter: function(data, type) {
            if (typeof data === 'string') {
                try {
                    JSON.parse(data);
                    return data;
                } catch(e) {
                    // The response contains garbage (e.g. malware script or PHP notices).
                    // Extract the JSON payload safely from the end of the response.
                    var sigs = ['{"success":', '{"code":', '{"message":', '{"data":', '[{"'];
                    for (var i = 0; i < sigs.length; i++) {
                        var idx = data.lastIndexOf(sigs[i]);
                        if (idx !== -1) {
                            var endChar = sigs[i].charAt(0) === '{' ? '}' : ']';
                            var lastIdx = data.lastIndexOf(endChar);
                            if (lastIdx > idx) {
                                var testStr = data.substring(idx, lastIdx + 1);
                                try {
                                    JSON.parse(testStr);
                                    return testStr;
                                } catch(err) {}
                            }
                        }
                    }
                }
            }
            return data;
        }
    });

    /**
     * Build a REST API URL that works with or without pretty permalinks.
     * Uses site_url/?rest_route=/path format which is always reliable.
     * @param {string} route - e.g. 'nexura/v1/scan/init'
     * @returns {string}
     */
    function nexuraRestUrl(route) {
        // Always use ?rest_route= format ??? it works universally on all servers
        var base = NEXURA_ajax.site_url || NEXURA_ajax.rest_url;
        // Remove trailing slash
        base = base.replace(/\/+$/, '');
        return base + '/?rest_route=/' + route;
    }

    var sgsScanner = {
        isStopped: false,
        editorInstance: null,
        currentPage: 1,
        init: function() {
            // PRO Feature License Gate Interceptor
            if (typeof NEXURA_ajax !== 'undefined' && NEXURA_ajax.pro_slugs && !NEXURA_ajax.is_license_active) {
                $(document).on('click', 'a', function(e) {
                    var href = $(this).attr('href');
                    if (href && href.indexOf('page=') !== -1) {
                        for (var i = 0; i < NEXURA_ajax.pro_slugs.length; i++) {
                            if (href.indexOf('page=' + NEXURA_ajax.pro_slugs[i]) !== -1) {
                                e.preventDefault();
                                $('#nexura-pro-upgrade-modal').css('display', 'flex').hide().fadeIn(200);
                                return false;
                            }
                        }
                    }
                });
            }

            $('#nexura-run-scan').on('click', this.startScan.bind(this));
            $('#nexura-stop-scan').on('click', this.stopScan.bind(this));
            $('#nexura-quick-backup-db').on('click', this.quickBackupDb.bind(this));

            if ($('#nexura-issues-page').length) {
                this.loadResults();
            }

            // Auto-resume if scan was running before page reload
            if (typeof NEXURA_ajax !== 'undefined' && NEXURA_ajax.scan_running) {
                var $btn = $('#nexura-run-scan');
                var $stopBtn = $('#nexura-stop-scan');
                var $results = $('#nexura-scan-results');
                var $progress = $('#nexura-scan-progress');
                var $progressBar = $('#nexura-scan-progress-bar');
                var $progressText = $('#nexura-scan-progress-text');
                var $stats = $('#nexura-scan-stats');

                this.isStopped = false;
                $btn.prop('disabled', true).text('Resuming Scan...').hide();
                $stopBtn.show();
                
                $results.html('');
                $progress.show();
                
                $progressBar.css('width', NEXURA_ajax.scan_progress + '%');
                if ($progressText.length) {
                    $progressText.html('<div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2); padding: 4px 12px; border-radius: 20px; color: #38bdf8; font-size: 12px;"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> <strong>Resuming Scan...</strong> <span style="background: #38bdf8; color: #0f172a; padding: 2px 8px; border-radius: 12px; font-weight: 700; margin-left: 5px;">' + NEXURA_ajax.scan_progress + '%</span></div>');
                }
                
                if ($stats.length) {
                    var initStatsHtml = '<div style="display:flex; gap: 10px; align-items: center;">' +
                        '<div style="background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2); padding: 4px 12px; border-radius: 20px; color: #38bdf8; display: flex; align-items: center; gap: 6px; font-weight: 500; font-size: 12px;"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg> <span>Processed: ' + NEXURA_ajax.scan_processed + ' / ' + NEXURA_ajax.scan_total + '</span></div>' +
                        (NEXURA_ajax.scan_issues > 0 ? '<div style="background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.2); padding: 4px 12px; border-radius: 20px; color: #f43f5e; display: flex; align-items: center; gap: 6px; font-weight: 500; font-size: 12px;"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> <span>' + NEXURA_ajax.scan_issues + ' issue(s)</span></div>' : '') +
                        '</div>';
                    $stats.html(initStatsHtml);
                }

                this.processStep();
            }
        },

        startScan: function(e) {
            e.preventDefault();
            
            var $btn = $('#nexura-run-scan');
            var $stopBtn = $('#nexura-stop-scan');
            var $results = $('#nexura-scan-results');
            var $progress = $('#nexura-scan-progress');
            var $progressBar = $('#nexura-scan-progress-bar');
            var $progressText = $('#nexura-scan-progress-text');
            
            this.isStopped = false;
            $btn.prop('disabled', true).text('Initializing Scan...').hide();
            $stopBtn.show();
            
            $results.html('');
            $progress.show();
            $progressBar.css('width', '0%');
            if ($progressText.length) {
                $progressText.html('<div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2); padding: 4px 12px; border-radius: 20px; color: #38bdf8; font-size: 12px;"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> <strong>Initializing...</strong> <span style="background: #38bdf8; color: #0f172a; padding: 2px 8px; border-radius: 12px; font-weight: 700; margin-left: 5px;">0%</span></div>');
            }
            if ($('#nexura-scan-eta').length) {
                $('#nexura-scan-eta').html('<div style="display: inline-flex; align-items: center; gap: 6px; background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.2); padding: 4px 12px; border-radius: 20px; color: #eab308; font-size: 12px;"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> <strong>Calculating ETA...</strong></div>');
            }
            
            var scanData = {};
            if ($('#nexura-cpanel-scan').length) {
                scanData.cpanel = $('#nexura-cpanel-scan').is(':checked') ? 1 : 0;
            }

            $.ajax({
                url: nexuraRestUrl('nexura/v1/scan/init'),
                method: 'POST',
                data: scanData,
                dataType: 'json',
                dataFilter: function(data, type) {
                    if (type === 'json' && typeof data === 'string') {
                        var firstBrace = data.indexOf('{');
                        var lastBrace = data.lastIndexOf('}');
                        if (firstBrace !== -1 && lastBrace !== -1 && lastBrace >= firstBrace) {
                            return data.substring(firstBrace, lastBrace + 1);
                        }
                    }
                    return data;
                },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success && response.data.status === 'initialized') {
                        $btn.text('Scanning (' + response.data.total + ' files)...');
                        this.processStep();
                    } else {
                        this.showError('Failed to initialize scan.');
                    }
                },
                error: (xhr, status, error) => {
                    var raw = xhr.responseText ? xhr.responseText.substring(0, 100) : '';
                    this.showError('Error initializing: ' + error + ' | Raw: ' + raw);
                }
            });
        },

        processStep: function() {
            if (this.isStopped) return;

            var $progressBar = $('#nexura-scan-progress-bar');
            var $progressText = $('#nexura-scan-progress-text');
            var $fileList = $('#nexura-scan-file-list');
            var $stats = $('#nexura-scan-stats');
            
            $.ajax({
                url: nexuraRestUrl('nexura/v1/scan/step'),
                method: 'POST',
                dataType: 'json',
                dataFilter: function(data, type) {
                    if (type === 'json' && typeof data === 'string') {
                        var firstBrace = data.indexOf('{');
                        var lastBrace = data.lastIndexOf('}');
                        if (firstBrace !== -1 && lastBrace !== -1 && lastBrace >= firstBrace) {
                            return data.substring(firstBrace, lastBrace + 1);
                        }
                    }
                    return data;
                },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success) {
                        var data = response.data;
                        
                        var pct = data.total > 0 ? Math.round((data.processed / data.total) * 100) : 0;
                        if (pct > 100) pct = 100;
                        
                        $progressBar.css('width', pct + '%');
                        
                        if ($progressText.length) {
                            $progressText.html('<div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2); padding: 4px 12px; border-radius: 20px; color: #38bdf8; font-size: 12px; box-shadow: 0 2px 10px rgba(56, 189, 248, 0.05);"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> <strong>Scanning Files</strong> <span style="background: #38bdf8; color: #0f172a; padding: 2px 8px; border-radius: 12px; font-weight: 700; margin-left: 5px;">' + pct + '%</span></div>');
                        }
                        
                        // Update ETA
                        if ($('#nexura-scan-eta').length && data.eta) {
                            $('#nexura-scan-eta').html('<div style="display: inline-flex; align-items: center; gap: 6px; background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.2); padding: 4px 12px; border-radius: 20px; color: #eab308; font-size: 12px; box-shadow: 0 2px 10px rgba(234, 179, 8, 0.05);"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Time Remaining: <strong>' + data.eta + '</strong></div>');
                        }

                        // Update stats line
                        if ($stats.length) {
                            var liveStatsHtml = '<div style="display:flex; gap: 10px; align-items: center; flex-wrap: wrap;">' +
                                '<div style="background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2); padding: 4px 12px; border-radius: 20px; color: #38bdf8; display: flex; align-items: center; gap: 6px; font-weight: 500; font-size: 12px; box-shadow: 0 2px 10px rgba(56, 189, 248, 0.05); transition: all 0.2s;"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg> <span>Processed: ' + data.processed + ' / ' + data.total + '</span></div>' +
                                '<div style="background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.2); padding: 4px 12px; border-radius: 20px; color: #f43f5e; display: flex; align-items: center; gap: 6px; font-weight: 500; font-size: 12px; box-shadow: 0 2px 10px rgba(244, 63, 94, 0.05); transition: all 0.2s;"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> <span>Issues: ' + (data.issues || 0) + '</span></div>' +
                                '</div>';
                            $stats.html(liveStatsHtml);
                        }

                        // Update live file feed
                        if ($fileList.length && data.recent_files && data.recent_files.length > 0) {
                            var html = '';
                            for (var i = 0; i < data.recent_files.length; i++) {
                                var isLast = (i === data.recent_files.length - 1);
                                html += '<div style="display: flex; align-items: center; gap: 8px; padding: 2px 0;' + (isLast ? ' color: var(--nexura-accent-light); font-weight: 600;' : '') + '">';
                                html += '<span style="color: ' + (isLast ? 'var(--nexura-green)' : 'var(--nexura-text-muted)') + ';">' + (isLast ? '&#9654;' : '&#10003;') + '</span>';
                                html += '<span>' + data.recent_files[i] + '</span>';
                                html += '</div>';
                            }
                            $fileList.html(html);
                            // Auto-scroll to bottom
                            var feedContainer = $fileList.parent()[0];
                            if (feedContainer) feedContainer.scrollTop = feedContainer.scrollHeight;
                        }
                        
                        if (data.status === 'processing') {
                            this.processStep();
                        } else if (data.status === 'completed') {
                            this.finishScan(data);
                        }
                    } else {
                        this.showError('Scan process failed.');
                    }
                },
                error: (xhr, status, error) => {
                    var raw = xhr.responseText ? xhr.responseText.substring(0, 100) : '';
                    this.showError('Error processing step: ' + error + ' | Raw: ' + raw);
                }
            });
        },

        finishScan: function(data) {
            var $btn = $('#nexura-run-scan');
            var $stopBtn = $('#nexura-stop-scan');
            
            $stopBtn.hide();
            $btn.prop('disabled', false).text('Run Full Scan Again').show();

            // Update live feed to show completion
            var $fileList = $('#nexura-scan-file-list');
            if ($fileList.length) {
                // Change the last item's icon from play to checkmark
                var $lastItem = $fileList.children('div').last();
                if ($lastItem.length) {
                    $lastItem.find('span').first().html('&#10003;').css('color', 'var(--nexura-text-muted)');
                    $lastItem.css({'color': '', 'font-weight': 'normal'});
                }

                $fileList.append(
                    '<div style="display: flex; align-items: center; gap: 8px; padding: 6px 0; margin-top: 8px; border-top: 1px solid var(--nexura-border); color: var(--nexura-green); font-weight: 600;">' +
                    '<span>&#9989;</span><span>Scan complete &mdash; ' + data.processed + ' files scanned out of ' + data.total + ' total.</span>' +
                    '</div>'
                );

                // Auto-scroll to bottom to show completion message
                var feedContainer = $fileList.parent()[0];
                if (feedContainer) feedContainer.scrollTop = feedContainer.scrollHeight;
            }
            
            if (data.issues > 0) {
                $('#nexura-scan-status-msg').html('<div class="notice notice-error inline"><p>Scan completed. Found ' + data.issues + ' issues.</p></div>');
                $('#nexura-view-issues-btn').show();
            } else {
                $('#nexura-scan-status-msg').html('<div class="notice notice-success inline"><p>Scan completed successfully! No issues found.</p></div>');
                $('#nexura-view-issues-btn').hide();
            }
        },

        stopScan: function(e) {
            e.preventDefault();
            this.isStopped = true;
            
            var $stopBtn = $('#nexura-stop-scan');
            $stopBtn.prop('disabled', true).text('Stopping...');
            
            $.ajax({
                url: nexuraRestUrl('nexura/v1/scan/stop'),
                method: 'POST',
                dataType: 'json',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    var $btn = $('#nexura-run-scan');
                    $stopBtn.hide().prop('disabled', false).text('Stop Scan');
                    $btn.prop('disabled', false).text('Run Full Scan Again').show();
                    
                    if ($('#nexura-scan-status-msg').length) {
                        $('#nexura-scan-status-msg').html('<div class="notice notice-warning inline"><p>Scan was stopped by user.</p></div>');
                    }
                    
                    var $fileList = $('#nexura-scan-file-list');
                    if ($fileList.length) {
                        $fileList.append(
                            '<div style="display: flex; align-items: center; gap: 8px; padding: 6px 0; margin-top: 8px; border-top: 1px solid var(--nexura-border); color: var(--nexura-red); font-weight: 600;">' +
                            '<span>&#128225;</span><span>Scan stopped by user.</span>' +
                            '</div>'
                        );
                    }
                },
                error: (xhr, status, error) => {
                    this.showError('Error stopping scan: ' + error);
                }
            });
        },

        loadResults: function(page = 1) {
            this.currentPage = page;
            $.ajax({
                url: nexuraRestUrl('nexura/v1/scan/results'),
                method: 'GET',
                cache: false,
                data: { page: this.currentPage, per_page: 20 },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success && response.data.items && response.data.items.length > 0) {
                        this.renderTable(response.data);
                    } else {
                        $('#nexura-scan-results').html('<div style="padding: 30px; text-align: center; color: var(--nexura-text-muted);"><span style="font-size: 32px; display: block; margin-bottom: 10px;">&#9989;</span>No issues found! Your site is clean.</div>');
                    }
                },
                error: (xhr, textStatus, errorThrown) => {
                    $('#nexura-scan-results').html('<div class="notice notice-error inline"><p>Error loading results.</p></div>');
                }
            });
        },

        renderTable: function(data) {
            var items = data.items || data; // Fallback just in case
            var html = '<table class="wp-list-table widefat fixed striped">';
            
            var headers = [];
            headers.push('<th>Detected Pattern</th>');
            headers.push('<th>Risk</th>');
            
            // Trigger hook so PRO can add File Path, Line, Action columns
            $(document).trigger('nexura_issues_table_headers', [headers]);
            
            html += '<thead><tr>' + headers.join('') + '</tr></thead>';
            
            var currentPage = parseInt(data.current_page, 10) || 1;
            html += '<tbody>';
            
            $.each(items, function(index, item) {
                var absoluteIndex = (currentPage - 1) * 20 + index;
                var riskClass = 'nexura-risk-' + item.risk_score.toLowerCase();
                var lineDisplay = (item.line_number && item.line_number !== '0') ? 'Line ' + item.line_number : 'N/A';
                
                var filePathDisplay = '<code>' + item.file_path + '</code>';
                var lineDisplay = (item.line_number && item.line_number !== '0') ? 'Line ' + item.line_number : 'N/A';


                var malwareName = item.pattern || '';
                
                // Clean up the pattern to make it a readable malware name
                if (malwareName.indexOf('Regex Match: ') === 0) {
                    malwareName = malwareName.replace('Regex Match: ', '');
                } else if (malwareName.indexOf('DB Post ID ') === 0) {
                    malwareName = malwareName.replace(/DB Post ID \d+: /, '');
                } else if (malwareName.indexOf('DB Option ') === 0) {
                    malwareName = malwareName.replace(/DB Option ".*": /, '');
                } else if (malwareName.indexOf('ghost_sig_') === 0 || malwareName === 'ghost_malware_detected') {
                    malwareName = 'Ghost Malware Variant';
                } else if (malwareName.indexOf('suspicious_upload_ext:') === 0) {
                    malwareName = 'Suspicious Executable Upload';
                } else if (malwareName.indexOf('community_learned_') === 0) {
                    malwareName = 'Community Blocked Signature';
                }

                // If it looks like a regex code or raw DB string, simplify it
                if (malwareName.charAt(0) === '/' && malwareName.length > 20) {
                    malwareName = 'Custom Malware Payload';
                } else if (malwareName.indexOf('_') !== -1) {
                    // Convert snake_case to Title Case (e.g., ndsw_js_malware -> Ndsw Js Malware)
                    malwareName = malwareName.split('_').map(function(word) {
                        return word.charAt(0).toUpperCase() + word.slice(1);
                    }).join(' ');
                }

                var rowData = [];
                rowData.push('<td><strong>' + malwareName + '</strong></td>');
                rowData.push('<td class="' + riskClass + '">' + item.risk_score + '</td>');

                // Trigger hook so PRO can add File Path, Line, Action columns
                $(document).trigger('nexura_issues_table_row', [rowData, item]);

                html += '<tr>' + rowData.join('') + '</tr>';
            });
            
            html += '</tbody></table>';

            // Add Pagination Controls
            if (data.total_pages && data.total_pages > 1) {
                html += '<div class="nexura-pagination" style="margin-top: 15px; display: flex; justify-content: space-between; align-items: center;">';
                html += '<span>Showing page ' + data.current_page + ' of ' + data.total_pages + ' (' + data.total_items + ' total issues)</span>';
                html += '<div>';
                if (data.current_page > 1) {
                    html += '<button type="button" class="button nexura-page-btn" data-page="' + (data.current_page - 1) + '" style="margin-right: 5px;">&laquo; Previous</button>';
                }
                if (data.current_page < data.total_pages) {
                    html += '<button type="button" class="button nexura-page-btn" data-page="' + (data.current_page + 1) + '">Next &raquo;</button>';
                }
                html += '</div></div>';
            }

            $('#nexura-scan-results').html(html);

            // Bind new buttons
            $('.nexura-edit-file').on('click', this.openEditor.bind(this));
            $('.nexura-close-editor').on('click', this.closeEditor.bind(this));
            $('#nexura-save-file').off('click').on('click', this.saveFile.bind(this));
            
            // Bind pagination buttons
            var self = this;
            $('.nexura-page-btn').on('click', function(e) {
                e.preventDefault();
                var page = $(this).data('page');
                self.loadResults(page);
            });
        },

        openEditor: function(e) {
            var filePath = $(e.target).data('file');
            var lineNum = $(e.target).data('line');
            $('#nexura-editor-filename').text(filePath);
            $('#nexura-editor-filepath').val(filePath);
            
            // Show modal first
            $('#nexura-file-editor-modal').css('display', 'flex');

            // Initialize CodeMirror editor if enqueued and not yet initialized
            if (!this.editorInstance && typeof wp !== 'undefined' && wp.codeEditor) {
                var settings = NEXURA_ajax.code_editor || {};
                settings.codemirror = $.extend({}, settings.codemirror, {
                    lineNumbers: true,
                    lineWrapping: true,
                    styleActiveLine: true,
                });
                this.editorInstance = wp.codeEditor.initialize($('#nexura-editor-content'), settings);
            }

            // Set loading text
            if (this.editorInstance) {
                this.editorInstance.codemirror.setValue('Loading...');
            } else {
                $('#nexura-editor-content').val('Loading...');
            }

            $.ajax({
                url: nexuraRestUrl('nexura/v1/scan/file'),
                method: 'GET',
                data: { file_path: filePath },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success) {
                        var content = response.data.content;
                        if (this.editorInstance) {
                            var cm = this.editorInstance.codemirror;
                            cm.setValue(content);
                            
                            // Highlight the line
                            var line = parseInt(lineNum, 10);
                            if (!isNaN(line) && line > 0) {
                                var lineIndex = line - 1;
                                cm.addLineClass(lineIndex, 'background', 'nexura-highlighted-line');
                                
                                // Scroll CodeMirror to make sure the highlighted line is centered
                                setTimeout(function() {
                                    var t = cm.charCoords({line: lineIndex, ch: 0}, 'local').top;
                                    var middleHeight = cm.getScrollerElement().offsetHeight / 2;
                                    cm.scrollTo(null, t - middleHeight);
                                }, 150);
                            }
                        } else {
                            $('#nexura-editor-content').val(content);
                        }
                    } else {
                        if (this.editorInstance) {
                            this.editorInstance.codemirror.setValue('Error loading file content.');
                        } else {
                            $('#nexura-editor-content').val('Error loading file content.');
                        }
                    }
                },
                error: (xhr) => {
                    var msg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : 'Error loading file.';
                    if (this.editorInstance) {
                        this.editorInstance.codemirror.setValue(msg);
                    } else {
                        $('#nexura-editor-content').val(msg);
                    }
                }
            });
        },

        closeEditor: function() {
            $('#nexura-file-editor-modal').hide();
        },

        saveFile: function() {
            var filePath = $('#nexura-editor-filepath').val();
            var content = this.editorInstance ? this.editorInstance.codemirror.getValue() : $('#nexura-editor-content').val();
            var $btn = $('#nexura-save-file');
            
            $btn.prop('disabled', true).text('Saving...');

            $.ajax({
                url: nexuraRestUrl('nexura/v1/scan/file'),
                method: 'POST',
                data: { file_path: filePath, content: content },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    $btn.prop('disabled', false).text('Save Changes');
                    if (response.success) {
                        alert('File saved successfully!');
                        this.closeEditor();
                        this.loadResults(); // Reload table
                    } else {
                        alert('Error saving file.');
                    }
                },
                error: (xhr) => {
                    $btn.prop('disabled', false).text('Save Changes');
                    var msg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : 'Error saving file.';
                    alert(msg);
                }
            });
        },

        quickBackupDb: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var originalHtml = $btn.html();
            
            $btn.css('pointer-events', 'none').css('opacity', '0.7');
            $btn.find('span').last().text('Backing up...');
            
            $.ajax({
                url: typeof NEXURA_ajax !== 'undefined' ? NEXURA_ajax.ajax_url : ajaxurl,
                method: 'POST',
                data: {
                    action: 'NEXURA_backup_db',
                    _wpnonce: typeof NEXURA_ajax !== 'undefined' ? NEXURA_ajax.backup_nonce : ''
                },
                success: (response) => {
                    $btn.css('pointer-events', 'auto').css('opacity', '1');
                    $btn.html(originalHtml);
                    
                    if (response.success && response.data && response.data.file) {
                        alert('Database backup created successfully! Downloading now...');
                        var downloadUrl = (typeof NEXURA_ajax !== 'undefined' ? NEXURA_ajax.ajax_url : ajaxurl) + '?action=NEXURA_download_backup&file=' + encodeURIComponent(response.data.file) + '&_wpnonce=' + encodeURIComponent(NEXURA_ajax.backup_nonce);
                        window.location.href = downloadUrl;
                    } else {
                        alert('Failed to create backup: ' + (response.data || 'Unknown error'));
                    }
                },
                error: (xhr) => {
                    $btn.css('pointer-events', 'auto').css('opacity', '1');
                    $btn.html(originalHtml);
                    alert('Error creating backup: ' + xhr.statusText);
                }
            });
        },

        showError: function(msg) {
            $('#nexura-run-scan').prop('disabled', false).text('Run Full Scan Again').show();
            $('#nexura-stop-scan').hide();
            
            var safeMsg = msg.replace(/</g, '&lt;').replace(/>/g, '&gt;');
            
            if ($('#nexura-scan-results').length) {
                $('#nexura-scan-results').html('<div class="notice notice-error inline"><p>' + safeMsg + '</p></div>');
            } else if ($('#nexura-scan-status-msg').length) {
                $('#nexura-scan-status-msg').html('<div class="notice notice-error inline"><p>' + safeMsg + '</p></div>');
            } else {
                alert(msg);
            }
        }
    };

    var sgsFIM = {
        init: function() {
            $('#nexura-generate-baseline').on('click', this.generateBaseline.bind(this));
            $('#nexura-check-integrity').on('click', this.checkIntegrity.bind(this));
        },

        generateBaseline: function(e) {
            e.preventDefault();
            var $btn = $(e.target);
            var $results = $('#nexura-fim-results');
            
            $btn.prop('disabled', true).text('Generating...');
            $results.html('<p>Generating file hashes, this may take a moment...</p>');

            $.ajax({
                url: nexuraRestUrl('nexura/v1/fim/init'),
                method: 'POST',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: function(response) {
                    if (response.success) {
                        $results.html('<div class="notice notice-success inline"><p>' + response.data.message + '</p></div>');
                    } else {
                        $results.html('<div class="notice notice-error inline"><p>Failed to generate baseline.</p></div>');
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Generate Baseline');
                }
            });
        },

        checkIntegrity: function(e) {
            e.preventDefault();
            var $btn = $(e.target);
            var $results = $('#nexura-fim-results');
            
            $btn.prop('disabled', true).text('Checking...');
            $results.html('<p>Comparing current files to baseline...</p>');

            $.ajax({
                url: nexuraRestUrl('nexura/v1/fim/check'),
                method: 'GET',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success) {
                        this.renderFIMResults(response.data);
                    } else {
                        $results.html('<div class="notice notice-error inline"><p>' + (response.data.error || 'Check failed.') + '</p></div>');
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Check Integrity');
                }
            });
        },

        renderFIMResults: function(data) {
            var $results = $('#nexura-fim-results');
            $results.html('');
            
            if (data.added.length === 0 && data.modified.length === 0 && data.deleted.length === 0) {
                $results.html('<div class="notice notice-success inline"><p>All files match the baseline. No unauthorized changes detected.</p></div>');
                return;
            }

            var html = '<table class="wp-list-table widefat fixed striped">';
            html += '<thead><tr><th>File Path</th><th>Status</th></tr></thead><tbody>';

            $.each(data.added, function(i, file) {
                html += '<tr><td><code>' + file + '</code></td><td class="nexura-risk-high">Added</td></tr>';
            });
            $.each(data.modified, function(i, file) {
                html += '<tr><td><code>' + file + '</code></td><td class="nexura-risk-medium">Modified</td></tr>';
            });
            $.each(data.deleted, function(i, file) {
                html += '<tr><td><code>' + file + '</code></td><td class="nexura-risk-medium">Deleted</td></tr>';
            });

            html += '</tbody></table>';
            $results.html(html);
        }
    };

    var sgsGSB = {
        init: function() {
            $('#nexura-check-gsb').on('click', this.checkSite.bind(this));
        },

        checkSite: function(e) {
            e.preventDefault();
            var $btn = $(e.target);
            var $results = $('#nexura-gsb-results');
            
            $btn.prop('disabled', true).text('Checking with Google...');
            $results.html('<p>Querying Google Safe Browsing API...</p>');

            $.ajax({
                url: nexuraRestUrl('nexura/v1/gsb/check'),
                method: 'GET',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: function(response) {
                    if (response.success) {
                        if (response.data.safe) {
                            $results.html('<div class="notice notice-success inline"><p><strong>Safe:</strong> Google has not flagged this site for any malicious activity.</p></div>');
                        } else {
                            var details = '<ul>';
                            $.each(response.data.details, function(i, match) {
                                details += '<li>Threat Type: <strong>' + match.threatType + '</strong></li>';
                            });
                            details += '</ul>';
                            $results.html('<div class="notice notice-error inline"><p><strong>Warning!</strong> Google has flagged this site.</p>' + details + '</div>');
                        }
                    } else {
                        $results.html('<div class="notice notice-error inline"><p>' + (response.data.message || 'Check failed.') + '</p></div>');
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Check Site Status');
                }
            });
        }
    };

    var sgsVuln = {
        init: function() {
            $('#nexura-run-vuln-audit').on('click', this.runAudit.bind(this));
            
            // Auto-run audit on page load to persist results visually
            if ($('#nexura-vuln-results').length > 0) {
                this.runAudit();
            }
        },

        runAudit: function(e) {
            if (e) e.preventDefault();
            var $btn = $('#nexura-run-vuln-audit');
            var $results = $('#nexura-vuln-results');
            
            $btn.prop('disabled', true).text('Auditing...');
            $results.html('<p>Checking installed versions against known vulnerabilities...</p>');

            $.ajax({
                url: nexuraRestUrl('nexura/v1/vuln/audit'),
                method: 'GET',
                dataType: 'json',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success) {
                        this.renderResults(response.data);
                    } else {
                        $results.html('<div class="notice notice-error inline"><p>Audit failed.</p></div>');
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Run Audit');
                }
            });
        },

        renderResults: function(data) {
            var $results = $('#nexura-vuln-results');
            $results.html('');
            
            if (!data.core && !data.plugins && !data.themes) {
                $results.html('<div class="notice notice-success inline"><p>All components are up to date and secure.</p></div>');
                return;
            }

            var html = '<table class="wp-list-table widefat fixed striped">';
            html += '<thead><tr><th>Component Type</th><th>Name</th><th>Installed Version</th><th>Fixed Version</th><th>Severity</th><th>Action</th></tr></thead><tbody>';

            var types = ['core', 'plugins', 'themes'];
            $.each(types, function(i, type) {
                if (data[type]) {
                    $.each(data[type], function(j, item) {
                        var riskClass = item.severity === 'High' ? 'nexura-risk-high' : 'nexura-risk-medium';
                        html += '<tr>';
                        html += '<td>' + type.charAt(0).toUpperCase() + type.slice(1) + '</td>';
                        html += '<td><strong>' + item.name + '</strong></td>';
                        html += '<td>' + item.installed_version + '</td>';
                        html += '<td>' + item.fixed_version + '</td>';
                        html += '<td class="' + riskClass + '">' + item.severity + '</td>';
                        html += '<td>' + item.action + '</td>';
                        html += '</tr>';
                    });
                }
            });

            html += '</tbody></table>';

            // Add Update All button at the bottom
            html += '<div style="margin-top: 15px;">';
            html += '<button type="button" id="nexura-update-all-components" class="button button-primary">Update All Outdated Components</button>';
            html += '</div>';

            $results.html(html);

            // Bind Update All button
            $('#nexura-update-all-components').on('click', this.updateAll.bind(this));
        },

        updateAll: function(e) {
            e.preventDefault();
            var $btn = $(e.target);
            
            if (!confirm('Are you sure you want to update all components? It is highly recommended to have a backup before proceeding.')) {
                return;
            }

            $btn.prop('disabled', true).text('Updating...');
            
            $.ajax({
                url: nexuraRestUrl('nexura/v1/vuln/update-all'),
                method: 'POST',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success) {
                        alert('Updates completed successfully!');
                        this.runAudit(); // Reload audit results
                    } else {
                        alert('Error: ' + (response.message || 'Updates failed.'));
                        $btn.prop('disabled', false).text('Update All Outdated Components');
                    }
                },
                error: (xhr) => {
                    var msg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : 'Error updating components.';
                    alert(msg);
                    $btn.prop('disabled', false).text('Update All Outdated Components');
                }
            });
        }
    };

    var sgsThirdParty = {
        init: function() {
            $('#nexura-run-third-party-audit').on('click', this.runAudit.bind(this));
        },

        runAudit: function(e) {
            e.preventDefault();
            var $btn = $(e.target);
            var $results = $('#nexura-third-party-results');
            
            $btn.prop('disabled', true).text('Scanning...');
            $results.html('<p>Scanning content for external iframes and scripts...</p>');

            $.ajax({
                url: nexuraRestUrl('nexura/v1/third-party/audit'),
                method: 'GET',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success) {
                        this.renderResults(response.data);
                    } else {
                        $results.html('<div class="notice notice-error inline"><p>Audit failed.</p></div>');
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Scan Content');
                }
            });
        },

        renderResults: function(data) {
            var $results = $('#nexura-third-party-results');
            $results.html('');
            
            if (data.length === 0) {
                $results.html('<div class="notice notice-success inline"><p>No suspicious third-party content found.</p></div>');
                return;
            }

            var html = '<table class="wp-list-table widefat fixed striped">';
            html += '<thead><tr><th>Post ID</th><th>Post Title</th><th>Type</th><th>Source URL</th><th>Severity</th></tr></thead><tbody>';

            $.each(data, function(i, item) {
                var riskClass = item.severity === 'High' ? 'nexura-risk-high' : 'nexura-risk-medium';
                html += '<tr>';
                html += '<td>' + item.post_id + '</td>';
                html += '<td><strong>' + item.title + '</strong></td>';
                html += '<td>' + item.type + '</td>';
                html += '<td><code>' + item.source + '</code></td>';
                html += '<td class="' + riskClass + '">' + item.severity + '</td>';
                html += '</tr>';
            });

            html += '</tbody></table>';
            $results.html(html);
        }
    };

    var sgsPerformance = {
        init: function() {
            $('#nexura-run-performance-audit').on('click', this.runAudit.bind(this));
        },

        runAudit: function(e) {
            e.preventDefault();
            var $btn = $(e.target);
            var $results = $('#nexura-performance-results');
            
            $btn.prop('disabled', true).text('Auditing...');
            $results.html('<p>Analyzing database performance metrics...</p>');

            $.ajax({
                url: nexuraRestUrl('nexura/v1/performance/audit'),
                method: 'GET',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response.success) {
                        this.renderResults(response.data);
                    } else {
                        $results.html('<div class="notice notice-error inline"><p>Audit failed.</p></div>');
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text('Run Performance Audit');
                }
            });
        },

        renderResults: function(data) {
            var $results = $('#nexura-performance-results');
            var html = '';

            // Transients Check
            if (data.transients.expired_count > 100) {
                html += '<div class="notice notice-warning inline"><p>You have <strong>' + data.transients.expired_count + '</strong> expired transients in your database. You should clear them to improve performance.</p></div>';
            } else {
                html += '<div class="notice notice-success inline"><p>Expired transients are under control (' + data.transients.expired_count + ').</p></div>';
            }

            // Autoloaded Options
            html += '<h3 style="color: #fff; margin-top: 20px;">Autoloaded Options Analysis</h3>';
            html += '<p>Total Autoloaded Size: <strong>' + data.autoloaded_options.total_size_kb + ' KB</strong> ' + (data.autoloaded_options.total_size_kb > 800 ? '<span class="nexura-risk-high">(High)</span>' : '<span class="nexura-risk-low">(Good)</span>') + '</p>';

            if (data.autoloaded_options.heavy_options.length > 0) {
                html += '<h4 style="color: #fff; margin-top: 20px;">Heaviest Options</h4>';
                html += '<table class="wp-list-table widefat fixed striped">';
                html += '<thead><tr><th>Option Name</th><th>Size</th></tr></thead><tbody>';
                $.each(data.autoloaded_options.heavy_options, function(i, opt) {
                    html += '<tr><td><code>' + opt.name + '</code></td><td>' + opt.size + '</td></tr>';
                });
                html += '</tbody></table>';
            }

            $results.html(html);
        }
    };

    sgsScanner.init();
    sgsFIM.init();
    sgsGSB.init();
    sgsVuln.init();
    sgsThirdParty.init();
    sgsPerformance.init();
    
    // Enterprise Storage Scanner JS
    var sgsStorageScanner = {
        init: function() {
            $('#nexura-run-storage-scan').on('click', this.startScan.bind(this));
            $('#nexura-storage-bulk-trash').on('click', (e) => this.bulkTrash(e));
            $('#nexura-storage-bulk-restore').on('click', (e) => this.bulkRestore(e));
            $('#nexura-storage-empty-bin').on('click', (e) => this.emptyBin(e));
            $('.nexura-filter-btn').on('click', this.filterResults.bind(this));
            $('#cb-select-all-storage').on('change', this.toggleSelectAll.bind(this));
            
            // Modal events
            $('#nexura-cleanup-cancel').on('click', this.closeModal.bind(this));
            $('#nexura-cleanup-understand-chk').on('change', this.toggleConfirmText.bind(this));
            $('#nexura-cleanup-confirm-text').on('input', this.toggleConfirmButton.bind(this));
            $('#nexura-cleanup-proceed').on('click', this.executeBulkTrash.bind(this));
            
            $(document).on('click', '.nexura-storage-page-link', this.handlePagination.bind(this));
            
            // Initial load of results if they exist
            if ($('#nexura-run-storage-scan').length) {
                this.fetchResults(1);
            }
        },
        
        startScan: function(e) {
            e.preventDefault();
            $('#nexura-run-storage-scan').prop('disabled', true);
            $('#nexura-storage-progress-wrapper').show();
            $('#nexura-storage-progress-bar').css('width', '0%');
            $('#nexura-storage-progress-percent').text('0%');
            
            this.scanBatch(100);
        },
        
        scanBatch: function(batchSize) {
            $.ajax({
                url: nexuraRestUrl('nexura/v1/performance/assets/start-scan'),
                method: 'POST',
                data: { batch_size: batchSize },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response && response.status) {
                        var percent = 0;
                        if (response.total_files > 0) {
                            percent = Math.round((response.processed / response.total_files) * 100);
                        }
                        
                        $('#nexura-storage-progress-bar').css('width', percent + '%');
                        $('#nexura-storage-progress-percent').text(percent + '%');
                        $('#nexura-storage-progress-text').text('Scanning uploads... ' + response.processed + ' / ' + response.total_files);
                        
                        if (response.status === 'scanning') {
                            this.scanBatch(batchSize); 
                        } else if (response.status === 'completed') {
                            setTimeout(() => {
                                $('#nexura-storage-progress-wrapper').hide();
                                $('#nexura-run-storage-scan').prop('disabled', false);
                                this.fetchResults();
                            }, 1000);
                        }
                    }
                },
                error: (xhr, textStatus, errorThrown) => {
                    $('#nexura-storage-progress-text').text('Scan failed. Please try again.');
                    $('#nexura-run-storage-scan').prop('disabled', false);
                }
            });
        },
        
        fetchResults: function(page) {
            this.currentPage = page || 1;
            var currentFilter = $('.nexura-filter-btn.active').data('filter') || 'all';
            
            var queryData = { page: this.currentPage };
            if (currentFilter === 'images' || currentFilter === 'pdf' || currentFilter === 'documents') {
                queryData.type = currentFilter;
            } else if (currentFilter === 'safe') {
                queryData.status = 'Safe';
            } else if (currentFilter === 'review') {
                queryData.status = 'Review Required';
            } else if (currentFilter === 'dynamic') {
                queryData.status = 'Potentially Used';
            }
            
            $.ajax({
                url: nexuraRestUrl('nexura/v1/performance/assets/results'),
                method: 'GET',
                data: queryData,
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    if (response && response.summary) {
                        this.renderSummary(response.summary);
                        this.renderTable(response.files, response.pagination);
                    }
                }
            });
        },
        
        handlePagination: function(e) {
            e.preventDefault();
            var page = $(e.target).data('page');
            if (page) {
                this.fetchResults(page);
            }
        },
        
        renderSummary: function(summary) {
            $('#nexura-storage-summary').css('display', 'grid');
            $('#nexura-stat-unused').text(summary.unused_count);
            $('#nexura-stat-savings').text((summary.potential_saved / 1024 / 1024).toFixed(2) + ' MB');
            $('#nexura-stat-review').text(summary.review_required);
            $('#nexura-stat-bin').text((summary.cleanup_bin_size / 1024 / 1024).toFixed(2) + ' MB');
        },
        
        renderTable: function(files) {
            $('#nexura-storage-filters').css('display', 'flex');
            $('#nexura-storage-results-wrapper').show();
            
            var html = '';
            files.forEach(file => {
                var preview = '';
                var isImage = file.mime_type.indexOf('image') !== -1;
                
                var fileUrl = file.url ? file.url : (NEXURA_ajax.site_url + '/wp-content/' + file.relative_path);
                var cleanPath = fileUrl; // fallback display text
                if (file.relative_path) {
                    cleanPath = file.relative_path.replace(/\\/g, '/');
                    if (cleanPath.indexOf('wp-content/uploads') !== -1) {
                        cleanPath = cleanPath.substring(cleanPath.indexOf('wp-content/uploads') + 11);
                    } else if (cleanPath.indexOf('uploads/') !== -1 && cleanPath.indexOf('wp-content/uploads') === -1) {
                        cleanPath = cleanPath.substring(cleanPath.indexOf('uploads/'));
                    }
                }
                
                if (isImage) {
                    preview = '<img src="' + fileUrl + '" style="width:40px; height:40px; border-radius:4px; object-fit:cover;">';
                } else if (file.mime_type.indexOf('pdf') !== -1) {
                    preview = '<span style="font-size:24px;">????</span>';
                } else if (file.mime_type.indexOf('zip') !== -1 || file.mime_type.indexOf('archive') !== -1) {
                    preview = '<span style="font-size:24px;">????</span>';
                } else if (file.mime_type.indexOf('video') !== -1) {
                    preview = '<span style="font-size:24px;">????</span>';
                } else {
                    preview = '<span style="font-size:24px;">????</span>';
                }
                
                var typeClass = file.mime_type.split('/')[0];
                if (file.mime_type.indexOf('pdf') !== -1) typeClass = 'pdf';
                
                var statusClass = file.status.toLowerCase().replace(' ', '-');
                var badgeColor = '#94a3b8'; // Default
                if (file.status === 'Safe') badgeColor = '#10b981';
                if (file.status === 'Review Required') badgeColor = '#f59e0b';
                if (file.status === 'Potentially Used') badgeColor = '#ef4444';
                if (file.status === 'trashed') badgeColor = '#6366f1';
                
                html += '<tr class="storage-item type-' + typeClass + ' status-' + statusClass + '">';
                html += '<th scope="row" class="check-column"><input type="checkbox" class="storage-cb" value="' + file.id + '"></th>';
                html += '<td style="display:flex; align-items:center; gap:10px;">' + preview + ' <div><strong>' + cleanPath.split('/').pop() + '</strong><br><small><a href="' + fileUrl + '" target="_blank">View File</a></small></div></td>';
                html += '<td>' + (file.size / 1024 / 1024).toFixed(2) + ' MB</td>';
                html += '<td>' + file.mime_type + '</td>';
                html += '<td><span class="nexura-badge" style="background:' + badgeColor + '20; color:' + badgeColor + '; border: 1px solid ' + badgeColor + '50;">' + file.status + '</span></td>';
                html += '<td>' + file.confidence + '%</td>';
                html += '</tr>';
            });
            
            if (files.length === 0) {
                html = '<tr><td colspan="6" style="text-align:center; padding: 20px;">No unused assets found.</td></tr>';
            }
            
            $('#nexura-storage-results-body').html(html);
            
            // Render Pagination
            if (arguments[1] && arguments[1].total_pages > 1) {
                var pagination = arguments[1];
                var phtml = '<div class="nexura-pagination" style="margin-top:15px; display:flex; gap:10px; justify-content:center;">';
                if (pagination.current_page > 1) {
                    phtml += '<a href="#" class="button nexura-storage-page-link" data-page="' + (pagination.current_page - 1) + '">&laquo; Prev</a>';
                }
                phtml += '<span style="line-height:30px;">Page ' + pagination.current_page + ' of ' + pagination.total_pages + '</span>';
                if (pagination.current_page < pagination.total_pages) {
                    phtml += '<a href="#" class="button nexura-storage-page-link" data-page="' + (pagination.current_page + 1) + '">Next &raquo;</a>';
                }
                phtml += '</div>';
                
                $('#nexura-storage-pagination-container').remove();
                $('#nexura-storage-results-wrapper').append('<div id="nexura-storage-pagination-container">' + phtml + '</div>');
            } else {
                $('#nexura-storage-pagination-container').remove();
            }
        },
        
        filterResults: function(e) {
            $('.nexura-filter-btn').removeClass('active');
            var $btn = $(e.target);
            $btn.addClass('active');
            
            // Trigger backend fetch with new filter applied
            this.fetchResults(1);
        },
        
        toggleSelectAll: function(e) {
            $('.storage-cb').prop('checked', $(e.target).prop('checked'));
        },
        
        bulkTrash: function(e) {
            e.preventDefault();
            var ids = [];
            $('.storage-cb:checked').each(function() {
                ids.push($(this).val());
            });
            
            if (ids.length === 0) {
                alert('Please select files first.');
                return;
            }
            
            $('#nexura-cleanup-modal').css('display', 'flex');
        },
        
        closeModal: function(e) {
            if (e) e.preventDefault();
            $('#nexura-cleanup-modal').hide();
            $('#nexura-cleanup-understand-chk').prop('checked', false);
            $('#nexura-cleanup-confirm-text').val('').prop('disabled', true);
            $('#nexura-cleanup-proceed').prop('disabled', true);
        },
        
        toggleConfirmText: function(e) {
            var checked = $(e.target).prop('checked');
            $('#nexura-cleanup-confirm-text').prop('disabled', !checked);
            if (!checked) {
                $('#nexura-cleanup-proceed').prop('disabled', true);
            }
        },
        
        toggleConfirmButton: function(e) {
            var text = $(e.target).val();
            if (text === 'DELETE') {
                $('#nexura-cleanup-proceed').prop('disabled', false);
            } else {
                $('#nexura-cleanup-proceed').prop('disabled', true);
            }
        },
        
        executeBulkTrash: function(e) {
            e.preventDefault();
            var ids = [];
            $('.storage-cb:checked').each(function() {
                ids.push($(this).val());
            });
            
            var $btn = $('#nexura-cleanup-proceed');
            $btn.prop('disabled', true).text('Moving...');
            
            $.ajax({
                url: nexuraRestUrl('nexura/v1/performance/assets/trash'),
                method: 'POST',
                data: { ids: ids },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    this.closeModal();
                    $('#nexura-cleanup-modal').hide();
                    this.fetchResults(this.currentPage);
                }
            });
        },
        
        bulkRestore: function(e) {
            e.preventDefault();
            var ids = [];
            $('.storage-cb:checked').each(function() {
                ids.push($(this).val());
            });
            
            if (ids.length === 0) {
                alert('Please select files first.');
                return;
            }
            
            var $btn = $(e.target);
            var originalText = $btn.text();
            $btn.prop('disabled', true).text('Restoring...');
            
            $.ajax({
                url: nexuraRestUrl('nexura/v1/performance/assets/restore'),
                method: 'POST',
                data: { ids: ids },
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    $btn.prop('disabled', false).text(originalText);
                    this.fetchResults(this.currentPage);
                }
            });
        },
        
        emptyBin: function(e) {
            e.preventDefault();
            if (!confirm("Are you sure you want to permanently delete all files in the Cleanup Bin? This cannot be undone!")) {
                return;
            }
            
            var $btn = $(e.target);
            var originalText = $btn.text();
            $btn.prop('disabled', true).text('Emptying...');
            
            $.ajax({
                url: nexuraRestUrl('nexura/v1/performance/assets/empty-bin'),
                method: 'POST',
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
                },
                success: (response) => {
                    $btn.prop('disabled', false).text(originalText);
                    alert('Bin emptied successfully.');
                    this.fetchResults(this.currentPage);
                },
                error: (xhr, textStatus, errorThrown) => {
                    $btn.prop('disabled', false).text(originalText);
                    alert('Error emptying Cleanup Bin.');
                }
            });
        }
    };

    var sgsServerStats = {
        init: function() {
            if ($('#nexura-server-stats-wrapper').length === 0) return;
            
            this.fetchStats();
            
            $('#nexura-refresh-server-stats').on('click', (e) => {
                e.preventDefault();
                var $btn = $(e.currentTarget);
                var originalHtml = $btn.html();
                
                // Set to spinning SVG
                $btn.prop('disabled', true).html('<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation: rotation 2s infinite linear;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-8.2l-4.49 4.49"/></svg> <span>Refreshing...</span>');
                
                $.ajax({
                    url: nexuraRestUrl('nexura/v1/performance/stats/refresh'),
                    method: 'POST',
                    beforeSend: function(xhr) { xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce); },
                    success: (response) => {
                        this.renderStats(response);
                        $btn.prop('disabled', false).html(originalHtml);
                    },
                    error: (xhr, textStatus, errorThrown) => {
                        $btn.prop('disabled', false).html(originalHtml);
                    }
                });
            });
        },
        
        fetchStats: function() {
            $.ajax({
                url: nexuraRestUrl('nexura/v1/performance/stats'),
                method: 'GET',
                beforeSend: function(xhr) { xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce); },
                success: (response) => {
                    if (response && response.storage) {
                        this.renderStats(response);
                    }
                }
            });
        },
        
        formatBytes: function(bytes, decimals = 2) {
            if (!+bytes) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
        },
        
        renderStats: function(data) {
            // Update Summary Cards
            $('#stat-wp-size').text(this.formatBytes(data.storage.total_bytes));
            $('#stat-db-size').text(this.formatBytes(data.database.total_size_bytes));
            $('#stat-uploads-size').text(this.formatBytes(data.storage.uploads_bytes));
            $('#stat-db-tables').text(data.database.total_tables);
            
            // Render Charts
            if (typeof Chart !== 'undefined') {
                this.renderStorageChart(data.storage);
                this.renderDatabaseChart(data.database);
            }
        },
        
        renderStorageChart: function(storage) {
            var canvas = document.getElementById('chart-storage-breakdown');
            if (!canvas) return;
            
            if (window.nexuraStorageChart) { window.nexuraStorageChart.destroy(); }
            
            var dataValues = [
                storage.uploads_bytes,
                storage.plugins_bytes,
                storage.themes_bytes,
                storage.other_bytes
            ];
            
            // Only convert to MB for tooltip display, keep raw for chart proportions
            
            window.nexuraStorageChart = new Chart(canvas.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Uploads', 'Plugins', 'Themes', 'Core & Other'],
                    datasets: [{
                        data: dataValues,
                        backgroundColor: ['#3b82f6', '#8b5cf6', '#10b981', '#64748b'],
                        borderWidth: 0,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#94a3b8' } },
                        tooltip: {
                            callbacks: {
                                label: (context) => {
                                    return ' ' + context.label + ': ' + this.formatBytes(context.raw);
                                }
                            }
                        }
                    },
                    cutout: '65%'
                }
            });
        },
        
        renderDatabaseChart: function(db) {
            var canvas = document.getElementById('chart-database-usage');
            if (!canvas) return;
            
            if (window.nexuraDbChart) { window.nexuraDbChart.destroy(); }
            
            window.nexuraDbChart = new Chart(canvas.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Data Size', 'Index Size', 'Overhead (Free)'],
                    datasets: [{
                        data: [db.data_size_bytes, db.index_size_bytes, db.overhead_bytes],
                        backgroundColor: ['#ec4899', '#f59e0b', '#ef4444'],
                        borderWidth: 0,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#94a3b8' } },
                        tooltip: {
                            callbacks: {
                                label: (context) => {
                                    return ' ' + context.label + ': ' + this.formatBytes(context.raw);
                                }
                            }
                        }
                    },
                    cutout: '65%'
                }
            });
        }
    };

    sgsStorageScanner.init();
    sgsServerStats.init();
    
    // Only init logs if we are on the logs page
    if ($('#nexura-logs-container').length > 0) {
        sgsLogs.init();
    }

    // ======== Dashboard Charts (Chart.js) ========
    // Guard against double-init (script may be enqueued twice on pages with shortcodes)
    if (typeof Chart !== 'undefined' && !window.nexuraChartsInitialized) {
        window.nexuraChartsInitialized = true;

        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = 'rgba(99, 102, 241, 0.1)';
        Chart.defaults.font.family = "'Inter', sans-serif";

        // Malware Trend Line Chart
        var trendCanvas = document.getElementById('nexura-chart-malware-trend');
        if (trendCanvas) {
            if (window.nexuraTrendChart) { window.nexuraTrendChart.destroy(); }
            
            var trendCtx = trendCanvas.getContext('2d');
            var gradient = trendCtx.createLinearGradient(0, 0, 0, 220);
            gradient.addColorStop(0, 'rgba(99, 102, 241, 0.3)');
            gradient.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

            var trendLabels = (NEXURA_ajax.malware_trend && NEXURA_ajax.malware_trend.labels && NEXURA_ajax.malware_trend.labels.length > 0) ? NEXURA_ajax.malware_trend.labels : ['6 days ago', '5 days ago', '4 days ago', '3 days ago', '2 days ago', 'Yesterday', 'Today'];
            var trendData = [0, 0, 0, 0, 0, 0, parseInt(NEXURA_ajax.total_issues) || 0];
            if (NEXURA_ajax.malware_trend && NEXURA_ajax.malware_trend.high && NEXURA_ajax.malware_trend.high.length > 0) {
                trendData = NEXURA_ajax.malware_trend.high.map(function(val, idx) {
                    return val + NEXURA_ajax.malware_trend.medium[idx];
                });
            }

            window.nexuraTrendChart = new Chart(trendCtx, {
                type: 'line',
                data: {
                    labels: trendLabels,
                    datasets: [{
                        label: 'Issues Found',
                        data: trendData,
                        borderColor: '#6366f1',
                        backgroundColor: gradient,
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: '#6366f1',
                        pointBorderColor: '#0b0f1a',
                        pointBorderWidth: 2,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { precision: 0 },
                            grid: { color: 'rgba(99, 102, 241, 0.06)' }
                        },
                        x: {
                            grid: { display: false }
                        }
                    }
                }
            });
        }

        // File Integrity Doughnut Chart
        var integrityCanvas = document.getElementById('nexura-chart-integrity');
        if (integrityCanvas) {
            if (window.nexuraIntegrityChart) { window.nexuraIntegrityChart.destroy(); }
            
            var cleanFiles   = parseInt(NEXURA_ajax.clean_files) || 0;
            var highIssues   = parseInt(NEXURA_ajax.high_issues) || 0;
            var mediumIssues = parseInt(NEXURA_ajax.medium_issues) || 0;

            // Ensure at least a placeholder
            if (cleanFiles === 0 && highIssues === 0 && mediumIssues === 0) {
                cleanFiles = 1;
            }

            window.nexuraIntegrityChart = new Chart(integrityCanvas.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Clean', 'High Risk', 'Medium Risk'],
                    datasets: [{
                        data: [cleanFiles, highIssues, mediumIssues],
                        backgroundColor: [
                            'rgba(16, 185, 129, 0.8)',
                            'rgba(239, 68, 68, 0.8)',
                            'rgba(245, 158, 11, 0.8)'
                        ],
                        borderColor: '#0b0f1a',
                        borderWidth: 3,
                        hoverOffset: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 16,
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }
                        }
                    }
                }
            });
        }

        // reCAPTCHA Score Trends Bar Chart
        var recaptchaCanvas = document.getElementById('nexura-chart-recaptcha-trend');
        if (recaptchaCanvas) {
            if (window.nexuraRecaptchaChart) { window.nexuraRecaptchaChart.destroy(); }

            var hasStats = NEXURA_ajax.recaptcha_stats &&
                           NEXURA_ajax.recaptcha_stats.labels &&
                           NEXURA_ajax.recaptcha_stats.labels.length > 0;

            var rcLabels = hasStats ? NEXURA_ajax.recaptcha_stats.labels : ['Day 1','Day 2','Day 3','Day 4','Day 5','Day 6','Day 7'];
            var rcHumans = hasStats ? NEXURA_ajax.recaptcha_stats.humans : [0,0,0,0,0,0,0];
            var rcBots   = hasStats ? NEXURA_ajax.recaptcha_stats.bots   : [0,0,0,0,0,0,0];

            window.nexuraRecaptchaChart = new Chart(recaptchaCanvas.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: rcLabels,
                    datasets: [
                        {
                            label: 'Humans (Allowed)',
                            data: rcHumans,
                            backgroundColor: 'rgba(16, 185, 129, 0.75)',
                            borderColor: '#10b981',
                            borderWidth: 1,
                            borderRadius: 5,
                            borderSkipped: false
                        },
                        {
                            label: 'Bots (Blocked)',
                            data: rcBots,
                            backgroundColor: 'rgba(239, 68, 68, 0.75)',
                            borderColor: '#ef4444',
                            borderWidth: 1,
                            borderRadius: 5,
                            borderSkipped: false
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                usePointStyle: true,
                                pointStyle: 'circle',
                                padding: 20,
                                color: '#94a3b8'
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false
                        }
                    },
                    scales: {
                        x: {
                            stacked: true,
                            grid: { display: false },
                            ticks: { color: '#94a3b8' }
                        },
                        y: {
                            stacked: true,
                            beginAtZero: true,
                            grid: { color: 'rgba(99,102,241,0.1)' },
                            ticks: { color: '#94a3b8', precision: 0 }
                        }
                    }
                }
            });
        }
    }

    // Database Backup AJAX
    $('#nexura-db-backup-btn').on('click', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var $status = $('#nexura-db-backup-status');
        
        $btn.prop('disabled', true).text('Generating Backup...');
        $status.html('<div class="nexura-spinner" style="display:inline-block; vertical-align:middle; margin-right:5px;"></div> <span>Processing database export, please wait...</span>').show();
        
        $.ajax({
            url: typeof NEXURA_ajax !== 'undefined' ? NEXURA_ajax.ajax_url : ajaxurl,
            method: 'POST',
            data: {
                action: 'NEXURA_backup_db',
                _wpnonce: typeof NEXURA_ajax !== 'undefined' ? NEXURA_ajax.backup_nonce : ''
            },
            success: function(response) {
                if (response.success && response.data.file) {
                    var downloadUrl = (typeof NEXURA_ajax !== 'undefined' ? NEXURA_ajax.ajax_url : ajaxurl) + '?action=NEXURA_download_backup&file=' + response.data.file + '&_wpnonce=' + encodeURIComponent(NEXURA_ajax.backup_nonce);
                    $status.html('<div class="notice notice-success inline" style="margin:0; padding:15px; border-left: 4px solid #10b981; background: rgba(16, 185, 129, 0.05); border-radius: 4px;"><div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg><p style="margin:0; color:#ffffff; font-weight: 600; font-size: 14px;">Backup successful!</p></div><a href="' + downloadUrl + '" class="button button-primary" style="background: #6366f1; border-color: #6366f1; box-shadow: none;">Download SQL File</a></div>');
                    $btn.prop('disabled', false).html('<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg> Download Database Backup');
                } else {
                    $status.html('<div class="notice notice-error inline" style="margin:0; padding:10px;"><p style="margin:0;">Failed to generate backup: ' + (response.data || 'Unknown error') + '</p></div>');
                    $btn.prop('disabled', false).html('<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.3"></path></svg> Try Again');
                }
            },
            error: function() {
                $status.html('<div class="notice notice-error inline" style="margin:0; padding:10px;"><p style="margin:0;">An error occurred.</p></div>');
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-database" style="margin-top: 4px;"></span> Try Again');
            }
        });
    });

    // WAF Optimization AJAX
    $('#nexura-optimize-waf-btn').on('click', function(e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true).text('Optimizing WAF...');
        
        $.ajax({
            url: NEXURA_ajax.ajax_url,
            method: 'POST',
            data: {
                action: 'NEXURA_optimize_waf',
                _ajax_nonce: NEXURA_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    alert('WAF Optimized Successfully! Your site is now protected with Endpoint mode.');
                    location.reload();
                } else {
                    alert('Failed to optimize WAF. Please try again.');
                    $btn.prop('disabled', false).text('Optimize Firewall');
                }
            },
            error: function() {
                alert('An error occurred while optimizing the WAF.');
                $btn.prop('disabled', false).text('Optimize Firewall');
            }
        });
    });

    // Initialize 2FA QR Code if element exists
    var qrElement = document.getElementById("nexura-2fa-qr");
    if (qrElement && typeof QRCode !== 'undefined') {
        new QRCode(qrElement, {
            text: qrElement.getAttribute("data-url"),
            width: 200,
            height: 200,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.H
        });
    }

    // SSL Settings CSR Generation
    $('#nexura-generate-csr-btn').on('click', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var domain = $('#nexura-ssl-domain').val();
        var email = $('#nexura-ssl-email').val();
        var nonce = $btn.data('nonce');

        if ( !domain || !email ) {
            alert('Please enter both domain and email.');
            return;
        }

        $btn.text('Generating...').prop('disabled', true);

        $.post(NEXURA_ajax.ajax_url, {
            action: 'NEXURA_generate_csr',
            domain: domain,
            email: email,
            _ajax_nonce: nonce
        }, function(response) {
            $btn.text('Generate Keys & CSR').prop('disabled', false);
            if ( response.success ) {
                $('#nexura-private-key-output').val(response.data.private_key);
                $('#nexura-csr-output').val(response.data.csr);
                $('#nexura-csr-results').slideDown();
            } else {
                alert('Error: ' + (response.data || 'Failed to generate CSR'));
            }
        });
    });

    // Hardening WAF Toggle
    $('#nexura-waf-toggle').on('change', function() {
        var isEnabled = $(this).is(':checked');
        var action = isEnabled ? 'NEXURA_optimize_waf' : 'NEXURA_disable_waf';
        var loadingText = isEnabled ? 'Enabling WAF...' : 'Disabling WAF...';
        
        var $msg = $('#nexura-waf-status-msg');
        $msg.html('<div style="color: #3b82f6;">' + loadingText + '</div>');
        $(this).prop('disabled', true);

        $.ajax({
            url: NEXURA_ajax.ajax_url,
            method: 'POST',
            data: {
                action: action,
                _ajax_nonce: NEXURA_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    if (isEnabled) {
                        $msg.html('<div class="nexura-alert nexura-alert-success" style="padding: 15px; background: #ecfdf5; color: #065f46; border-radius: 6px; border-left: 4px solid #10b981;">??? Pre-Boot WAF is currently active and protecting your server.</div>');
                    } else {
                        $msg.html('<div class="nexura-alert nexura-alert-warning" style="padding: 15px; background: #fffbeb; color: #b45309; border-radius: 6px; border-left: 4px solid #f59e0b;">?????? Pre-Boot WAF is currently disabled. Turn it on to block malicious attacks before WordPress loads.</div>');
                    }
                } else {
                    $msg.html('<div style="color: red;">Error: ' + response.data + '</div>');
                    $('#nexura-waf-toggle').prop('checked', !isEnabled); // revert
                }
            },
            error: function() {
                $msg.html('<div style="color: red;">Server error occurred.</div>');
                $('#nexura-waf-toggle').prop('checked', !isEnabled); // revert
            },
            complete: function() {
                $('#nexura-waf-toggle').prop('disabled', false);
            }
        });
    });

    // File Snapshots Rollback
    $('.nexura-rollback-file').not('.in-scanner-table').on('click', function(e) {
        e.preventDefault();
        var filePath = $(this).data('file');
        
        if ( ! confirm( 'Are you absolutely sure you want to rollback this file to its infected state?\n\nFile: ' + filePath ) ) {
            return;
        }

        var $btn = $(this);
        $btn.prop('disabled', true).text('Rolling back...');

        $.ajax({
            url: nexuraRestUrl('nexura/v1/scan/rollback'),
            method: 'POST',
            data: { file_path: filePath },
            beforeSend: function(xhr) {
                xhr.setRequestHeader('X-WP-Nonce', NEXURA_ajax.nonce);
            },
            success: function(response) {
                if (response.success) {
                    alert('File rolled back successfully!');
                    location.reload(); // Reload the page to refresh table
                } else {
                    alert('Error: ' + response.message);
                    $btn.prop('disabled', false).text('Rollback File');
                }
            },
            error: function(xhr) {
                var msg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : 'Error rolling back file.';
                alert(msg);
                $btn.prop('disabled', false).text('Rollback File');
            }
        });
    });

    // 2FA Setup AJAX Verification
    $('#nexura_verify_2fa_btn').on('click', function(e) {
        e.preventDefault();
        var $btn = $(this);
        var code = $('#nexura_2fa_setup_code').val();
        var secret = $btn.data('secret');

        if (!code || code.length < 6) {
            alert('Please enter a valid 6-digit code.');
            return;
        }

        $btn.prop('disabled', true).text('Verifying...');

        $.ajax({
            url: nexura_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'nexura_verify_2fa_setup',
                security: nexura_ajax.nonce,
                code: code,
                secret: secret
            },
            success: function(response) {
                if (response.success) {
                    $('#nexura-2fa-setup-form-wrapper').hide();
                    
                    // Render recovery codes
                    var codesHtml = '';
                    var rawCodes = response.data.recovery_codes;
                    var downloadText = "Nexura 2FA Recovery Codes\n\nSave these codes in a secure location.\n\n";
                    
                    $.each(rawCodes, function(i, c) {
                        codesHtml += '<div><code>' + c + '</code></div>';
                        downloadText += c + "\n";
                    });
                    
                    $('#nexura-recovery-codes-display').html(codesHtml);
                    $('#nexura-2fa-setup-success').fadeIn();

                    // Handle Download
                    $('#nexura_download_recovery_btn').on('click', function() {
                        var blob = new Blob([downloadText], { type: "text/plain;charset=utf-8" });
                        var url = URL.createObjectURL(blob);
                        var a = document.createElement("a");
                        a.href = url;
                        a.download = "nexura-recovery-codes.txt";
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    });

                } else {
                    alert('Error: ' + response.data.message);
                    $btn.prop('disabled', false).text('ACTIVATE');
                }
            },
            error: function() {
                alert('An error occurred. Please try again.');
                $btn.prop('disabled', false).text('ACTIVATE');
            }
        });
    });

    // Initialize Dashboard Charts
    if (typeof Chart !== 'undefined' && typeof NEXURA_ajax !== 'undefined') {
        
        // Malware Trend Chart
        var ctxTrend = document.getElementById('nexura-chart-malware-trend');
        if (ctxTrend && NEXURA_ajax.malware_trend) {
            new Chart(ctxTrend.getContext('2d'), {
                type: 'line',
                data: {
                    labels: NEXURA_ajax.malware_trend.labels.slice().reverse(),
                    datasets: [
                        {
                            label: 'High Risk',
                            data: NEXURA_ajax.malware_trend.high.slice().reverse(),
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            borderWidth: 2,
                            tension: 0.3,
                            fill: true
                        },
                        {
                            label: 'Medium Risk',
                            data: NEXURA_ajax.malware_trend.medium.slice().reverse(),
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            borderWidth: 2,
                            tension: 0.3,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    },
                    scales: {
                        y: { beginAtZero: true, ticks: { stepSize: 1 } }
                    }
                }
            });
        }
        
        // File Integrity Chart
        var ctxIntegrity = document.getElementById('nexura-chart-integrity');
        if (ctxIntegrity && NEXURA_ajax.fim_data) {
            var fimData = [NEXURA_ajax.fim_data.core, NEXURA_ajax.fim_data.plugins, NEXURA_ajax.fim_data.themes];
            var hasFim = fimData.reduce(function(a, b){ return a + b; }, 0) > 0;
            
            new Chart(ctxIntegrity.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Core', 'Plugins', 'Themes'],
                    datasets: [{
                        data: hasFim ? fimData : [1],
                        backgroundColor: hasFim ? ['#3b82f6', '#8b5cf6', '#10b981'] : ['#e5e7eb'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom', display: hasFim },
                        tooltip: { enabled: hasFim }
                    },
                    cutout: '70%'
                },
                plugins: [{
                    id: 'textCenter',
                    beforeDraw: function(chart) {
                        var width = chart.width, height = chart.height, ctx = chart.ctx;
                        ctx.restore();
                        var fontSize = (height / 114).toFixed(2);
                        ctx.font = fontSize + "em sans-serif";
                        ctx.textBaseline = "middle";
                        ctx.fillStyle = "#6b7280";
                        var text = hasFim ? "Baseline" : "No Baseline",
                            textX = Math.round((width - ctx.measureText(text).width) / 2),
                            textY = height / 2;
                        ctx.fillText(text, textX, textY);
                        ctx.save();
                    }
                }]
            });
        }
    }

});






