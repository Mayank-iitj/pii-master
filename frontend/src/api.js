const API_BASE = import.meta.env.VITE_API_BASE || '/api/v1';

export async function scanText(text, options = {}) {
  const response = await fetch(`${API_BASE}/scan/text`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text,
      source_type: options.sourceType || 'text',
      source_name: options.sourceName || 'dashboard_input',
      enable_ner: options.enableNer ?? true,
      enable_regex: options.enableRegex ?? true,
      min_confidence: options.minConfidence ?? 0.65,
      context: options.context || {},
    }),
  });
  if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`);
  return response.json();
}

export async function scanFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE}/scan/file`, {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) throw new Error(`File scan failed: ${response.statusText}`);
  return response.json();
}

export async function maskText(text, strategy = 'partial') {
  const response = await fetch(`${API_BASE}/mask`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, strategy }),
  });
  if (!response.ok) throw new Error(`Masking failed: ${response.statusText}`);
  return response.json();
}

export async function generateReport(scanResult, format = 'json', reportType = 'full') {
  const response = await fetch(`${API_BASE}/report/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_result: scanResult, format, report_type: reportType }),
  });
  if (!response.ok) throw new Error(`Report failed: ${response.statusText}`);
  return response.json();
}

export async function getHealth() {
  const response = await fetch(`${API_BASE}/health`);
  return response.json();
}

export async function getFrameworks() {
  const response = await fetch(`${API_BASE}/compliance/frameworks`);
  return response.json();
}

export async function submitFeedback(findingId, isFalsePositive, notes = '') {
  const response = await fetch(`${API_BASE}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ finding_id: findingId, is_false_positive: isFalsePositive, notes }),
  });
  return response.json();
}
