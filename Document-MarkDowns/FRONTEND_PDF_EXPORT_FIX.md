# Frontend PDF Export Integration Fix

## ⚠️ IMPORTANT: Endpoint Changed!

**OLD (REMOVED):** ❌ `/api/v1/scans/{scan_id}/export`  
**NEW (CORRECT):** ✅ `/api/v1/reports/{scan_id}/export`

---

## Backend Changes Made

### Endpoint: `/reports/{scan_id}/export`

**GET** `/api/v1/reports/{scan_id}/export?format=pdf|json|csv`

**Response:**
- `format=pdf`: Returns binary PDF file with proper headers
- `format=json`: Returns JSON report data
- `format=csv`: Returns CSV file with vulnerability data

**Headers (PDF):**
```
Content-Type: application/pdf
Content-Disposition: attachment; filename=report-{scan_id}.pdf
```

**Headers (CSV):**
```
Content-Type: text/csv
Content-Disposition: attachment; filename=report-{scan_id}.csv
```

---

## Frontend Implementation

### Option 1: Add to reportService (Recommended)

Use the existing `/reports/{scan_id}/export` endpoint:

```javascript
// src/services/reportService.js (or services.js)

export const reportService = {
  // ... existing methods ...

  /**
   * Export report as PDF
   * @param {string} scanId - The scan ID
   * @returns {Promise<Blob>} PDF blob
   */
  exportPDF: async (scanId) => {
    const response = await api.get(`/reports/${scanId}/export`, {
      params: { format: 'pdf' },
      responseType: 'blob', // CRITICAL: Must specify blob for binary data
    });
    return response.data;
  },

  /**
   * Export report as CSV
   * @param {string} scanId - The scan ID
   * @returns {Promise<Blob>} CSV blob
   */
  exportCSV: async (scanId) => {
    const response = await api.get(`/reports/${scanId}/export`, {
      params: { format: 'csv' },
      responseType: 'blob',
    });
    return response.data;
  },

  /**
   * Export report as JSON
   * @param {string} scanId - The scan ID
   * @returns {Promise<Object>} Report JSON
   */
  exportJSON: async (scanId) => {
    const response = await api.get(`/reports/${scanId}/export`, {
      params: { format: 'json' },
    });
    return response.data;
  },
};
```
```

### Option 2: TypeScript Version

```typescript
// src/services/reportService.ts

interface Report {
  id: string;
  scan_id: string;
  summary: {
    total_vulns: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  vulnerabilities: Array<any>;
  // ... other fields
}

export const reportService = {
  // ... existing methods ...

  exportPDF: async (scanId: string): Promise<Blob> => {
    const response = await api.get(`/reports/${scanId}/export`, {
      params: { format: 'pdf' },
      responseType: 'blob',
    });
    return response.data;
  },

  exportCSV: async (scanId: string): Promise<Blob> => {
    const response = await api.get(`/reports/${scanId}/export`, {
      params: { format: 'csv' },
      responseType: 'blob',
    });
    return response.data;
  },

  exportJSON: async (scanId: string): Promise<Report> => {
    const response = await api.get(`/reports/${scanId}/export`, {
      params: { format: 'json' },
    });
    return response.data;
  },
};
```

---

## Usage in ReportsPage.js

Update your download handler:

```javascript
// ReportsPage.js

import { reportService } from '../services/reportService'; // or './services'

const handleDownloadPDF = async (scanId) => {
  try {
    setDownloading(true);
    
    // Call reportService.exportPDF method
    const blob = await reportService.exportPDF(scanId);
    
    // Use your existing downloadBlob helper
    downloadBlob(blob, `report-${scanId}.pdf`);
    
    toast.success('PDF downloaded successfully!');
  } catch (error) {
    console.error('PDF download failed:', error);
    toast.error('Failed to download PDF report');
  } finally {
    setDownloading(false);
  }
};

const handleDownloadCSV = async (scanId) => {
  try {
    setDownloading(true);
    
    const blob = await reportService.exportCSV(scanId);
    downloadBlob(blob, `report-${scanId}.csv`);
    
    toast.success('CSV downloaded successfully!');
  } catch (error) {
    console.error('CSV download failed:', error);
    toast.error('Failed to download CSV');
  } finally {
    setDownloading(false);
  }
};
```

---

## Complete Example with Helper Function

If you don't have `downloadBlob`, here's the complete implementation:

```javascript
// utils/download.js (or inline in your component)

/**
 * Download a blob as a file
 * @param {Blob} blob - The blob to download
 * @param {string} filename - The filename to save as
 */
export const downloadBlob = (blob, filename) => {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
};
```

```javascript
// ReportsPage.js - Complete example

import React, { useState } from 'react';
import { reportService } from '../services/reportService';
import { downloadBlob } from '../utils/download';
import { toast } from 'react-toastify'; // or your notification library

const ReportsPage = () => {
  const [downloading, setDownloading] = useState(false);

  const handleDownloadPDF = async (scanId) => {
    try {
      setDownloading(true);
      
      // Get PDF blob from backend
      const blob = await reportService.exportPDF(scanId);
      
      // Trigger download
      downloadBlob(blob, `vulcan-report-${scanId}.pdf`);
      
      toast.success('PDF report downloaded successfully!');
    } catch (error) {
      console.error('PDF download error:', error);
      
      if (error.response?.status === 404) {
        toast.error('Report not found or not completed');
      } else {
        toast.error('Failed to generate PDF report');
      }
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadCSV = async (scanId) => {
    try {
      const blob = await reportService.exportCSV(scanId);
      downloadBlob(blob, `vulcan-report-${scanId}.csv`);
      toast.success('CSV report downloaded!');
    } catch (error) {
      console.error('CSV download error:', error);
      toast.error('Failed to export CSV');
    }
  };

  const handleDownloadJSON = async (scanId) => {
    try {
      const data = await reportService.exportJSON(scanId);
      const jsonStr = JSON.stringify(data, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      downloadBlob(blob, `vulcan-report-${scanId}.json`);
      toast.success('JSON report downloaded!');
    } catch (error) {
      console.error('JSON download error:', error);
      toast.error('Failed to export JSON');
    }
  };

  return (
    <div>
      {/* Your report list */}
      {reports.map((report) => (
        <div key={report.scan_id}>
          <h3>Scan {report.scan_id}</h3>
          <button 
            onClick={() => handleDownloadPDF(report.scan_id)}
            disabled={downloading}
          >
            {downloading ? 'Generating PDF...' : 'Download PDF'}
          </button>
          <button onClick={() => handleDownloadCSV(report.scan_id)}>
            Download CSV
          </button>
          <button onClick={() => handleDownloadJSON(report.scan_id)}>
            Download JSON
          </button>
        </div>
      ))}
    </div>
  );
};
```

---

## Error Handling

The backend will return these errors:

| Status | Reason | Frontend Action |
|--------|--------|-----------------|
| 404 | Scan not found or not completed | Show "Scan not ready" message |
| 400 | Invalid format parameter | Check your format param |
| 500 | PDF generation failed | Retry or report error |

---

## Testing

### Install reportlab on backend:
```bash
cd vulcan-backend
pip install reportlab
```

### Test the endpoint:
```bash
# Get report as JSON
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8000/api/v1/reports/scan-abc123/export?format=json"

# Download PDF
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8000/api/v1/reports/scan-abc123/export?format=pdf" \
  -o report.pdf

# Download CSV
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8000/api/v1/reports/scan-abc123/export?format=csv" \
  -o report.csv
```

### Frontend test:
```javascript
// In browser console
const scanId = 'scan-abc123';
reportService.exportPDF(scanId)
  .then(blob => console.log('PDF blob:', blob))
  .catch(err => console.error(err));
```

---

## Summary

✅ **Backend:** Uses `/reports/{scan_id}/export` endpoint with PDF/CSV/JSON generation  
✅ **Service Layer:** All report logic in `report_service.py` (not scan_service)  
✅ **Dependencies:** Added `reportlab>=4.0` to requirements.txt  
✅ **Frontend:** Use `reportService.exportPDF(scanId)` with `responseType: 'blob'`  
✅ **Error Handling:** Proper 404/500 error responses  

The PDF will include:
- Scan metadata (ID, status, duration)
- Vulnerability summary by severity
- Top 20 vulnerability details with file/line info
- Professional formatting with ReportLab
