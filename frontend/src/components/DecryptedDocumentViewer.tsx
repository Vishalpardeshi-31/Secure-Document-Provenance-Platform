import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Unlock,
  X,
  Download,
  ExternalLink,
  Copy,
  Check,
  FileText,
  FileSpreadsheet,
  FileArchive,
  File,
  AlertTriangle,
  ShieldCheck,
  Binary,
  Maximize2
} from 'lucide-react';
import { DecryptionResult } from '../types/auth';

interface DecryptedDocumentViewerProps {
  result: DecryptionResult;
  isEmergencySession?: boolean;
  onClose: () => void;
  formatDate: (dateStr: string) => string;
}

// Utility: sanitize base64 string
function sanitizeBase64(input: string | undefined | null): string {
  if (!input) return '';
  let str = input;
  if (str.includes('base64,')) {
    str = str.split('base64,')[1];
  }
  str = str.replace(/\s+/g, '');
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4 !== 0) {
    str += '=';
  }
  return str;
}

// Utility: convert sanitized base64 to Uint8Array
function base64ToUint8Array(cleanB64: string): Uint8Array {
  try {
    const binaryString = atob(cleanB64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } catch (err) {
    console.warn('atob conversion warning:', err);
    return new Uint8Array(0);
  }
}

export const DecryptedDocumentViewer: React.FC<DecryptedDocumentViewerProps> = ({
  result,
  isEmergencySession = false,
  onClose,
  formatDate,
}) => {
  const [copiedSha, setCopiedSha] = useState(false);
  const [copiedText, setCopiedText] = useState(false);
  const [showHexDump, setShowHexDump] = useState(false);
  const [blobUrl, setBlobUrl] = useState<string>('');
  const activeBlobUrlRef = useRef<string>('');

  const filename = result?.original_filename || 'decrypted_document';
  const mimeType = (result?.mime_type || '').toLowerCase();
  const lowerFilename = filename.toLowerCase();

  // Document categorization
  const isPdf = mimeType === 'application/pdf' || mimeType.includes('pdf') || lowerFilename.endsWith('.pdf');
  const isImage = mimeType.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg|bmp|ico)$/i.test(lowerFilename);
  const isAudio = mimeType.startsWith('audio/') || /\.(mp3|wav|ogg|m4a|flac)$/i.test(lowerFilename);
  const isVideo = mimeType.startsWith('video/') || /\.(mp4|webm|mov|mkv)$/i.test(lowerFilename);
  const isArchive = /\.(zip|tar|gz|rar|7z)$/i.test(lowerFilename) || mimeType.includes('zip') || mimeType.includes('compressed');
  const isSpreadsheet = /\.(xlsx?|csv|tsv|ods)$/i.test(lowerFilename) || mimeType.includes('sheet') || mimeType.includes('csv');
  const isWordDoc = /\.(docx?|rtf|odt)$/i.test(lowerFilename) || mimeType.includes('word') || mimeType.includes('document');
  const isText =
    !isPdf &&
    (mimeType.includes('text') ||
      mimeType.includes('json') ||
      mimeType.includes('javascript') ||
      mimeType.includes('xml') ||
      mimeType.includes('csv') ||
      /\.(txt|md|json|csv|xml|yaml|yml|js|ts|tsx|jsx|py|html|css|sql|sh|env|ini|log)$/i.test(lowerFilename));

  // Clean base64 string
  const cleanB64 = useMemo(() => sanitizeBase64(result?.plaintext_base64), [result?.plaintext_base64]);

  // Decode bytes
  const bytes = useMemo(() => {
    if (!cleanB64) return new Uint8Array(0);
    return base64ToUint8Array(cleanB64);
  }, [cleanB64]);

  // Data URL for instant, reliable browser rendering (especially images)
  const effectiveMime = useMemo(() => {
    if (isPdf) return 'application/pdf';
    if (isImage) {
      if (lowerFilename.endsWith('.jpg') || lowerFilename.endsWith('.jpeg')) return 'image/jpeg';
      if (lowerFilename.endsWith('.png')) return 'image/png';
      if (lowerFilename.endsWith('.gif')) return 'image/gif';
      if (lowerFilename.endsWith('.webp')) return 'image/webp';
      if (lowerFilename.endsWith('.svg')) return 'image/svg+xml';
      return mimeType || 'image/jpeg';
    }
    if (isText) return mimeType || 'text/plain';
    return mimeType || 'application/octet-stream';
  }, [isPdf, isImage, isText, lowerFilename, mimeType]);

  const dataUrl = useMemo(() => {
    if (!cleanB64) return '';
    return `data:${effectiveMime};base64,${cleanB64}`;
  }, [cleanB64, effectiveMime]);

  // Decoded text content
  const decodedText = useMemo(() => {
    if (!isText || bytes.length === 0) return '';
    try {
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch {
      try {
        return atob(cleanB64);
      } catch {
        return '';
      }
    }
  }, [isText, bytes, cleanB64]);

  // Create persistent Blob URL (for PDF iframe/object, large files, and downloads)
  useEffect(() => {
    if (bytes.length === 0) return;

    try {
      const blob = new Blob([bytes.buffer as ArrayBuffer], { type: effectiveMime });
      const url = URL.createObjectURL(blob);
      setBlobUrl(url);
      activeBlobUrlRef.current = url;
    } catch (err) {
      console.warn('Could not create Blob URL:', err);
    }

    // Cleanup ONLY when component unmounts
    return () => {
      if (activeBlobUrlRef.current) {
        URL.revokeObjectURL(activeBlobUrlRef.current);
        activeBlobUrlRef.current = '';
      }
    };
  }, [bytes, effectiveMime]);

  const formatFileSize = (bytesNum: number | undefined): string => {
    if (!bytesNum || bytesNum === 0) return `${bytes.length} B`;
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytesNum) / Math.log(k));
    return `${(bytesNum / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  // Robust download handler that works across all browsers
  const handleDownload = () => {
    const downloadUrl = blobUrl || dataUrl;
    if (!downloadUrl) return;

    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleOpenInNewTab = () => {
    const targetUrl = blobUrl || dataUrl;
    if (!targetUrl) return;
    window.open(targetUrl, '_blank');
  };

  const handleCopySha = () => {
    if (!result?.plaintext_sha256) return;
    navigator.clipboard.writeText(result.plaintext_sha256);
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 2000);
  };

  const handleCopyText = () => {
    if (!decodedText) return;
    navigator.clipboard.writeText(decodedText);
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 2000);
  };

  // Hex dump preview for binary/office files
  const hexDump = useMemo(() => {
    if (!bytes || bytes.length === 0) return '';
    const slice = bytes.slice(0, 512);
    let output = '';
    for (let i = 0; i < slice.length; i += 16) {
      const chunk = slice.slice(i, i + 16);
      const hex = Array.from(chunk)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const ascii = Array.from(chunk)
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('');
      output += `${i.toString(16).padStart(6, '0')}:  ${hex.padEnd(48, ' ')}  |${ascii}|\n`;
    }
    if (bytes.length > 512) {
      output += `\n... [${bytes.length - 512} more bytes truncated for preview]`;
    }
    return output;
  }, [bytes]);

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-2 sm:p-4">
      <div className="bg-slate-900 border border-emerald-800/80 rounded-xl max-w-5xl w-full h-[92vh] flex flex-col font-mono text-xs shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-5 py-3.5 flex-shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-700/60 flex items-center justify-center text-emerald-400 flex-shrink-0">
              <Unlock className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <h3 className="font-bold text-slate-100 text-sm truncate" title={filename}>
                {filename}
              </h3>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-[10px] text-emerald-400 font-semibold flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3" />
                  Decrypted & Authenticated (AES-256-GCM)
                </span>
                <span className="text-slate-600 text-[10px]">•</span>
                <span className="text-[10px] text-slate-400">{mimeType || 'Binary Payload'}</span>
                <span className="text-slate-600 text-[10px]">•</span>
                <span className="text-[10px] text-slate-400">
                  {formatFileSize(result?.original_size_bytes || bytes.length)}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            {/* Direct Open in Tab button */}
            {(isPdf || isImage) && (blobUrl || dataUrl) && (
              <button
                onClick={handleOpenInNewTab}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200 font-medium text-xs transition-colors"
                title="Open in a new full browser tab"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Open in Tab</span>
              </button>
            )}

            {/* Direct Download button */}
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs shadow transition-colors"
              title="Download decrypted document to disk"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </button>

            {/* Close button */}
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-100 p-1.5 rounded-lg hover:bg-slate-800/60 transition-colors"
              title="Close and destroy in-memory plaintext"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Emergency Alert Banner */}
        {isEmergencySession && (
          <div className="px-5 py-2 bg-rose-950/80 border-b border-rose-800 text-rose-300 text-xs flex items-center gap-2 flex-shrink-0">
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <div className="text-[11px]">
              <span className="font-bold">EMERGENCY BREAK-GLASS DECRYPTION SESSION:</span> Decryption executed under emergency authorization protocol. All events are cryptographically sealed in the provenance chain.
            </div>
          </div>
        )}

        {/* Cryptographic Provenance Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 bg-slate-950/90 px-5 py-2.5 border-b border-slate-800 text-[11px] flex-shrink-0">
          <div>
            <span className="text-slate-500 block text-[9px] uppercase tracking-wider">Session ID</span>
            <span className="text-slate-300 font-mono select-all truncate block" title={result?.session_id}>
              {(result?.session_id || 'UNKNOWN').slice(0, 16)}…
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase tracking-wider">Plaintext SHA-256</span>
            <button
              onClick={handleCopySha}
              className="text-slate-300 font-mono flex items-center gap-1.5 hover:text-emerald-400 transition-colors text-left truncate w-full"
              title="Click to copy full SHA-256 checksum"
            >
              <span className="truncate">{(result?.plaintext_sha256 || 'UNKNOWN').slice(0, 20)}…</span>
              {copiedSha ? <Check className="w-3 h-3 text-emerald-400 flex-shrink-0" /> : <Copy className="w-3 h-3 text-slate-500 flex-shrink-0" />}
            </button>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase tracking-wider">Decryption Completed</span>
            <span className="text-emerald-400 font-mono">
              {result?.completed_at ? formatDate(result.completed_at) : 'Active Session'}
            </span>
          </div>
        </div>

        {/* Main Document Viewer Canvas */}
        <div className="flex-1 bg-slate-950 min-h-0 flex flex-col p-3 sm:p-4 overflow-hidden relative">
          {/* Action Toolbar above Document */}
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 text-[11px] flex-shrink-0">
            <span className="text-slate-400 uppercase tracking-wider text-[10px] flex items-center gap-1.5">
              Controlled In-Memory Document View
            </span>
            <div className="flex items-center gap-2">
              {isPdf && (
                <button
                  onClick={handleOpenInNewTab}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-blue-600/80 hover:bg-blue-500 text-white text-[11px] font-medium transition-colors shadow"
                >
                  <Maximize2 className="w-3 h-3" />
                  <span>Open PDF in Full Tab</span>
                </button>
              )}
              {isText && (
                <button
                  onClick={handleCopyText}
                  className="flex items-center gap-1 px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-[11px] transition-colors"
                >
                  {copiedText ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedText ? 'Copied!' : 'Copy Text'}</span>
                </button>
              )}
            </div>
          </div>

          {/* Render by Document Type */}
          <div className="flex-1 min-h-0 overflow-auto rounded border border-slate-800/80 bg-slate-900/60 flex flex-col">
            {/* 1. PDF Documents: Render using object/iframe + fallback buttons */}
            {isPdf ? (
              <div className="w-full h-full min-h-[450px] flex-1 flex flex-col">
                {/* Fallback bar if browser restricts PDF iframes */}
                <div className="px-4 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-[11px] text-slate-300 flex-shrink-0">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-rose-400" />
                    <span>PDF Document: <strong className="text-slate-100">{filename}</strong></span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleOpenInNewTab}
                      className="text-xs px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium flex items-center gap-1"
                    >
                      <ExternalLink className="w-3 h-3" />
                      <span>Open in Browser Reader</span>
                    </button>
                    <button
                      onClick={handleDownload}
                      className="text-xs px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium flex items-center gap-1"
                    >
                      <Download className="w-3 h-3" />
                      <span>Download PDF</span>
                    </button>
                  </div>
                </div>

                {/* PDF Object with nested iframe for maximum compatibility */}
                <div className="flex-1 min-h-0 w-full bg-slate-950">
                  {blobUrl ? (
                    <object
                      data={`${blobUrl}#toolbar=1&navpanes=1`}
                      type="application/pdf"
                      className="w-full h-full min-h-[500px] border-0"
                    >
                      <iframe
                        src={`${blobUrl}#toolbar=1`}
                        title={filename}
                        className="w-full h-full min-h-[500px] border-0"
                      >
                        <div className="p-8 text-center space-y-4">
                          <FileText className="w-12 h-12 text-rose-400 mx-auto" />
                          <p className="text-slate-200 font-medium">PDF Ready to View</p>
                          <p className="text-slate-400 text-xs">
                            Your browser settings require opening this PDF in a dedicated tab or downloading it.
                          </p>
                          <div className="flex items-center justify-center gap-3">
                            <button
                              onClick={handleOpenInNewTab}
                              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold"
                            >
                              Open in Full Tab
                            </button>
                            <button
                              onClick={handleDownload}
                              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold"
                            >
                              Download PDF
                            </button>
                          </div>
                        </div>
                      </iframe>
                    </object>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full p-8 space-y-3">
                      <div className="animate-spin w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full" />
                      <p className="text-slate-400 text-xs">Preparing PDF document...</p>
                    </div>
                  )}
                </div>
              </div>
            ) : null}

            {/* 2. Image Files: Guaranteed rendering with Data URI */}
            {isImage ? (
              <div className="w-full h-full min-h-[400px] flex-1 flex flex-col items-center justify-center p-4 bg-slate-950/90 overflow-auto">
                {dataUrl || blobUrl ? (
                  <img
                    src={dataUrl || blobUrl}
                    alt={filename}
                    className="max-h-[75vh] max-w-full object-contain rounded border border-slate-800 shadow-2xl bg-black/40"
                    onError={(e) => {
                      // Fallback to blob URL if data URL had an issue
                      if (blobUrl && e.currentTarget.src !== blobUrl) {
                        e.currentTarget.src = blobUrl;
                      }
                    }}
                  />
                ) : (
                  <p className="text-rose-400">Unable to load image stream.</p>
                )}
              </div>
            ) : null}

            {/* 3. Text, JSON, Code, CSV, Markdown */}
            {isText ? (
              <div className="w-full h-full p-4 overflow-auto font-mono text-xs text-slate-200 whitespace-pre-wrap select-text leading-relaxed bg-slate-950">
                {decodedText || (
                  <p className="text-slate-500 italic">Empty text content or non-UTF8 encoded payload.</p>
                )}
              </div>
            ) : null}

            {/* 4. Audio Files */}
            {isAudio ? (
              <div className="w-full h-full flex flex-col items-center justify-center p-8 space-y-4">
                <p className="text-slate-300 font-medium">Decrypted Audio Stream</p>
                <audio controls src={blobUrl || dataUrl} className="w-full max-w-md" />
              </div>
            ) : null}

            {/* 5. Video Files */}
            {isVideo ? (
              <div className="w-full h-full flex items-center justify-center p-4">
                <video controls src={blobUrl || dataUrl} className="max-h-full max-w-full rounded border border-slate-800" />
              </div>
            ) : null}

            {/* 6. Office Documents (Word, Excel, PowerPoint) and Binary Files */}
            {!isPdf && !isImage && !isText && !isAudio && !isVideo ? (
              <div className="w-full h-full flex flex-col items-center justify-center p-6 text-center space-y-5 flex-1">
                <div className="w-16 h-16 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center shadow-xl">
                  {isSpreadsheet ? (
                    <FileSpreadsheet className="w-8 h-8 text-emerald-400" />
                  ) : isWordDoc ? (
                    <FileText className="w-8 h-8 text-blue-400" />
                  ) : isArchive ? (
                    <FileArchive className="w-8 h-8 text-amber-400" />
                  ) : (
                    <File className="w-8 h-8 text-slate-300" />
                  )}
                </div>

                <div className="max-w-md space-y-1.5">
                  <h4 className="text-sm font-bold text-slate-100">{filename}</h4>
                  <p className="text-xs text-emerald-400 font-semibold">Binary Document Decrypted & Authenticated</p>
                  <p className="text-[11px] text-slate-400 leading-normal">
                    This file is ready for download. Because modern browsers do not support in-tab rendering for proprietary Office/binary formats, download the file to open it in Microsoft Word, Excel, or your desktop application.
                  </p>
                </div>

                <div className="flex flex-wrap items-center justify-center gap-3">
                  <button
                    onClick={handleDownload}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs shadow-lg transition-all"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download Decrypted File ({formatFileSize(result?.original_size_bytes || bytes.length)})</span>
                  </button>

                  <button
                    onClick={() => setShowHexDump(!showHexDump)}
                    className="flex items-center gap-1.5 px-3 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-300 text-xs transition-colors"
                  >
                    <Binary className="w-3.5 h-3.5 text-slate-400" />
                    <span>{showHexDump ? 'Hide Hex Dump' : 'Inspect Raw Hex'}</span>
                  </button>
                </div>

                {showHexDump && (
                  <div className="w-full max-w-2xl text-left mt-4 border border-slate-800 rounded bg-slate-950 p-3 max-h-48 overflow-auto">
                    <span className="text-[10px] text-slate-500 block mb-1 uppercase tracking-wider">
                      Hex Header Inspection (First 512 bytes)
                    </span>
                    <pre className="text-[10px] font-mono text-slate-400 whitespace-pre leading-tight">
                      {hexDump}
                    </pre>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-slate-800 bg-slate-950/80 px-5 py-3 flex-shrink-0">
          <span className="text-[10px] text-slate-500 italic">
            🛡️ Ephemeral in-memory view. Memory will be purged upon closing.
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-200 rounded font-medium transition-colors"
          >
            Close & Destroy Plaintext
          </button>
        </div>
      </div>
    </div>
  );
};
