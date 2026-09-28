import React, { useState, useEffect, useMemo } from 'react';
import {
  Unlock,
  X,
  Download,
  ExternalLink,
  Copy,
  Check,
  FileText,
  FileSpreadsheet,
  File,
  AlertTriangle,
  ShieldCheck,
  Binary
} from 'lucide-react';
import { DecryptionResult } from '../types/auth';

interface DecryptedDocumentViewerProps {
  result: DecryptionResult;
  isEmergencySession?: boolean;
  onClose: () => void;
  formatDate: (dateStr: string) => string;
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

  // Convert base64 to byte array and blob URL for safe in-memory browser rendering
  const { blobUrl, bytes, isPdf, isImage, isAudio, isVideo, isText, decodedText } = useMemo(() => {
    try {
      const binaryString = atob(result.plaintext_base64);
      const len = binaryString.length;
      const byteArray = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        byteArray[i] = binaryString.charCodeAt(i);
      }

      const mime = (result.mime_type || '').toLowerCase();
      const fn = (result.original_filename || '').toLowerCase();

      const isPdfDoc = mime === 'application/pdf' || mime.includes('pdf') || fn.endsWith('.pdf');
      const isImg = mime.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg|bmp|ico)$/i.test(fn);
      const isAud = mime.startsWith('audio/') || /\.(mp3|wav|ogg|m4a|flac)$/i.test(fn);
      const isVid = mime.startsWith('video/') || /\.(mp4|webm|mov|mkv)$/i.test(fn);
      const isTxt =
        mime.includes('text') ||
        mime.includes('json') ||
        mime.includes('javascript') ||
        mime.includes('xml') ||
        mime.includes('csv') ||
        /\.(txt|md|json|csv|xml|yaml|yml|js|ts|tsx|jsx|py|html|css|sql|sh|env|ini|log)$/i.test(fn);

      let textContent = '';
      if (isTxt) {
        try {
          textContent = new TextDecoder('utf-8', { fatal: false }).decode(byteArray);
        } catch {
          textContent = binaryString;
        }
      }

      const effectiveMime = isPdfDoc
        ? 'application/pdf'
        : isImg
        ? mime || 'image/png'
        : isTxt
        ? mime || 'text/plain'
        : mime || 'application/octet-stream';

      const blob = new Blob([byteArray], { type: effectiveMime });
      const url = URL.createObjectURL(blob);

      return {
        blobUrl: url,
        bytes: byteArray,
        isPdf: isPdfDoc,
        isImage: isImg,
        isAudio: isAud,
        isVideo: isVid,
        isText: isTxt,
        decodedText: textContent,
      };
    } catch {
      return {
        blobUrl: '',
        bytes: new Uint8Array(),
        isPdf: false,
        isImage: false,
        isAudio: false,
        isVideo: false,
        isText: false,
        decodedText: '',
      };
    }
  }, [result.plaintext_base64, result.mime_type, result.original_filename]);

  // Clean up blob URL on unmount to completely purge decrypted plaintext from browser memory
  useEffect(() => {
    return () => {
      if (blobUrl) {
        URL.revokeObjectURL(blobUrl);
      }
    };
  }, [blobUrl]);

  const handleDownload = () => {
    if (!blobUrl) return;
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = result.original_filename || 'decrypted_document';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleOpenInNewTab = () => {
    if (!blobUrl) return;
    window.open(blobUrl, '_blank');
  };

  const handleCopySha = () => {
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

  const formatFileSize = (bytesNum: number): string => {
    if (!bytesNum || bytesNum === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytesNum) / Math.log(k));
    return `${(bytesNum / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  // Generate simple hex dump preview for binary/office files
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
      <div className="bg-surface border border-emerald-800/80 rounded-xl max-w-5xl w-full h-[92vh] flex flex-col font-mono text-xs shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border bg-slate-950/70 px-5 py-3.5 flex-shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-700/60 flex items-center justify-center text-emerald-400 flex-shrink-0">
              <Unlock className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <h3 className="font-bold text-slate-100 text-sm truncate" title={result.original_filename}>
                {result.original_filename}
              </h3>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-[10px] text-emerald-400 font-semibold flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3" />
                  Decrypted & Authenticated (AES-256-GCM)
                </span>
                <span className="text-slate-600 text-[10px]">•</span>
                <span className="text-[10px] text-slate-400">{result.mime_type || 'Unknown Type'}</span>
                <span className="text-slate-600 text-[10px]">•</span>
                <span className="text-[10px] text-slate-400">{formatFileSize(result.original_size_bytes || bytes.length)}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs shadow transition-colors"
              title="Download decrypted document"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Download</span>
            </button>
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
            <span className="text-slate-300 font-mono select-all truncate block" title={result.session_id}>
              {result.session_id.slice(0, 16)}…
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase tracking-wider">Plaintext SHA-256</span>
            <button
              onClick={handleCopySha}
              className="text-slate-300 font-mono flex items-center gap-1.5 hover:text-emerald-400 transition-colors text-left truncate w-full"
              title="Click to copy full SHA-256 checksum"
            >
              <span className="truncate">{result.plaintext_sha256.slice(0, 20)}…</span>
              {copiedSha ? <Check className="w-3 h-3 text-emerald-400 flex-shrink-0" /> : <Copy className="w-3 h-3 text-slate-500 flex-shrink-0" />}
            </button>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase tracking-wider">Decryption Completed</span>
            <span className="text-emerald-400 font-mono">{formatDate(result.completed_at)}</span>
          </div>
        </div>

        {/* Main Document Viewer Canvas */}
        <div className="flex-1 bg-slate-950 min-h-0 flex flex-col p-4 overflow-hidden relative">
          {/* Action Toolbar above Document */}
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 text-[11px] flex-shrink-0">
            <span className="text-slate-400 uppercase tracking-wider text-[10px] flex items-center gap-1.5">
              Controlled In-Memory Document View
            </span>
            <div className="flex items-center gap-2">
              {isPdf && blobUrl && (
                <button
                  onClick={handleOpenInNewTab}
                  className="flex items-center gap-1 px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-[11px] transition-colors"
                >
                  <ExternalLink className="w-3 h-3" />
                  <span>Open in Full Tab</span>
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
          <div className="flex-1 min-h-0 overflow-auto rounded border border-slate-800/80 bg-slate-900/60">
            {/* 1. PDF Documents */}
            {isPdf && blobUrl ? (
              <div className="w-full h-full min-h-[500px] flex flex-col">
                <iframe
                  src={`${blobUrl}#view=FitH&toolbar=1`}
                  title={result.original_filename}
                  className="w-full h-full min-h-[500px] border-0 rounded bg-slate-900"
                />
              </div>
            ) : null}

            {/* 2. Image Files */}
            {isImage && blobUrl ? (
              <div className="w-full h-full min-h-[400px] flex items-center justify-center p-4 bg-slate-950/80 overflow-auto">
                <img
                  src={blobUrl}
                  alt={result.original_filename}
                  className="max-h-full max-w-full object-contain rounded border border-slate-800 shadow-lg"
                />
              </div>
            ) : null}

            {/* 3. Text, JSON, Code, CSV, Markdown */}
            {isText ? (
              <div className="w-full h-full p-4 overflow-auto font-mono text-xs text-slate-200 whitespace-pre-wrap select-text leading-relaxed">
                {decodedText}
              </div>
            ) : null}

            {/* 4. Audio Files */}
            {isAudio && blobUrl ? (
              <div className="w-full h-full flex flex-col items-center justify-center p-8 space-y-4">
                <p className="text-slate-300 font-medium">Decrypted Audio Stream</p>
                <audio controls src={blobUrl} className="w-full max-w-md" />
              </div>
            ) : null}

            {/* 5. Video Files */}
            {isVideo && blobUrl ? (
              <div className="w-full h-full flex items-center justify-center p-4">
                <video controls src={blobUrl} className="max-h-full max-w-full rounded border border-slate-800" />
              </div>
            ) : null}

            {/* 6. Office Documents (Word, Excel, PowerPoint) and Binary Files */}
            {!isPdf && !isImage && !isText && !isAudio && !isVideo ? (
              <div className="w-full h-full flex flex-col items-center justify-center p-6 text-center space-y-5">
                <div className="w-16 h-16 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-blue-400 shadow-xl">
                  {result.original_filename.match(/\.(xlsx?|csv)$/i) ? (
                    <FileSpreadsheet className="w-8 h-8 text-emerald-400" />
                  ) : result.original_filename.match(/\.(docx?|rtf|odt)$/i) ? (
                    <FileText className="w-8 h-8 text-blue-400" />
                  ) : (
                    <File className="w-8 h-8 text-slate-300" />
                  )}
                </div>

                <div className="max-w-md space-y-1.5">
                  <h4 className="text-sm font-bold text-slate-100">{result.original_filename}</h4>
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
                    <span>Download Decrypted File ({formatFileSize(result.original_size_bytes || bytes.length)})</span>
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
                    <span className="text-[10px] text-slate-500 block mb-1 uppercase tracking-wider">Hex Header Inspection (First 512 bytes)</span>
                    <pre className="text-[10px] font-mono text-slate-400 whitespace-pre leading-tight">{hexDump}</pre>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-border bg-slate-950/70 px-5 py-3 flex-shrink-0">
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
