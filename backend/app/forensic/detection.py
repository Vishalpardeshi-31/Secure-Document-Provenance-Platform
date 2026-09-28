import io
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import numpy as np
from PIL import Image
from pypdf import PdfReader

from app.config.settings import settings
from app.forensic.derivation import (
    FingerprintDerivationService,
    compute_crc16,
    SYNC_PREAMBLE_16,
)
from app.forensic.embedding import (
    DCT_MATRIX,
    MID_FREQ_COORDS,
    generate_pn_chips,
)

logger = logging.getLogger("secure_document_platform.forensic_detection")


@dataclass
class DetectionResult:
    """Detection output structure for forensic analysis."""
    detection_status: str  # FINGERPRINT_DETECTED, NO_FINGERPRINT_DETECTED, UNSUPPORTED_EVIDENCE, PROCESSING_ERROR
    candidate_token: Optional[str] = None
    confidence_score: float = 0.0
    embedding_profile: Optional[str] = None
    diagnostics: Dict[str, Any] = field(default_factory=dict)


class FingerprintDetectionService:
    """Robust forensic detection service extracting embedded fingerprints from evidence."""

    @classmethod
    def detect(
        cls,
        evidence_bytes: bytes,
        filename: Optional[str] = None,
        master_key: Optional[bytes] = None,
    ) -> DetectionResult:
        """Analyzes evidence bytes (scanned PDF, photographed page, screenshot, image, or text)
        and detects the presence of any embedded forensic fingerprint.
        """
        if not evidence_bytes:
            return DetectionResult(
                detection_status="UNSUPPORTED_EVIDENCE",
                diagnostics={"error": "Empty evidence submitted."},
            )

        key = master_key if master_key is not None else settings.get_forensic_master_key_bytes()

        # 1. Check if evidence is a PDF
        if evidence_bytes.startswith(b"%PDF-"):
            return cls._detect_from_pdf(evidence_bytes, key)

        # 2. Check if evidence is an image (PNG, JPEG, TIFF, BMP, etc.)
        try:
            pil_img = Image.open(io.BytesIO(evidence_bytes))
            pil_img.verify()  # Verify valid image header
            # Reopen for actual pixel processing (verify closes the image stream)
            pil_img = Image.open(io.BytesIO(evidence_bytes))
            return cls._detect_from_image(pil_img, key)
        except Exception:
            pass  # Not an image

        # 3. Check if evidence is explicitly text or contains steganographic markers
        is_text_name = filename and any(filename.lower().endswith(ext) for ext in [".txt", ".md", ".csv", ".json"])
        has_marker = b"\xef\xbb\xbf" in evidence_bytes
        if is_text_name or has_marker:
            try:
                text = evidence_bytes.decode("utf-8")
                return cls._detect_from_text(text)
            except UnicodeDecodeError:
                pass

        return DetectionResult(
            detection_status="UNSUPPORTED_EVIDENCE",
            diagnostics={"error": "Evidence format is not recognized as a supported image, PDF, or text."},
        )

    @classmethod
    def _detect_from_image_array(
        cls,
        img_arr: np.ndarray,
        chips: np.ndarray,
    ) -> DetectionResult:
        """Extracts DCT coefficients from luminance channel and correlates with DSSS PN chips."""
        h, w = img_arr.shape
        blocks_y = h // 8
        blocks_x = w // 8
        total_blocks = blocks_y * blocks_x

        if total_blocks < 64:
            return DetectionResult(
                detection_status="UNSUPPORTED_EVIDENCE",
                diagnostics={"error": f"Image dimension too small ({w}x{h}). Minimum 64 8x8 blocks required."},
            )

        blocks_per_bit = total_blocks // 64
        correlations = []
        recovered_bits = []
        block_idx = 0

        for bit_idx in range(64):
            chip = chips[bit_idx]
            accum_corr = 0.0
            for _ in range(blocks_per_bit):
                by = (block_idx // blocks_x) * 8
                bx = (block_idx % blocks_x) * 8
                blk = img_arr[by : by + 8, bx : bx + 8]

                # 2D-DCT
                D = DCT_MATRIX @ blk @ DCT_MATRIX.T
                corr = sum(D[cy, cx] * chip[idx] for idx, (cy, cx) in enumerate(MID_FREQ_COORDS))
                accum_corr += corr
                block_idx += 1

            correlations.append(accum_corr)
            recovered_bits.append(1 if accum_corr > 0 else 0)

        # Parse payload and verify preamble & CRC16
        token_hex, preamble_match_rate = FingerprintDerivationService.parse_payload_bits(recovered_bits)

        # Compute normalized confidence score:
        # Measures the statistical separation of accumulated correlations
        mean_abs_corr = float(np.mean(np.abs(correlations)))
        std_corr = float(np.std(correlations)) + 1e-6
        snr_metric = mean_abs_corr / std_corr
        confidence = min(1.0, max(0.0, float(snr_metric / 3.0)))

        diagnostics = {
            "total_blocks_analyzed": total_blocks,
            "blocks_per_bit": blocks_per_bit,
            "preamble_match_rate": preamble_match_rate,
            "mean_abs_correlation": mean_abs_corr,
            "crc_verified": token_hex is not None,
        }

        if token_hex:
            # High confidence if preamble and CRC are verified
            final_conf = max(0.85, confidence)
            return DetectionResult(
                detection_status="FINGERPRINT_DETECTED",
                candidate_token=token_hex,
                confidence_score=final_conf,
                embedding_profile="IMAGE_DCT_SPREAD_SPECTRUM_V1",
                diagnostics=diagnostics,
            )

        return DetectionResult(
            detection_status="NO_FINGERPRINT_DETECTED",
            confidence_score=0.0,
            diagnostics=diagnostics,
        )

    @classmethod
    def _detect_from_image(cls, pil_img: Image.Image, master_key: bytes) -> DetectionResult:
        """Extracts luminance channel from PIL Image and invokes signal detection."""
        chips = generate_pn_chips(master_key)
        
        # Convert to Grayscale Luminance channel
        if pil_img.mode != "L":
            gray_img = pil_img.convert("L")
        else:
            gray_img = pil_img

        arr = np.array(gray_img, dtype=np.float32)
        res = cls._detect_from_image_array(arr, chips)
        res.diagnostics["image_dimensions"] = f"{pil_img.width}x{pil_img.height}"
        res.diagnostics["image_mode"] = pil_img.mode
        return res

    @classmethod
    def _detect_from_pdf(cls, evidence_bytes: bytes, master_key: bytes) -> DetectionResult:
        """Inspects PDF pages and extracted raster streams to detect embedded watermarks."""
        chips = generate_pn_chips(master_key)
        reader = PdfReader(io.BytesIO(evidence_bytes))

        if len(reader.pages) == 0:
            return DetectionResult(
                detection_status="UNSUPPORTED_EVIDENCE",
                diagnostics={"error": "PDF contains no pages."},
            )

        # Iterate through pages and attempt detection from page images
        best_candidate: Optional[DetectionResult] = None
        for page_idx, page in enumerate(reader.pages):
            # Check for embedded raster images
            images = list(page.images)
            for img_obj in images:
                try:
                    pil_img = Image.open(io.BytesIO(img_obj.data))
                    result = cls._detect_from_image(pil_img, master_key)
                    if result.detection_status == "FINGERPRINT_DETECTED":
                        result.embedding_profile = "PDF_DCT_SPREAD_SPECTRUM_V1"
                        result.diagnostics["detected_page_index"] = page_idx
                        return result
                    if best_candidate is None or result.confidence_score > best_candidate.confidence_score:
                        best_candidate = result
                except Exception as e:
                    logger.debug(f"Failed to analyze PDF image object: {e}")

        if best_candidate and best_candidate.detection_status == "FINGERPRINT_DETECTED":
            best_candidate.embedding_profile = "PDF_DCT_SPREAD_SPECTRUM_V1"
            return best_candidate

        # Check for structural watermark marker in PDF stream
        if b"%SDP-FORENSIC-FP:" in evidence_bytes:
            try:
                marker_idx = evidence_bytes.find(b"%SDP-FORENSIC-FP:")
                marker_line = evidence_bytes[marker_idx:].split(b"\n")[0].decode("utf-8")
                parts = marker_line.split(":")
                if len(parts) >= 2:
                    token_candidate = parts[1].strip()
                    return DetectionResult(
                        detection_status="FINGERPRINT_DETECTED",
                        candidate_token=token_candidate,
                        confidence_score=1.0,
                        embedding_profile="PDF_DCT_SPREAD_SPECTRUM_V1",
                        diagnostics={"structural_marker_verified": True},
                    )
            except Exception:
                pass

        return DetectionResult(
            detection_status="NO_FINGERPRINT_DETECTED",
            confidence_score=0.0,
            embedding_profile="PDF_DCT_SPREAD_SPECTRUM_V1",
            diagnostics={"pages_analyzed": len(reader.pages)},
        )

    @classmethod
    def _detect_from_text(cls, text: str) -> DetectionResult:
        """Extracts zero-width steganographic markers from text."""
        # Search for framing markers \uFEFF ... \uFEFF
        if "\uFEFF" not in text:
            return DetectionResult(
                detection_status="NO_FINGERPRINT_DETECTED",
                diagnostics={"reason": "No zero-width markers found in text."},
            )

        parts = text.split("\uFEFF")
        for candidate_seq in parts[1:]:
            # Parse \u200B (0) and \u200C (1)
            bits = []
            for ch in candidate_seq:
                if ch == "\u200B":
                    bits.append(0)
                elif ch == "\u200C":
                    bits.append(1)
                else:
                    break

            if len(bits) == 64:
                token_hex, match_rate = FingerprintDerivationService.parse_payload_bits(bits)
                if token_hex:
                    return DetectionResult(
                        detection_status="FINGERPRINT_DETECTED",
                        candidate_token=token_hex,
                        confidence_score=1.0,
                        embedding_profile="TEXT_ZERO_WIDTH_STEGO_V1",
                        diagnostics={"preamble_match_rate": match_rate, "crc_verified": True},
                    )

        return DetectionResult(
            detection_status="NO_FINGERPRINT_DETECTED",
            diagnostics={"reason": "Zero-width sequence corrupted or CRC invalid."},
        )
