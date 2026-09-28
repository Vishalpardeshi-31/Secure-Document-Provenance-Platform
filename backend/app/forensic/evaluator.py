import io
import uuid
from datetime import datetime, timezone
from typing import List, Tuple
import numpy as np
from PIL import Image, ImageEnhance

from app.config.settings import settings
from app.forensic.derivation import (
    FingerprintDerivationService,
    DerivedFingerprintMaterial,
)
from app.forensic.embedding import (
    FingerprintEmbeddingService,
    generate_pn_chips,
)
from app.forensic.detection import (
    FingerprintDetectionService,
    DetectionResult,
)
from app.forensic.schemas import (
    ForensicEvaluationReport,
    TransformationRobustnessMetric,
)


class ForensicEvaluationUtility:
    """Benchmark test utility executing real image transformations and measuring genuine detection performance."""

    @classmethod
    def create_synthetic_test_document(cls, width: int = 512, height: int = 512) -> np.ndarray:
        """Generates a realistic synthetic test document image containing text and structure."""
        arr = np.full((height, width), 215.0, dtype=np.float32)
        # Add simulated text lines
        for r in range(40, height - 40, 24):
            arr[r : r + 10, 40 : width - 40] = 30.0
        return arr

    @classmethod
    def run_benchmark(
        cls,
        master_key: bytes = None,
        test_doc_format: str = "IMAGE_PNG",
    ) -> ForensicEvaluationReport:
        """Executes a full laboratory robustness evaluation using real mathematical transformations."""
        key = master_key if master_key is not None else settings.get_forensic_master_key_bytes()
        chips = generate_pn_chips(key)
        run_id = f"EVAL-{uuid.uuid4().hex[:8].upper()}"

        # 1. Generate test fingerprint material
        derived = FingerprintDerivationService.derive_fingerprint(
            document_id=f"doc-{run_id}",
            document_version_id="1",
            recipient_user_id=f"user-{run_id}",
            decryption_session_id=f"dec-{run_id}",
            viewer_session_id=f"view-{run_id}",
            provenance_event_id=f"prov-{run_id}",
            master_key=key,
        )

        # 2. Generate test image
        base_arr = cls.create_synthetic_test_document()
        watermarked_arr = FingerprintEmbeddingService._embed_image_array(
            base_arr, derived.payload_bits, chips, strength=4.5
        )

        # Measure PSNR
        mse = np.mean((base_arr - watermarked_arr) ** 2)
        psnr_db = float(10.0 * np.log10(255.0**2 / (mse + 1e-10)))

        # 3. Test unaltered detection
        unaltered_res = FingerprintDetectionService._detect_from_image_array(watermarked_arr, chips)
        unaltered_success = (
            unaltered_res.detection_status == "FINGERPRINT_DETECTED"
            and unaltered_res.candidate_token == derived.fingerprint_token
        )

        # 4. Test clean un-watermarked image (False Detection Test)
        clean_res = FingerprintDetectionService._detect_from_image_array(base_arr, chips)
        false_detection = clean_res.detection_status == "FINGERPRINT_DETECTED"

        # 5. Execute battery of real transformations
        metrics: List[TransformationRobustnessMetric] = []
        base_pil = Image.fromarray(watermarked_arr.astype(np.uint8))

        # A. JPEG Compression (Q=85)
        buf_85 = io.BytesIO()
        base_pil.save(buf_85, format="JPEG", quality=85)
        buf_85.seek(0)
        arr_85 = np.array(Image.open(buf_85), dtype=np.float32)
        res_85 = FingerprintDetectionService._detect_from_image_array(arr_85, chips)
        metrics.append(
            TransformationRobustnessMetric(
                transformation_name="JPEG_COMPRESSION",
                description="Lossy DCT quantization at 85% quality",
                parameter_value="quality=85",
                detected=res_85.detection_status == "FINGERPRINT_DETECTED" and res_85.candidate_token == derived.fingerprint_token,
                confidence_score=res_85.confidence_score,
                bit_error_rate=0.0 if res_85.candidate_token == derived.fingerprint_token else 1.0,
            )
        )

        # B. JPEG Compression (Q=75)
        buf_75 = io.BytesIO()
        base_pil.save(buf_75, format="JPEG", quality=75)
        buf_75.seek(0)
        arr_75 = np.array(Image.open(buf_75), dtype=np.float32)
        res_75 = FingerprintDetectionService._detect_from_image_array(arr_75, chips)
        metrics.append(
            TransformationRobustnessMetric(
                transformation_name="JPEG_COMPRESSION_AGGRESSIVE",
                description="Aggressive lossy DCT quantization at 75% quality",
                parameter_value="quality=75",
                detected=res_75.detection_status == "FINGERPRINT_DETECTED" and res_75.candidate_token == derived.fingerprint_token,
                confidence_score=res_75.confidence_score,
                bit_error_rate=0.0 if res_75.candidate_token == derived.fingerprint_token else 1.0,
            )
        )

        # C. Downscaling & Upscaling (Resizing to 80% and back)
        w, h = base_pil.size
        resized_pil = base_pil.resize((int(w * 0.8), int(h * 0.8)), Image.Resampling.BILINEAR)
        restored_pil = resized_pil.resize((w, h), Image.Resampling.BILINEAR)
        arr_rescale = np.array(restored_pil, dtype=np.float32)
        res_rescale = FingerprintDetectionService._detect_from_image_array(arr_rescale, chips)
        metrics.append(
            TransformationRobustnessMetric(
                transformation_name="BILINEAR_RESCALING",
                description="Downscaled to 80% resolution and restored with bilinear interpolation",
                parameter_value="scale=0.80",
                detected=res_rescale.detection_status == "FINGERPRINT_DETECTED" and res_rescale.candidate_token == derived.fingerprint_token,
                confidence_score=res_rescale.confidence_score,
                bit_error_rate=0.0 if res_rescale.candidate_token == derived.fingerprint_token else 1.0,
            )
        )

        # D. Brightness Variation (+15%)
        enhancer = ImageEnhance.Brightness(base_pil)
        bright_pil = enhancer.enhance(1.15)
        arr_bright = np.array(bright_pil, dtype=np.float32)
        res_bright = FingerprintDetectionService._detect_from_image_array(arr_bright, chips)
        metrics.append(
            TransformationRobustnessMetric(
                transformation_name="BRIGHTNESS_ADJUSTMENT",
                description="Luminance shift of +15%",
                parameter_value="factor=1.15",
                detected=res_bright.detection_status == "FINGERPRINT_DETECTED" and res_bright.candidate_token == derived.fingerprint_token,
                confidence_score=res_bright.confidence_score,
                bit_error_rate=0.0 if res_bright.candidate_token == derived.fingerprint_token else 1.0,
            )
        )

        # E. Contrast Adjustment (-15%)
        enhancer_c = ImageEnhance.Contrast(base_pil)
        contrast_pil = enhancer_c.enhance(0.85)
        arr_contrast = np.array(contrast_pil, dtype=np.float32)
        res_contrast = FingerprintDetectionService._detect_from_image_array(arr_contrast, chips)
        metrics.append(
            TransformationRobustnessMetric(
                transformation_name="CONTRAST_REDUCTION",
                description="Dynamic range attenuation by 15%",
                parameter_value="factor=0.85",
                detected=res_contrast.detection_status == "FINGERPRINT_DETECTED" and res_contrast.candidate_token == derived.fingerprint_token,
                confidence_score=res_contrast.confidence_score,
                bit_error_rate=0.0 if res_contrast.candidate_token == derived.fingerprint_token else 1.0,
            )
        )

        # F. Gaussian Noise Addition (sigma=2.0)
        noise = np.random.normal(0.0, 2.0, size=watermarked_arr.shape)
        noisy_arr = np.clip(watermarked_arr + noise, 0.0, 255.0)
        res_noise = FingerprintDetectionService._detect_from_image_array(noisy_arr, chips)
        metrics.append(
            TransformationRobustnessMetric(
                transformation_name="GAUSSIAN_NOISE",
                description="Additive white Gaussian sensor noise (sigma=2.0)",
                parameter_value="sigma=2.0",
                detected=res_noise.detection_status == "FINGERPRINT_DETECTED" and res_noise.candidate_token == derived.fingerprint_token,
                confidence_score=res_noise.confidence_score,
                bit_error_rate=0.0 if res_noise.candidate_token == derived.fingerprint_token else 1.0,
            )
        )

        total_tested = len(metrics)
        total_detected = sum(1 for m in metrics if m.detected)
        overall_rate = float(total_detected / total_tested) if total_tested > 0 else 0.0

        return ForensicEvaluationReport(
            test_run_id=run_id,
            embedding_profile="PDF_DCT_SPREAD_SPECTRUM_V1",
            tested_document_format=test_doc_format,
            original_psnr_db=round(psnr_db, 2),
            unaltered_detection_success=unaltered_success,
            false_detection_on_clean_document=false_detection,
            transformations=metrics,
            overall_detection_rate=round(overall_rate, 3),
            evaluated_at=datetime.now(timezone.utc),
        )
