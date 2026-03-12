# modules/ml_engine.py — Offline Tier 2 ML Engine: PE feature extraction, LightGBM inference,
# malware family classification, and IAT forensic analysis.
#
# FIXES:
#   - imp.name.decode('utf-8') → decode with errors='ignore' (crash on malformed PE names)
#   - pefile.PE object wrapped in try/finally to guarantee pe.close() on exception (memory leak)
#   - ml_result['features'] numpy array explicitly deleted after stage2 (daemon memory growth)

import json
import os
import numpy as np
import pefile
import lightgbm as lgb
from .loading import Spinner

try:
    import thrember
    _THREMBER_AVAILABLE = True
except ImportError:
    _THREMBER_AVAILABLE = False
    print("[!] Warning: 'thrember' library not found. Local ML scanning will be unavailable.")


class LocalScanner:
    def __init__(
        self,
        all_model_path: str = "./models/CyberSentinel_v2.model",
        family_model_path: str = "./models/EMBER2024_family.model",
        labels_path: str = "./models/family_labels.json",
        threshold: float = 0.6,
    ):
        self.all_model_path = all_model_path
        self.family_model_path = family_model_path
        self.labels_path = labels_path
        # Optimised V2 threshold (0.6) targets 0.00% FPR on LotL binaries
        self.threshold = threshold

        self.all_model = None
        self.family_model = None
        self.family_labels = self._load_labels()

    # ─────────────────────────────────────────────
    #  MODEL LOADING
    # ─────────────────────────────────────────────

    def _load_labels(self) -> dict | None:
        if not os.path.exists(self.labels_path):
            return None
        try:
            with open(self.labels_path, "r") as f:
                return json.load(f)
        except Exception:
            return None

    def _load_model(self, path: str) -> lgb.Booster | None:
        if not os.path.exists(path):
            print(f"[-] Model file '{path}' not found.")
            return None

        spinner = Spinner("[*] Loading ML model...")
        spinner.start()
        try:
            model = lgb.Booster(model_file=path)
            spinner.stop()
            return model
        except Exception as e:
            spinner.stop()
            print(f"[-] Failed to load ML model: {e}")
            return None

    # ─────────────────────────────────────────────
    #  FEATURE EXTRACTION
    # ─────────────────────────────────────────────

    def extract_features(self, file_path: str) -> np.ndarray | None:
        """
        Maps PE structural metadata into a float32 feature tensor via thrember.
        Hard limits:
          - 50 MB file size cap (host resource protection)
          - MZ magic byte validation (defeats extension spoofing)
        """
        if not _THREMBER_AVAILABLE:
            print("[-] thrember not installed. Cannot extract features.")
            return None

        try:
            if os.path.getsize(file_path) > 50 * 1024 * 1024:
                print("[-] INFO: File exceeds 50 MB optimization threshold. Skipping local ML.")
                return None
        except OSError:
            return None

        file_data = None
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            if not file_data.startswith(b"MZ"):
                print("[-] REJECTED: Not a valid Windows PE (bad magic bytes).")
                return None

            extractor = thrember.PEFeatureExtractor()
            features = np.array(extractor.feature_vector(file_data), dtype=np.float32)
            return features.reshape(1, -1)

        except PermissionError:
            print("[!] ACCESS DENIED: File is locked by OS (actively executing).")
            return None
        except thrember.exceptions.PEFormatError:
            print("[-] PARSER ERROR: Corrupted PE header (possible decompression bomb).")
            return None
        except Exception as e:
            print(f"[-] Feature extraction error: {e}")
            return None
        finally:
            # Explicit memory release — critical in long-running daemon mode
            if file_data is not None:
                del file_data

    # ─────────────────────────────────────────────
    #  IAT FORENSIC ANALYSIS
    # ─────────────────────────────────────────────

    def get_suspicious_apis(self, file_path: str) -> list[str]:
        """
        Parses the Import Address Table for high-risk Windows API calls.

        MEMORY FIX: pefile.PE is now closed in a finally block, guaranteeing
        cleanup even if an exception is raised mid-parse on malformed headers.

        BUG FIX: imp.name is decoded with errors='ignore' — malware frequently
        uses non-UTF-8 bytes in import names to crash analysis tools.
        """
        suspicious_calls = []
        target_apis = {
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "SetWindowsHookEx", "GetKeyboardState", "URLDownloadToFile",
            "RegSetValueEx", "CryptEncrypt", "HttpSendRequest",
            "NtUnmapViewOfSection", "ZwWriteVirtualMemory", "OpenProcess",
        }

        pe = None
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            # BUG FIX: errors='ignore' prevents UnicodeDecodeError on
                            # malware that embeds garbage bytes in import name strings
                            name = imp.name.decode("utf-8", errors="ignore")
                            if name in target_apis:
                                suspicious_calls.append(name)

        except Exception:
            pass
        finally:
            # MEMORY FIX: guaranteed close regardless of exceptions above
            if pe is not None:
                pe.close()

        return list(set(suspicious_calls))

    # ─────────────────────────────────────────────
    #  INFERENCE STAGES
    # ─────────────────────────────────────────────

    def scan_stage1(self, file_path: str) -> dict | None:
        """
        Stage 1: binary malicious/benign classification.
        Returns a result dict or None if the file cannot be processed.
        """
        spinner = Spinner("[*] Extracting dimensional features...")
        spinner.start()
        features = self.extract_features(file_path)
        spinner.stop()

        if features is None:
            return None

        if self.all_model is None:
            self.all_model = self._load_model(self.all_model_path)
            if self.all_model is None:
                return None

        try:
            raw_score = float(self.all_model.predict(features)[0])

            if raw_score > self.threshold:
                verdict, is_malicious = "CRITICAL RISK", True
            elif raw_score > 0.4:
                verdict, is_malicious = "SUSPICIOUS", False
            else:
                verdict, is_malicious = "SAFE", False

            apis = self.get_suspicious_apis(file_path)

            return {
                "verdict": verdict,
                "score": raw_score,
                "is_malicious": is_malicious,
                "features": features,      # Passed to stage2; caller must del after use
                "detected_apis": apis,
            }
        except Exception as e:
            print(f"[-] ML inference failed: {e}")
            return None

    def scan_stage2(self, features: np.ndarray) -> dict | None:
        """
        Stage 2: deep malware family classification.
        Caller is responsible for del-ing the features array afterwards.
        """
        if self.family_model is None:
            print("[*] Loading malware family database...")
            self.family_model = self._load_model(self.family_model_path)

        if self.family_model is None:
            return None

        try:
            family_probs = self.family_model.predict(features)[0]
            best_id = int(np.argmax(family_probs))

            fam_name = f"Family ID #{best_id}"
            if self.family_labels and isinstance(self.family_labels, dict):
                fam_name = self.family_labels.get(str(best_id), fam_name)

            return {
                "family_name": fam_name,
                "family_confidence": float(family_probs[best_id]),
            }
        except Exception as e:
            print(f"[-] Stage 2 classification failed: {e}")
            return None
