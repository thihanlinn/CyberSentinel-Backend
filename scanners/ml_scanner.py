"""
RandomForest phishing detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import joblib
import shap
import numpy as np

from utils.feature_extractor import extract_features
from utils.logger import get_logger

logger = get_logger("scanner.ml")

RISK_LABELS = ["Safe", "Phishing"]
ML_MODEL_FILE = "phishing_random_forest_model.pkl"

@dataclass
class MLResult:
    score:       float                        # probability
    prediction:  int                          # 0 = benign, 1 = phishing
    label:       str
    explanation: list[dict] = field(default_factory=list)
    error:       Optional[str] = None

# Wraps a pre-trained RandomForest model for phishing URL classification.
class MLScanner:

    def __init__(self) -> None:
        self.model = None
        self.explainer = None
        self._load_model()

    # Initialisation

    def _load_model(self) -> None:
        try:
            self.model = joblib.load(ML_MODEL_FILE)
            self.explainer = shap.TreeExplainer(self.model)
            logger.info("ML model loaded from %s", ML_MODEL_FILE)
        except FileNotFoundError:
            logger.warning("ML model file not found at '%s'. ML scoring disabled.", ML_MODEL_FILE)
        except Exception as exc:
            logger.error("Failed to load ML model: %s", exc)

    @property
    def available(self) -> bool:
        return self.model is not None

    # SHAP explanation
    # Return top-5 SHAP feature importances (feature_name, shap_value).

    def _explain(self, sample) -> list[dict]:

        if self.explainer is None:
            return []

        try:
            shap_values = self.explainer.shap_values(sample)

            if isinstance(shap_values, list):
                values = shap_values[1][0]      # class 1 = phishing
            else:
                values = shap_values[0]

            values = np.array(values).flatten() # Convert to 1D array

            #Get feature values from sample
            feature_values = sample.iloc[0].to_dict()

            importance = []
            for feature, shap_val in zip(sample.columns, values):
                val = feature_values.get(feature)

                # skip features with no value
                if val in [0, False, None] or (isinstance(val, float) and np.isnan(val)):
                    continue

                importance.append((feature, shap_val))
            importance.sort(key=lambda x: abs(float(x[1])), reverse=True)
            return importance[:5]

        except Exception as exc:
            logger.warning("SHAP explanation failed: %s", exc)
            return []


    # Public API

    # Run the ML model on *url*
    def predict(self, url: str) -> MLResult:

        if not self.available:
            return MLResult(score=0.0, prediction=0, label="Unknown",
                            error="ML model not loaded")

        try:
            features = extract_features(url)

            # Align columns to what the model was trained on
            features = features.reindex(columns=self.model.feature_names_in_, fill_value=0)

            prediction:    int = int(np.ravel(self.model.predict(features))[0])
            probability: float = round(float(np.ravel(self.model.predict_proba(features)[:, 1])[0]), 2)
            score:       float = probability * 100

            label = RISK_LABELS[1] if prediction == 1 else RISK_LABELS[0]

            reasons = []

            if (prediction == 1):
                explanation = self._explain(features)

                for f, shap_val in explanation:
                    feature_value = float(features.iloc[0][f])

                    if feature_value > 0 and float(shap_val) > 0:
                        reasons.append({
                            "feature": f,
                            "impact": round(float(shap_val), 4)
                        })

            return MLResult(
                score=score,
                prediction=prediction,
                label=label,
                explanation=reasons,
            )

        except Exception as exc:
            logger.error("ML inference error for '%s': %s", url, exc)
            return MLResult(score=0.0, prediction=0, label="Unknown", error=str(exc))
